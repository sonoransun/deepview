"""CUDA GPU offload backend — slice 13.

Mirror of :mod:`deepview.offload.backends.gpu_opencl`. Implements
``pbkdf2_sha256`` and ``sha512_iter`` kernels on top of ``pycuda``,
falls back to the CPU reference implementations in
:mod:`deepview.offload.kdf` when compilation or execution fails, and
honestly refuses ``argon2id`` — Argon2 is memory-hard and would need
hundreds of MB of per-thread VRAM at realistic parameters. Use the
CPU ``argon2-cffi`` path via ``backend="process"`` for that workload.

Fallback / result contract matches :class:`OpenCLBackend`:

- :meth:`is_available` is ``False`` if ``pycuda`` / CUDA driver /
  NVCC is missing. :meth:`submit` raises :class:`NotImplementedError`.
- When the GPU path runs, :attr:`OffloadResult.backend` is
  ``"gpu-cuda"``.
- When we silently fall back to the CPU reference (e.g. kernel
  compile failed, dklen > 32, salt > 60 bytes, or any runtime CUDA
  error), :attr:`OffloadResult.backend` is
  ``"gpu-cuda[cpu-fallback]"``.

Single-job wall-clock reality: one-off PBKDF2 rarely beats CPU by
more than a hair because of kernel launch overhead, so callers that
really want to lean on the GPU should submit a batch via
``payload["passwords"]``.

``pycuda`` and its ``pycuda.autoinit`` (which actually initializes
the driver and picks a device) are both imported lazily inside
:meth:`__init__` so a core install never touches CUDA userland.
"""
from __future__ import annotations

import time
from collections.abc import Mapping
from concurrent.futures import Future
from typing import Any

from deepview.core.logging import get_logger
from deepview.offload.backends.base import OffloadBackend
from deepview.offload.jobs import OffloadJob, OffloadResult
from deepview.offload.kdf import pbkdf2_sha256 as _cpu_pbkdf2_sha256
from deepview.offload.kdf import sha512_iter as _cpu_sha512_iter

log = get_logger("offload.gpu_cuda")

_BACKEND_NAME = "gpu-cuda"
_FALLBACK_NAME = "gpu-cuda[cpu-fallback]"


# ---------------------------------------------------------------------------
# Kernel source — CUDA C. Pure ASCII, no Python interpolation.
# The SHA-256 and SHA-512 primitives are inlined; layout and behavior
# mirror the OpenCL kernels for consistency.
# ---------------------------------------------------------------------------

_CUDA_KERNELS_SRC = r"""
typedef unsigned int  u32;
typedef unsigned long long u64;
typedef unsigned char u8;

__device__ __constant__ u32 K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)    (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)     (ROTR32(x,2) ^ ROTR32(x,13) ^ ROTR32(x,22))
#define BSIG1(x)     (ROTR32(x,6) ^ ROTR32(x,11) ^ ROTR32(x,25))
#define SSIG0(x)     (ROTR32(x,7) ^ ROTR32(x,18) ^ ((x) >> 3))
#define SSIG1(x)     (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10))

__device__ static void sha256_block(u32 state[8], u32 W[64]) {
    for (int t = 16; t < 64; t++) {
        W[t] = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16];
    }
    u32 a=state[0],b=state[1],c=state[2],d=state[3];
    u32 e=state[4],f=state[5],g=state[6],h=state[7];
    for (int t = 0; t < 64; t++) {
        u32 T1 = h + BSIG1(e) + CH(e,f,g) + K256[t] + W[t];
        u32 T2 = BSIG0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

__device__ static void sha256_init(u32 state[8]) {
    state[0]=0x6a09e667u; state[1]=0xbb67ae85u;
    state[2]=0x3c6ef372u; state[3]=0xa54ff53au;
    state[4]=0x510e527fu; state[5]=0x9b05688cu;
    state[6]=0x1f83d9abu; state[7]=0x5be0cd19u;
}

__device__ static void sha256_compress_block(u32 state[8], const u8 *blk64) {
    u32 W[64];
    for (int i = 0; i < 16; i++) {
        W[i] = ((u32)blk64[i*4    ] << 24)
             | ((u32)blk64[i*4 + 1] << 16)
             | ((u32)blk64[i*4 + 2] <<  8)
             | ((u32)blk64[i*4 + 3]);
    }
    sha256_block(state, W);
}

extern "C" __global__ void pbkdf2_sha256_kernel(
    const u8  * __restrict__ passwords,
    const u32 * __restrict__ pwd_lens,
    const u8  * __restrict__ salt,
    u8        * __restrict__ out,
    u32 pwd_stride,
    u32 salt_len,
    u32 iterations,
    u32 num_items
) {
    unsigned int gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= num_items) return;

    u8 password[64];
    u32 pwd_len = pwd_lens[gid];
    if (pwd_len > 64) pwd_len = 64;
    for (unsigned i = 0; i < 64; i++) {
        password[i] = (i < pwd_len) ? passwords[gid * pwd_stride + i] : (u8)0;
    }
    u8 ipad[64];
    u8 opad[64];
    for (unsigned i = 0; i < 64; i++) {
        ipad[i] = password[i] ^ 0x36;
        opad[i] = password[i] ^ 0x5C;
    }
    u32 ipad_state[8]; sha256_init(ipad_state);
    sha256_compress_block(ipad_state, ipad);
    u32 opad_state[8]; sha256_init(opad_state);
    sha256_compress_block(opad_state, opad);

    // U_1 = HMAC(password, salt || INT(1)); single-block output.
    u32 u_state[8];
    for (int i = 0; i < 8; i++) u_state[i] = ipad_state[i];

    // Host verifies salt_len <= 51 (single SHA block fits salt+4+1+8).
    u8 inner[64];
    unsigned ilen = 0;
    for (unsigned i = 0; i < salt_len && i < 51; i++) inner[ilen++] = salt[i];
    inner[ilen++] = 0x00;
    inner[ilen++] = 0x00;
    inner[ilen++] = 0x00;
    inner[ilen++] = 0x01;
    unsigned total_bits = (64 + ilen) * 8;
    inner[ilen++] = 0x80;
    while (ilen < 56) inner[ilen++] = 0x00;
    inner[56] = 0; inner[57] = 0; inner[58] = 0; inner[59] = 0;
    inner[60] = (u8)((total_bits >> 24) & 0xFF);
    inner[61] = (u8)((total_bits >> 16) & 0xFF);
    inner[62] = (u8)((total_bits >>  8) & 0xFF);
    inner[63] = (u8)((total_bits      ) & 0xFF);
    sha256_compress_block(u_state, inner);

    u32 t_state[8];
    for (int i = 0; i < 8; i++) t_state[i] = opad_state[i];
    u8 outer[64];
    for (int i = 0; i < 8; i++) {
        outer[i*4    ] = (u8)(u_state[i] >> 24);
        outer[i*4 + 1] = (u8)(u_state[i] >> 16);
        outer[i*4 + 2] = (u8)(u_state[i] >>  8);
        outer[i*4 + 3] = (u8)(u_state[i]      );
    }
    outer[32] = 0x80;
    for (int i = 33; i < 56; i++) outer[i] = 0x00;
    unsigned total_bits2 = (64 + 32) * 8;
    outer[56]=0; outer[57]=0; outer[58]=0; outer[59]=0;
    outer[60] = (u8)((total_bits2 >> 24) & 0xFF);
    outer[61] = (u8)((total_bits2 >> 16) & 0xFF);
    outer[62] = (u8)((total_bits2 >>  8) & 0xFF);
    outer[63] = (u8)((total_bits2      ) & 0xFF);
    sha256_compress_block(t_state, outer);

    u32 T[8];
    u32 U_prev[8];
    for (int i = 0; i < 8; i++) { T[i] = t_state[i]; U_prev[i] = t_state[i]; }

    for (unsigned it = 1; it < iterations; it++) {
        u32 inner_state[8];
        for (int i = 0; i < 8; i++) inner_state[i] = ipad_state[i];
        u8 buf[64];
        for (int i = 0; i < 8; i++) {
            buf[i*4    ] = (u8)(U_prev[i] >> 24);
            buf[i*4 + 1] = (u8)(U_prev[i] >> 16);
            buf[i*4 + 2] = (u8)(U_prev[i] >>  8);
            buf[i*4 + 3] = (u8)(U_prev[i]      );
        }
        buf[32] = 0x80;
        for (int i = 33; i < 56; i++) buf[i] = 0x00;
        unsigned tb = (64 + 32) * 8;
        buf[56]=0; buf[57]=0; buf[58]=0; buf[59]=0;
        buf[60] = (u8)((tb >> 24) & 0xFF);
        buf[61] = (u8)((tb >> 16) & 0xFF);
        buf[62] = (u8)((tb >>  8) & 0xFF);
        buf[63] = (u8)((tb      ) & 0xFF);
        sha256_compress_block(inner_state, buf);

        u32 outer_state[8];
        for (int i = 0; i < 8; i++) outer_state[i] = opad_state[i];
        for (int i = 0; i < 8; i++) {
            buf[i*4    ] = (u8)(inner_state[i] >> 24);
            buf[i*4 + 1] = (u8)(inner_state[i] >> 16);
            buf[i*4 + 2] = (u8)(inner_state[i] >>  8);
            buf[i*4 + 3] = (u8)(inner_state[i]      );
        }
        buf[32] = 0x80;
        for (int i = 33; i < 56; i++) buf[i] = 0x00;
        unsigned tb2 = (64 + 32) * 8;
        buf[56]=0; buf[57]=0; buf[58]=0; buf[59]=0;
        buf[60] = (u8)((tb2 >> 24) & 0xFF);
        buf[61] = (u8)((tb2 >> 16) & 0xFF);
        buf[62] = (u8)((tb2 >>  8) & 0xFF);
        buf[63] = (u8)((tb2      ) & 0xFF);
        sha256_compress_block(outer_state, buf);

        for (int i = 0; i < 8; i++) {
            T[i]      ^= outer_state[i];
            U_prev[i]  = outer_state[i];
        }
    }

    u8 *dst = out + gid * 32u;
    for (int i = 0; i < 8; i++) {
        dst[i*4    ] = (u8)(T[i] >> 24);
        dst[i*4 + 1] = (u8)(T[i] >> 16);
        dst[i*4 + 2] = (u8)(T[i] >>  8);
        dst[i*4 + 3] = (u8)(T[i]      );
    }
}

// --- SHA-512 primitives + sha512_iter kernel --------------------------------

__device__ __constant__ u64 K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH64(x,y,z)    (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x,y,z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0_64(x)    (ROTR64(x,28) ^ ROTR64(x,34) ^ ROTR64(x,39))
#define BSIG1_64(x)    (ROTR64(x,14) ^ ROTR64(x,18) ^ ROTR64(x,41))
#define SSIG0_64(x)    (ROTR64(x,1)  ^ ROTR64(x,8)  ^ ((x) >> 7))
#define SSIG1_64(x)    (ROTR64(x,19) ^ ROTR64(x,61) ^ ((x) >> 6))

__device__ static void sha512_block(u64 state[8], u64 W[80]) {
    for (int t = 16; t < 80; t++) {
        W[t] = SSIG1_64(W[t-2]) + W[t-7] + SSIG0_64(W[t-15]) + W[t-16];
    }
    u64 a=state[0],b=state[1],c=state[2],d=state[3];
    u64 e=state[4],f=state[5],g=state[6],h=state[7];
    for (int t = 0; t < 80; t++) {
        u64 T1 = h + BSIG1_64(e) + CH64(e,f,g) + K512[t] + W[t];
        u64 T2 = BSIG0_64(a) + MAJ64(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

__device__ static void sha512_init(u64 state[8]) {
    state[0]=0x6a09e667f3bcc908ULL; state[1]=0xbb67ae8584caa73bULL;
    state[2]=0x3c6ef372fe94f82bULL; state[3]=0xa54ff53a5f1d36f1ULL;
    state[4]=0x510e527fade682d1ULL; state[5]=0x9b05688c2b3e6c1fULL;
    state[6]=0x1f83d9abfb41bd6bULL; state[7]=0x5be0cd19137e2179ULL;
}

__device__ static void sha512_hash_short(const u8 *msg, unsigned msg_len, u8 *digest) {
    u64 state[8]; sha512_init(state);
    u8 buf[256];
    for (unsigned i = 0; i < msg_len; i++) buf[i] = msg[i];
    buf[msg_len] = 0x80;
    unsigned pad_to = (msg_len < 112) ? 128 : 256;
    for (unsigned i = msg_len + 1; i < pad_to - 16; i++) buf[i] = 0;
    u64 bits = (u64)msg_len * 8ULL;
    for (int i = 0; i < 8; i++) buf[pad_to - 16 + i] = 0;
    buf[pad_to - 8] = (u8)((bits >> 56) & 0xFF);
    buf[pad_to - 7] = (u8)((bits >> 48) & 0xFF);
    buf[pad_to - 6] = (u8)((bits >> 40) & 0xFF);
    buf[pad_to - 5] = (u8)((bits >> 32) & 0xFF);
    buf[pad_to - 4] = (u8)((bits >> 24) & 0xFF);
    buf[pad_to - 3] = (u8)((bits >> 16) & 0xFF);
    buf[pad_to - 2] = (u8)((bits >>  8) & 0xFF);
    buf[pad_to - 1] = (u8)((bits      ) & 0xFF);
    unsigned blocks = pad_to / 128;
    for (unsigned b = 0; b < blocks; b++) {
        u64 W[80];
        for (int i = 0; i < 16; i++) {
            W[i] =
                ((u64)buf[b*128 + i*8    ] << 56) |
                ((u64)buf[b*128 + i*8 + 1] << 48) |
                ((u64)buf[b*128 + i*8 + 2] << 40) |
                ((u64)buf[b*128 + i*8 + 3] << 32) |
                ((u64)buf[b*128 + i*8 + 4] << 24) |
                ((u64)buf[b*128 + i*8 + 5] << 16) |
                ((u64)buf[b*128 + i*8 + 6] <<  8) |
                ((u64)buf[b*128 + i*8 + 7]      );
        }
        sha512_block(state, W);
    }
    for (int i = 0; i < 8; i++) {
        digest[i*8    ] = (u8)(state[i] >> 56);
        digest[i*8 + 1] = (u8)(state[i] >> 48);
        digest[i*8 + 2] = (u8)(state[i] >> 40);
        digest[i*8 + 3] = (u8)(state[i] >> 32);
        digest[i*8 + 4] = (u8)(state[i] >> 24);
        digest[i*8 + 5] = (u8)(state[i] >> 16);
        digest[i*8 + 6] = (u8)(state[i] >>  8);
        digest[i*8 + 7] = (u8)(state[i]      );
    }
}

extern "C" __global__ void sha512_iter_kernel(
    const u8  * __restrict__ data_in,
    const u32 * __restrict__ data_lens,
    u8        * __restrict__ out,
    u32 in_stride,
    u32 iterations,
    u32 num_items
) {
    unsigned int gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= num_items) return;
    u32 dlen = data_lens[gid];
    if (dlen > 128) dlen = 128;
    u8 cur[128];
    u8 nxt[64];
    for (unsigned i = 0; i < 128; i++) cur[i] = (i < dlen) ? data_in[gid*in_stride + i] : 0;
    unsigned cur_len = dlen;
    for (unsigned it = 0; it < iterations; it++) {
        sha512_hash_short(cur, cur_len, nxt);
        for (int i = 0; i < 64; i++) cur[i] = nxt[i];
        cur_len = 64;
    }
    u8 *dst = out + gid * 64u;
    for (int i = 0; i < 64; i++) dst[i] = cur[i];
}
"""


# ---------------------------------------------------------------------------
# Backend class
# ---------------------------------------------------------------------------


class CUDABackend(OffloadBackend):
    """CUDA backend with PBKDF2-SHA-256 + SHA-512-iter kernels.

    Mirrors :class:`OpenCLBackend` in shape and fallback semantics.
    """

    _NAME = _BACKEND_NAME

    def __init__(self, context: Any = None) -> None:
        self._context = context
        self._available = False
        self._pycuda: Any = None
        self._drv: Any = None
        self._compiler: Any = None
        self._module: Any = None
        self._pbkdf2_fn: Any = None
        self._sha512_fn: Any = None
        self._compile_error: str | None = None
        try:
            import pycuda  # noqa: F401
            import pycuda.autoinit  # noqa: F401 — triggers driver init
            import pycuda.driver as drv
            from pycuda.compiler import SourceModule

            self._pycuda = pycuda
            self._drv = drv
            self._compiler = SourceModule
            self._available = True
        except Exception as exc:  # noqa: BLE001
            log.debug("pycuda unavailable", error=str(exc))
            self._available = False

    @property
    def name(self) -> str:
        return self._NAME

    def is_available(self) -> bool:
        return self._available

    def capabilities(self) -> set[str]:
        if not self._available:
            return set()
        return {"pbkdf2_sha256_gpu", "sha512_iter_gpu"}

    def _ensure_module(self) -> bool:
        if not self._available or self._compiler is None:
            return False
        if self._module is not None:
            return True
        if self._compile_error is not None:
            return False
        try:
            self._module = self._compiler(_CUDA_KERNELS_SRC, no_extern_c=False)
            self._pbkdf2_fn = self._module.get_function("pbkdf2_sha256_kernel")
            self._sha512_fn = self._module.get_function("sha512_iter_kernel")
            return True
        except Exception as exc:  # noqa: BLE001
            self._compile_error = f"{type(exc).__name__}: {exc}"
            log.warning("cuda program build failed", error=self._compile_error)
            self._module = None
            return False

    def submit(self, job: OffloadJob[object, object]) -> Future[OffloadResult]:
        if not self._available:
            raise NotImplementedError(
                "CUDABackend requires the 'pycuda' package "
                "(install the 'offload_gpu' extra)"
            )

        future: Future[OffloadResult] = Future()
        future.set_running_or_notify_cancel()
        started = time.perf_counter()
        payload = job.payload if isinstance(job.payload, Mapping) else {}

        try:
            if job.kind == "pbkdf2_sha256":
                output, backend_used = self._run_pbkdf2(payload)
            elif job.kind == "sha512_iter":
                output, backend_used = self._run_sha512_iter(payload)
            elif job.kind == "argon2id":
                raise NotImplementedError(
                    "Argon2id is memory-hard and not implemented on the CUDA "
                    "backend — use backend='process' with the CPU argon2-cffi path"
                )
            else:
                raise NotImplementedError(
                    f"CUDABackend does not handle kind={job.kind!r}"
                )
            future.set_result(
                OffloadResult(
                    job_id=job.job_id,
                    ok=True,
                    output=output,
                    error=None,
                    elapsed_s=time.perf_counter() - started,
                    backend=backend_used,
                )
            )
        except NotImplementedError:
            raise
        except BaseException as exc:  # noqa: BLE001
            future.set_result(
                OffloadResult(
                    job_id=job.job_id,
                    ok=False,
                    output=None,
                    error=f"{type(exc).__name__}: {exc}",
                    elapsed_s=time.perf_counter() - started,
                    backend=_BACKEND_NAME,
                )
            )
        return future

    def _run_pbkdf2(self, payload: Mapping[str, Any]) -> tuple[bytes, str]:
        passwords, salt, iterations, dklen = _extract_pbkdf2(payload)
        if not self._ensure_module() or self._pbkdf2_fn is None:
            return self._cpu_pbkdf2(passwords, salt, iterations, dklen)
        if dklen > 32 or len(salt) > 51 or any(len(p) > 64 for p in passwords):
            log.debug("pbkdf2 outside kernel limits — CPU fallback")
            return self._cpu_pbkdf2(passwords, salt, iterations, dklen)

        try:
            import numpy as np
            drv = self._drv

            n = len(passwords)
            stride = 64
            pwd_buf = np.zeros(n * stride, dtype=np.uint8)
            pwd_lens = np.zeros(n, dtype=np.uint32)
            for i, p in enumerate(passwords):
                pwd_buf[i * stride : i * stride + len(p)] = np.frombuffer(p, dtype=np.uint8)
                pwd_lens[i] = len(p)
            salt_buf = np.frombuffer(salt, dtype=np.uint8).copy()
            out_buf = np.zeros(n * 32, dtype=np.uint8)

            d_pwd = drv.mem_alloc(pwd_buf.nbytes)
            d_lens = drv.mem_alloc(pwd_lens.nbytes)
            d_salt = drv.mem_alloc(max(1, salt_buf.nbytes))
            d_out = drv.mem_alloc(out_buf.nbytes)
            drv.memcpy_htod(d_pwd, pwd_buf)
            drv.memcpy_htod(d_lens, pwd_lens)
            if salt_buf.nbytes:
                drv.memcpy_htod(d_salt, salt_buf)

            block = (min(n, 64), 1, 1)
            grid = ((n + block[0] - 1) // block[0], 1, 1)
            self._pbkdf2_fn(
                d_pwd,
                d_lens,
                d_salt,
                d_out,
                np.uint32(stride),
                np.uint32(len(salt)),
                np.uint32(iterations),
                np.uint32(n),
                block=block,
                grid=grid,
            )
            drv.Context.synchronize()
            drv.memcpy_dtoh(out_buf, d_out)
        except Exception as exc:  # noqa: BLE001
            log.warning("cuda pbkdf2 kernel run failed — CPU fallback",
                        error=f"{type(exc).__name__}: {exc}")
            return self._cpu_pbkdf2(passwords, salt, iterations, dklen)

        if len(passwords) == 1:
            return bytes(out_buf[:dklen].tobytes()), _BACKEND_NAME
        results: list[bytes] = []
        for i in range(len(passwords)):
            results.append(bytes(out_buf[i * 32 : i * 32 + dklen].tobytes()))
        return b"".join(results), _BACKEND_NAME

    def _cpu_pbkdf2(
        self,
        passwords: list[bytes],
        salt: bytes,
        iterations: int,
        dklen: int,
    ) -> tuple[bytes, str]:
        if len(passwords) == 1:
            out = _cpu_pbkdf2_sha256(
                {
                    "password": passwords[0],
                    "salt": salt,
                    "iterations": iterations,
                    "dklen": dklen,
                }
            )
            return out, _FALLBACK_NAME
        chunks = [
            _cpu_pbkdf2_sha256(
                {
                    "password": p,
                    "salt": salt,
                    "iterations": iterations,
                    "dklen": dklen,
                }
            )
            for p in passwords
        ]
        return b"".join(chunks), _FALLBACK_NAME

    def _run_sha512_iter(self, payload: Mapping[str, Any]) -> tuple[bytes, str]:
        data, iterations = _extract_sha512_iter(payload)
        if not self._ensure_module() or self._sha512_fn is None:
            return self._cpu_sha512_iter(data, iterations)
        if len(data) > 128:
            return self._cpu_sha512_iter(data, iterations)
        try:
            import numpy as np
            drv = self._drv

            stride = 128
            data_buf = np.zeros(stride, dtype=np.uint8)
            data_buf[: len(data)] = np.frombuffer(data, dtype=np.uint8)
            lens_buf = np.array([len(data)], dtype=np.uint32)
            out_buf = np.zeros(64, dtype=np.uint8)

            d_in = drv.mem_alloc(data_buf.nbytes)
            d_lens = drv.mem_alloc(lens_buf.nbytes)
            d_out = drv.mem_alloc(out_buf.nbytes)
            drv.memcpy_htod(d_in, data_buf)
            drv.memcpy_htod(d_lens, lens_buf)
            self._sha512_fn(
                d_in,
                d_lens,
                d_out,
                np.uint32(stride),
                np.uint32(iterations),
                np.uint32(1),
                block=(1, 1, 1),
                grid=(1, 1, 1),
            )
            drv.Context.synchronize()
            drv.memcpy_dtoh(out_buf, d_out)
        except Exception as exc:  # noqa: BLE001
            log.warning("cuda sha512 kernel run failed — CPU fallback",
                        error=f"{type(exc).__name__}: {exc}")
            return self._cpu_sha512_iter(data, iterations)
        return bytes(out_buf.tobytes()), _BACKEND_NAME

    def _cpu_sha512_iter(self, data: bytes, iterations: int) -> tuple[bytes, str]:
        out = _cpu_sha512_iter({"data": data, "iterations": iterations})
        return out, _FALLBACK_NAME

    def shutdown(self, wait: bool = True) -> None:
        self._module = None
        self._pbkdf2_fn = None
        self._sha512_fn = None


# ---------------------------------------------------------------------------
# Payload extractors (duplicated intentionally — avoids an import of the
# OpenCL module, which would trigger its own pyopencl probe).
# ---------------------------------------------------------------------------


def _as_bytes(value: Any, field: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"payload field {field!r} must be bytes or str")


def _extract_pbkdf2(payload: Mapping[str, Any]) -> tuple[list[bytes], bytes, int, int]:
    if "passwords" in payload:
        raw = payload["passwords"]
        passwords = [_as_bytes(p, "passwords[i]") for p in raw]
    else:
        passwords = [_as_bytes(payload["password"], "password")]
    salt = _as_bytes(payload["salt"], "salt")
    iterations = int(payload["iterations"])
    dklen = int(payload["dklen"])
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if dklen <= 0:
        raise ValueError("dklen must be positive")
    return passwords, salt, iterations, dklen


def _extract_sha512_iter(payload: Mapping[str, Any]) -> tuple[bytes, int]:
    data = _as_bytes(payload["data"], "data")
    iterations = int(payload["iterations"])
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    return data, iterations


__all__ = ["CUDABackend"]
