"""OpenCL GPU offload backend — slice 13.

Implements :class:`OpenCLBackend` with kernels for the two GPU-amenable
KDFs in Deep View's unlock pipeline:

- ``pbkdf2_sha256`` — PBKDF2-HMAC-SHA-256 (single-block output only,
  i.e. ``dklen <= 32``). Each work-item computes one independent
  derivation; batch submit is where GPU offload actually wins.
- ``sha512_iter`` — repeated SHA-512 of a ``data`` buffer for N rounds,
  used by the VeraCrypt / TrueCrypt unlock paths.

:func:`submit` dispatches on ``OffloadJob.kind``. Anything else — and
explicitly ``argon2id`` — raises :class:`NotImplementedError` with a
message pointing at the CPU ``argon2-cffi`` path. Argon2 is
memory-hard and would require a GB of VRAM per thread at realistic
parameters, so it is honestly out of scope for this backend. Use
``backend="process"`` and the :mod:`deepview.offload.kdf` reference
implementation instead.

Fallback semantics: every call that reaches :meth:`submit` returns a
valid :class:`OffloadResult`. If the kernel fails to build, or any
runtime OpenCL error fires during enqueue / read-back, we log the
error and transparently fall back to the CPU implementation in
:mod:`deepview.offload.kdf`. The caller still sees a healthy future;
the ``error`` field is always ``None`` on success regardless of which
path ran. :attr:`OffloadResult.backend` is ``"gpu-opencl"`` when the
GPU path ran and ``"gpu-opencl[cpu-fallback]"`` when we reverted.

Single-job wall-clock reality check: for ``dklen <= 32`` and
``iterations`` in the realistic LUKS2 range, one lone derivation
spends most of its time in kernel launch / read-back overhead. The
GPU advantage materializes when the caller submits a *batch* of
candidate passphrases by shoving a list into ``payload["passwords"]``
(see :func:`_dispatch_pbkdf2`). For the ``"password"`` singleton form
we still run the kernel, but caller-measured speedup may be < 1x.

``pyopencl`` is imported lazily inside :meth:`__init__`. A core
install with no ``offload_gpu`` extra never triggers the import or
the noisy ICD-discovery warnings.
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

log = get_logger("offload.gpu_opencl")

_BACKEND_NAME = "gpu-opencl"
_FALLBACK_NAME = "gpu-opencl[cpu-fallback]"


# ---------------------------------------------------------------------------
# Kernel source strings. Pure ASCII, no Python interpolation. These are
# deliberately self-contained — the SHA primitives are inlined so the kernels
# build without any #include fishing.
# ---------------------------------------------------------------------------

_PBKDF2_SHA256_KERNEL_SRC = r"""
// PBKDF2-HMAC-SHA-256, single-block output (dklen <= 32).
//
// Layout in global memory:
//   passwords  : uchar[num_items][PWD_STRIDE]  (zero-padded)
//   pwd_lens   : uint[num_items]
//   salt       : uchar[SALT_LEN]               (shared)
//   out        : uchar[num_items][32]          (always a full 32-byte block)
// Scalars passed as kernel args: salt_len, iterations.
//
// One work-item per (password, salt) pair. Correctness is the priority;
// this is neither a constant-time implementation nor an optimal one.

typedef unsigned int  u32;
typedef unsigned char u8;

__constant u32 K256[64] = {
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

// Transform a single 64-byte block given 16 big-endian u32 words in W[0..15].
static inline void sha256_block(u32 state[8], u32 W[64]) {
    #pragma unroll 16
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

// Hash an arbitrary-length message (length <= 64 + salt_len + 4) producing
// a 32-byte digest. This is only used for the keyed pre-hash when the
// password is longer than 64 bytes — which the host rejects anyway.
// We keep the implementation minimal and target the exact sizes PBKDF2
// needs.

// Initialize SHA-256 state.
static inline void sha256_init(u32 state[8]) {
    state[0]=0x6a09e667u; state[1]=0xbb67ae85u;
    state[2]=0x3c6ef372u; state[3]=0xa54ff53au;
    state[4]=0x510e527fu; state[5]=0x9b05688cu;
    state[6]=0x1f83d9abu; state[7]=0x5be0cd19u;
}

// HMAC-SHA-256 with at-most-64-byte keys (which is what PBKDF2 gives us
// after the key->ipad/opad expansion). Produces a 32-byte MAC from an
// arbitrary-length message expressed as two concatenated buffers so we
// can avoid copying the salt every iteration.
//
// key_blk: caller-prepared 64-byte key block XORed with ipad/opad as
//          needed; i.e. caller does the XOR into a scratch buffer.
static inline void sha256_compress_with_prefix(
    u32 state[8],
    __private const u8 *key_blk64
) {
    u32 W[64];
    #pragma unroll 16
    for (int i = 0; i < 16; i++) {
        W[i] = ((u32)key_blk64[i*4    ] << 24)
             | ((u32)key_blk64[i*4 + 1] << 16)
             | ((u32)key_blk64[i*4 + 2] <<  8)
             | ((u32)key_blk64[i*4 + 3]);
    }
    sha256_block(state, W);
}

__kernel void pbkdf2_sha256_kernel(
    __global const u8  *passwords,
    __global const u32 *pwd_lens,
    __global const u8  *salt,
    __global       u8  *out,
    const u32          pwd_stride,
    const u32          salt_len,
    const u32          iterations
) {
    const uint gid = get_global_id(0);

    // Load password.
    u8 password[64];
    u32 pwd_len = pwd_lens[gid];
    if (pwd_len > 64) pwd_len = 64;  // host ensures <= 64.
    #pragma unroll
    for (uint i = 0; i < 64; i++) {
        password[i] = (i < pwd_len) ? passwords[gid * pwd_stride + i] : (u8)0;
    }

    // ipad / opad scratch (key XOR 0x36 / 0x5C, zero-padded to 64 bytes).
    u8 ipad[64];
    u8 opad[64];
    #pragma unroll
    for (uint i = 0; i < 64; i++) {
        ipad[i] = password[i] ^ 0x36;
        opad[i] = password[i] ^ 0x5C;
    }

    // Pre-compute ipad/opad states (HMAC key schedule).
    u32 ipad_state[8]; sha256_init(ipad_state);
    sha256_compress_with_prefix(ipad_state, ipad);
    u32 opad_state[8]; sha256_init(opad_state);
    sha256_compress_with_prefix(opad_state, opad);

    // U_1 = HMAC(password, salt || INT(1))
    // We only compute block index 1; dklen <= 32 by contract.
    u32 u_state[8];
    for (int i = 0; i < 8; i++) u_state[i] = ipad_state[i];

    // Build the inner message salt || 0x00000001 then pad for SHA.
    // Total inner length (after ipad block) = salt_len + 4 bytes; the
    // 64-byte ipad block has already been absorbed into u_state.
    //
    // We assume salt_len <= 51 (fits in one SHA block: salt + 4 (INT(1)) +
    // 0x80 + zero-pad + 8-byte length == <= 64 iff salt_len <= 51).
    // Host verifies this.
    u8 inner[64];
    uint ilen = 0;
    for (uint i = 0; i < salt_len && i < 51; i++) inner[ilen++] = salt[i];
    inner[ilen++] = 0x00;
    inner[ilen++] = 0x00;
    inner[ilen++] = 0x00;
    inner[ilen++] = 0x01;
    // SHA padding: one 0x80 byte, zeros, then 8-byte big-endian bit length.
    // Total message absorbed into SHA = 64 (ipad) + ilen bytes.
    uint total_bits = (64 + ilen) * 8;
    inner[ilen++] = 0x80;
    while (ilen < 56) inner[ilen++] = 0x00;
    // length (big-endian 64-bit)
    inner[56] = 0;
    inner[57] = 0;
    inner[58] = 0;
    inner[59] = 0;
    inner[60] = (u8)((total_bits >> 24) & 0xFF);
    inner[61] = (u8)((total_bits >> 16) & 0xFF);
    inner[62] = (u8)((total_bits >>  8) & 0xFF);
    inner[63] = (u8)((total_bits      ) & 0xFF);

    {
        u32 W[64];
        #pragma unroll 16
        for (int i = 0; i < 16; i++) {
            W[i] = ((u32)inner[i*4    ] << 24)
                 | ((u32)inner[i*4 + 1] << 16)
                 | ((u32)inner[i*4 + 2] <<  8)
                 | ((u32)inner[i*4 + 3]);
        }
        sha256_block(u_state, W);
    }

    // u_state now holds HMAC inner hash. Feed through opad.
    u32 t_state[8];
    for (int i = 0; i < 8; i++) t_state[i] = opad_state[i];
    {
        u8 outer[64];
        // opad block already absorbed into t_state; now we absorb
        // the 32-byte inner hash + SHA padding.
        for (int i = 0; i < 8; i++) {
            outer[i*4    ] = (u8)(u_state[i] >> 24);
            outer[i*4 + 1] = (u8)(u_state[i] >> 16);
            outer[i*4 + 2] = (u8)(u_state[i] >>  8);
            outer[i*4 + 3] = (u8)(u_state[i]      );
        }
        outer[32] = 0x80;
        for (int i = 33; i < 56; i++) outer[i] = 0x00;
        uint total_bits2 = (64 + 32) * 8;
        outer[56] = 0;
        outer[57] = 0;
        outer[58] = 0;
        outer[59] = 0;
        outer[60] = (u8)((total_bits2 >> 24) & 0xFF);
        outer[61] = (u8)((total_bits2 >> 16) & 0xFF);
        outer[62] = (u8)((total_bits2 >>  8) & 0xFF);
        outer[63] = (u8)((total_bits2      ) & 0xFF);

        u32 W[64];
        #pragma unroll 16
        for (int i = 0; i < 16; i++) {
            W[i] = ((u32)outer[i*4    ] << 24)
                 | ((u32)outer[i*4 + 1] << 16)
                 | ((u32)outer[i*4 + 2] <<  8)
                 | ((u32)outer[i*4 + 3]);
        }
        sha256_block(t_state, W);
    }

    // T = U_1 initially; U_prev = U_1.
    u32 T[8];
    u32 U_prev[8];
    for (int i = 0; i < 8; i++) {
        T[i] = t_state[i];
        U_prev[i] = t_state[i];
    }

    // Subsequent iterations: U_n = HMAC(password, U_{n-1})
    for (uint it = 1; it < iterations; it++) {
        // inner hash: ipad_state absorbs 32-byte U_prev + SHA padding.
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
        uint tb = (64 + 32) * 8;
        buf[56]=0; buf[57]=0; buf[58]=0; buf[59]=0;
        buf[60] = (u8)((tb >> 24) & 0xFF);
        buf[61] = (u8)((tb >> 16) & 0xFF);
        buf[62] = (u8)((tb >>  8) & 0xFF);
        buf[63] = (u8)((tb      ) & 0xFF);
        {
            u32 W[64];
            #pragma unroll 16
            for (int i = 0; i < 16; i++) {
                W[i] = ((u32)buf[i*4    ] << 24)
                     | ((u32)buf[i*4 + 1] << 16)
                     | ((u32)buf[i*4 + 2] <<  8)
                     | ((u32)buf[i*4 + 3]);
            }
            sha256_block(inner_state, W);
        }
        // outer hash: opad_state absorbs 32-byte inner + padding.
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
        uint tb2 = (64 + 32) * 8;
        buf[56]=0; buf[57]=0; buf[58]=0; buf[59]=0;
        buf[60] = (u8)((tb2 >> 24) & 0xFF);
        buf[61] = (u8)((tb2 >> 16) & 0xFF);
        buf[62] = (u8)((tb2 >>  8) & 0xFF);
        buf[63] = (u8)((tb2      ) & 0xFF);
        {
            u32 W[64];
            #pragma unroll 16
            for (int i = 0; i < 16; i++) {
                W[i] = ((u32)buf[i*4    ] << 24)
                     | ((u32)buf[i*4 + 1] << 16)
                     | ((u32)buf[i*4 + 2] <<  8)
                     | ((u32)buf[i*4 + 3]);
            }
            sha256_block(outer_state, W);
        }
        // T ^= U_n; U_prev = U_n.
        for (int i = 0; i < 8; i++) {
            T[i]      ^= outer_state[i];
            U_prev[i]  = outer_state[i];
        }
    }

    // Write 32-byte block out (caller truncates to dklen <= 32).
    __global u8 *dst = out + gid * 32u;
    for (int i = 0; i < 8; i++) {
        dst[i*4    ] = (u8)(T[i] >> 24);
        dst[i*4 + 1] = (u8)(T[i] >> 16);
        dst[i*4 + 2] = (u8)(T[i] >>  8);
        dst[i*4 + 3] = (u8)(T[i]      );
    }
}
"""


_SHA512_ITER_KERNEL_SRC = r"""
// Repeated SHA-512(data) for N rounds. One work-item, one (data, N) pair.
// Host constrains the initial data to <= 128 bytes so the first block
// fits in a single SHA-512 block with padding.

typedef unsigned long  u64;
typedef unsigned int   u32;
typedef unsigned char  u8;

__constant u64 K512[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH64(x,y,z)    (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x,y,z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0_64(x)    (ROTR64(x,28) ^ ROTR64(x,34) ^ ROTR64(x,39))
#define BSIG1_64(x)    (ROTR64(x,14) ^ ROTR64(x,18) ^ ROTR64(x,41))
#define SSIG0_64(x)    (ROTR64(x,1)  ^ ROTR64(x,8)  ^ ((x) >> 7))
#define SSIG1_64(x)    (ROTR64(x,19) ^ ROTR64(x,61) ^ ((x) >> 6))

static inline void sha512_block(u64 state[8], u64 W[80]) {
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

static inline void sha512_init(u64 state[8]) {
    state[0]=0x6a09e667f3bcc908UL; state[1]=0xbb67ae8584caa73bUL;
    state[2]=0x3c6ef372fe94f82bUL; state[3]=0xa54ff53a5f1d36f1UL;
    state[4]=0x510e527fade682d1UL; state[5]=0x9b05688c2b3e6c1fUL;
    state[6]=0x1f83d9abfb41bd6bUL; state[7]=0x5be0cd19137e2179UL;
}

// Hash a <=128-byte message to 64-byte digest; digest -> 64-byte buffer.
// If msg_len <= 111, one block suffices; otherwise two blocks.
static inline void sha512_hash_short(
    __private const u8 *msg, uint msg_len, __private u8 *digest
) {
    u64 state[8]; sha512_init(state);
    u8 buf[256];
    for (uint i = 0; i < msg_len; i++) buf[i] = msg[i];
    buf[msg_len] = 0x80;
    uint pad_to = (msg_len < 112) ? 128 : 256;
    for (uint i = msg_len + 1; i < pad_to - 16; i++) buf[i] = 0;
    // 128-bit length in bits, big-endian.
    unsigned long bits = (unsigned long)msg_len * 8UL;
    for (int i = 0; i < 8; i++) buf[pad_to - 16 + i] = 0;
    buf[pad_to - 8] = (u8)((bits >> 56) & 0xFF);
    buf[pad_to - 7] = (u8)((bits >> 48) & 0xFF);
    buf[pad_to - 6] = (u8)((bits >> 40) & 0xFF);
    buf[pad_to - 5] = (u8)((bits >> 32) & 0xFF);
    buf[pad_to - 4] = (u8)((bits >> 24) & 0xFF);
    buf[pad_to - 3] = (u8)((bits >> 16) & 0xFF);
    buf[pad_to - 2] = (u8)((bits >>  8) & 0xFF);
    buf[pad_to - 1] = (u8)((bits      ) & 0xFF);
    uint blocks = pad_to / 128;
    for (uint b = 0; b < blocks; b++) {
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

__kernel void sha512_iter_kernel(
    __global const u8  *data_in,
    __global const u32 *data_lens,
    __global       u8  *out,
    const u32          in_stride,
    const u32          iterations
) {
    const uint gid = get_global_id(0);
    u32 dlen = data_lens[gid];
    if (dlen > 128) dlen = 128;

    u8 cur[128];
    u8 nxt[64];
    for (uint i = 0; i < 128; i++) cur[i] = (i < dlen) ? data_in[gid*in_stride + i] : 0;
    uint cur_len = dlen;

    for (uint it = 0; it < iterations; it++) {
        sha512_hash_short(cur, cur_len, nxt);
        for (int i = 0; i < 64; i++) cur[i] = nxt[i];
        cur_len = 64;
    }

    __global u8 *dst = out + gid * 64u;
    for (int i = 0; i < 64; i++) dst[i] = cur[i];
}
"""


# ---------------------------------------------------------------------------
# Backend class
# ---------------------------------------------------------------------------


class OpenCLBackend(OffloadBackend):
    """OpenCL backend with PBKDF2-SHA-256 + SHA-512-iter kernels.

    Construction never raises: if ``pyopencl`` is unavailable,
    :meth:`is_available` returns ``False`` and :meth:`submit` raises
    :class:`NotImplementedError`. Callers — typically
    :class:`deepview.offload.engine.OffloadEngine` — are expected to
    check :meth:`is_available` before registering the backend.
    """

    _NAME = _BACKEND_NAME

    def __init__(self, context: Any = None) -> None:
        # ``context`` is accepted but unused; the backend is stateless
        # with respect to the AnalysisContext. Tests pass it explicitly,
        # while :class:`OffloadEngine` constructs with no args.
        self._context = context
        self._available = False
        self._pyopencl: Any = None
        self._ctx: Any = None
        self._queue: Any = None
        self._program: Any = None
        self._compile_error: str | None = None
        try:
            import pyopencl as cl  # noqa: F401

            self._pyopencl = cl
            self._available = True
        except Exception as exc:  # noqa: BLE001 — ICD / driver failures too
            log.debug("pyopencl unavailable", error=str(exc))
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

    # ------------------------------------------------------------------
    # Lazy device/program setup
    # ------------------------------------------------------------------

    def _ensure_context(self) -> bool:
        """Lazily create the OpenCL context, queue, and compile programs.

        Returns ``True`` when the GPU path is ready, ``False`` if any
        step failed. Never raises.
        """
        if not self._available or self._pyopencl is None:
            return False
        if self._program is not None:
            return True
        if self._compile_error is not None:
            return False
        cl = self._pyopencl
        try:
            self._ctx = cl.create_some_context(interactive=False)
            self._queue = cl.CommandQueue(self._ctx)
            src = _PBKDF2_SHA256_KERNEL_SRC + "\n" + _SHA512_ITER_KERNEL_SRC
            self._program = cl.Program(self._ctx, src).build()
            return True
        except Exception as exc:  # noqa: BLE001
            self._compile_error = f"{type(exc).__name__}: {exc}"
            log.warning("opencl program build failed", error=self._compile_error)
            self._program = None
            return False

    # ------------------------------------------------------------------
    # submit()
    # ------------------------------------------------------------------

    def submit(self, job: OffloadJob[object, object]) -> Future[OffloadResult]:
        if not self._available:
            raise NotImplementedError(
                "OpenCLBackend requires the 'pyopencl' package "
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
                    "Argon2id is memory-hard and not implemented on the OpenCL "
                    "backend — use backend='process' with the CPU argon2-cffi path"
                )
            else:
                raise NotImplementedError(
                    f"OpenCLBackend does not handle kind={job.kind!r}"
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

    # ------------------------------------------------------------------
    # Dispatchers
    # ------------------------------------------------------------------

    def _run_pbkdf2(self, payload: Mapping[str, Any]) -> tuple[bytes, str]:
        passwords, salt, iterations, dklen = _extract_pbkdf2(payload)
        if not self._ensure_context() or self._program is None:
            return self._cpu_pbkdf2(passwords, salt, iterations, dklen)

        # Constraints for the single-block kernel.
        if dklen > 32:
            log.debug("pbkdf2 dklen > 32 — using CPU fallback", dklen=dklen)
            return self._cpu_pbkdf2(passwords, salt, iterations, dklen)
        if len(salt) > 51:
            # Single-block inner: salt + 4 (INT(1)) + 1 (0x80) + 8 (length) <= 64
            log.debug("pbkdf2 salt > 51 bytes — CPU fallback", salt_len=len(salt))
            return self._cpu_pbkdf2(passwords, salt, iterations, dklen)
        if any(len(p) > 64 for p in passwords):
            log.debug("pbkdf2 password > 64 bytes — CPU fallback")
            return self._cpu_pbkdf2(passwords, salt, iterations, dklen)

        try:
            import numpy as np  # local import — numpy is an offload_gpu cousin dep
            cl = self._pyopencl

            n = len(passwords)
            stride = 64
            pwd_buf = np.zeros(n * stride, dtype=np.uint8)
            pwd_lens = np.zeros(n, dtype=np.uint32)
            for i, p in enumerate(passwords):
                pwd_buf[i * stride : i * stride + len(p)] = np.frombuffer(p, dtype=np.uint8)
                pwd_lens[i] = len(p)
            salt_buf = np.frombuffer(salt, dtype=np.uint8)

            out_buf = np.zeros(n * 32, dtype=np.uint8)

            mf = cl.mem_flags
            d_pwd = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pwd_buf)
            d_lens = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pwd_lens)
            d_salt = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=salt_buf)
            d_out = cl.Buffer(self._ctx, mf.WRITE_ONLY, size=out_buf.nbytes)

            self._program.pbkdf2_sha256_kernel(
                self._queue,
                (n,),
                None,
                d_pwd,
                d_lens,
                d_salt,
                d_out,
                np.uint32(stride),
                np.uint32(len(salt)),
                np.uint32(iterations),
            )
            cl.enqueue_copy(self._queue, out_buf, d_out)
            self._queue.finish()
        except Exception as exc:  # noqa: BLE001
            log.warning("opencl pbkdf2 kernel run failed — CPU fallback",
                        error=f"{type(exc).__name__}: {exc}")
            return self._cpu_pbkdf2(passwords, salt, iterations, dklen)

        # Single-password shape preserved: return bare bytes.
        if len(passwords) == 1:
            return bytes(out_buf[:dklen].tobytes()), _BACKEND_NAME
        # Batch shape: concatenate each derivation truncated to dklen.
        results: list[bytes] = []
        for i in range(n):
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
        if not self._ensure_context() or self._program is None:
            return self._cpu_sha512_iter(data, iterations)
        if len(data) > 128:
            log.debug("sha512_iter data > 128 bytes — CPU fallback", data_len=len(data))
            return self._cpu_sha512_iter(data, iterations)
        try:
            import numpy as np
            cl = self._pyopencl

            stride = 128
            data_buf = np.zeros(stride, dtype=np.uint8)
            data_buf[: len(data)] = np.frombuffer(data, dtype=np.uint8)
            lens_buf = np.array([len(data)], dtype=np.uint32)
            out_buf = np.zeros(64, dtype=np.uint8)

            mf = cl.mem_flags
            d_in = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=data_buf)
            d_lens = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=lens_buf)
            d_out = cl.Buffer(self._ctx, mf.WRITE_ONLY, size=out_buf.nbytes)
            self._program.sha512_iter_kernel(
                self._queue,
                (1,),
                None,
                d_in,
                d_lens,
                d_out,
                np.uint32(stride),
                np.uint32(iterations),
            )
            cl.enqueue_copy(self._queue, out_buf, d_out)
            self._queue.finish()
        except Exception as exc:  # noqa: BLE001
            log.warning("opencl sha512 kernel run failed — CPU fallback",
                        error=f"{type(exc).__name__}: {exc}")
            return self._cpu_sha512_iter(data, iterations)
        return bytes(out_buf.tobytes()), _BACKEND_NAME

    def _cpu_sha512_iter(self, data: bytes, iterations: int) -> tuple[bytes, str]:
        out = _cpu_sha512_iter({"data": data, "iterations": iterations})
        return out, _FALLBACK_NAME

    def shutdown(self, wait: bool = True) -> None:
        # OpenCL buffers / program / queue are GC'd when self goes out
        # of scope; nothing to await.
        self._program = None
        self._queue = None
        self._ctx = None


# ---------------------------------------------------------------------------
# Payload extractors
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


__all__ = ["OpenCLBackend"]
