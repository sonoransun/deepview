"""BCC-flavoured eBPF C programs for Deep View's expanded probe set.

Each program is exposed as a module-level string so the Linux backend can
compose them into a single BPF object via ``bcc.BPF(text=...)``. A shared
``event_t`` structure carries a ``kind`` discriminator so a single perf buffer
suffices — the Python dispatcher reads ``kind`` and routes to the right
``MonitorEvent`` factory.

The programs deliberately keep field layouts in sync with ``EbpfEvent`` in
``providers/ebpf.py``; if you change one you must change the other.
"""
from __future__ import annotations

# Shared header included once per compilation unit.
HEADER = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#define DV_KIND_SYSCALL      1
#define DV_KIND_EXEC         2
#define DV_KIND_MODULE_LOAD  3
#define DV_KIND_CREDS        4
#define DV_KIND_TCP_CONNECT  5
#define DV_KIND_UDP_SENDMSG  6
#define DV_KIND_INET_LISTEN  7
#define DV_KIND_FILE_OPEN    8
#define DV_KIND_FILE_UNLINK  9
#define DV_KIND_PTRACE      10
#define DV_KIND_BPF_LOAD    11

struct dv_event_t {
    u32 kind;
    u32 pid;
    u32 tid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u64 timestamp_ns;
    char comm[16];

    // Generic scratch
    s64 retval;
    s64 syscall_nr;
    u64 arg0;
    u64 arg1;
    u64 arg2;
    u64 arg3;

    // Paths / strings (ring-buffer entries packed; we use a fixed chunk)
    char path[256];
    char path2[256];

    // Networking
    u32 saddr_v4;
    u32 daddr_v4;
    u16 sport;
    u16 dport;
    u8  protocol;

    // Creds
    u32 old_uid;
    u32 new_uid;
    u64 old_cap_effective;
    u64 new_cap_effective;

    // Ptrace
    s64 ptrace_request;
    u32 ptrace_target;
};

BPF_PERF_OUTPUT(dv_events);

static __always_inline void dv_fill_common(struct dv_event_t *e, u32 kind) {
    e->kind = kind;
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = id & 0xffffffff;
    u64 ug = bpf_get_current_uid_gid();
    e->uid = ug & 0xffffffff;
    e->gid = ug >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = task->real_parent->tgid;
}
"""

RAW_SYSCALL = r"""
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_SYSCALL);
    e.syscall_nr = args->id;
    dv_events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""

EXEC_ARGS = r"""
TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_EXEC);
    /*
     * The exec tracepoint includes a filename offset; we copy up to 256 bytes
     * of the new command path into e.path for user-space resolution.
     */
    unsigned int filename_loc = args->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e.path, sizeof(e.path),
                       (void *)args + filename_loc);
    dv_events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""

MODULE_LOAD = r"""
int kprobe__do_init_module(struct pt_regs *ctx, struct module *mod) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_MODULE_LOAD);
    bpf_probe_read_kernel_str(&e.path, sizeof(e.path), mod->name);
    dv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int kprobe__security_kernel_module_request(struct pt_regs *ctx, char *kmod_name) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_MODULE_LOAD);
    bpf_probe_read_user_str(&e.path, sizeof(e.path), kmod_name);
    dv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

CREDS = r"""
int kprobe__commit_creds(struct pt_regs *ctx, struct cred *new_cred) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_CREDS);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred *old = task->real_cred;
    e.old_uid = old->uid.val;
    e.new_uid = new_cred->uid.val;
    e.old_cap_effective = old->cap_effective.cap[0] | ((u64)old->cap_effective.cap[1] << 32);
    e.new_cap_effective = new_cred->cap_effective.cap[0] | ((u64)new_cred->cap_effective.cap[1] << 32);
    dv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

NET_FLOW = r"""
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_TCP_CONNECT);
    struct inet_sock *inet = (struct inet_sock *)sk;
    e.saddr_v4 = inet->inet_saddr;
    e.daddr_v4 = inet->inet_daddr;
    e.sport = inet->inet_sport;
    e.dport = inet->inet_dport;
    e.protocol = 6; /* TCP */
    dv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_UDP_SENDMSG);
    struct inet_sock *inet = (struct inet_sock *)sk;
    e.saddr_v4 = inet->inet_saddr;
    e.daddr_v4 = inet->inet_daddr;
    e.sport = inet->inet_sport;
    e.dport = inet->inet_dport;
    e.protocol = 17; /* UDP */
    dv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_INET_LISTEN);
    struct sock *sk = sock->sk;
    struct inet_sock *inet = (struct inet_sock *)sk;
    e.saddr_v4 = inet->inet_saddr;
    e.sport = inet->inet_sport;
    dv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

FILE_ACCESS = r"""
int kprobe__security_file_open(struct pt_regs *ctx, struct file *file) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_FILE_OPEN);
    struct dentry *dentry = file->f_path.dentry;
    bpf_probe_read_kernel_str(&e.path, sizeof(e.path), dentry->d_name.name);
    dv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int kprobe__security_inode_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_FILE_UNLINK);
    bpf_probe_read_kernel_str(&e.path, sizeof(e.path), dentry->d_name.name);
    dv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

PTRACE_SIG = r"""
int kprobe__sys_ptrace(struct pt_regs *ctx, long request, long pid, unsigned long addr, unsigned long data) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_PTRACE);
    e.ptrace_request = request;
    e.ptrace_target = (u32)pid;
    dv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int kprobe__process_vm_readv(struct pt_regs *ctx, pid_t pid) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_PTRACE);
    e.ptrace_request = -1; /* sentinel for process_vm_readv */
    e.ptrace_target = (u32)pid;
    dv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

BPF_LOAD = r"""
int kprobe__bpf_prog_load(struct pt_regs *ctx) {
    struct dv_event_t e = {};
    dv_fill_common(&e, DV_KIND_BPF_LOAD);
    dv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""


# Ordered list of programs. ``id``s match DV_KIND_* in HEADER.
PROGRAMS: dict[str, str] = {
    "raw_syscall": RAW_SYSCALL,
    "exec_args": EXEC_ARGS,
    "module_load": MODULE_LOAD,
    "creds": CREDS,
    "net_flow": NET_FLOW,
    "file_access": FILE_ACCESS,
    "ptrace_signals": PTRACE_SIG,
    "bpf_load": BPF_LOAD,
}

# DV_KIND_* constants from HEADER replicated in Python for dispatch.
KIND_SYSCALL = 1
KIND_EXEC = 2
KIND_MODULE_LOAD = 3
KIND_CREDS = 4
KIND_TCP_CONNECT = 5
KIND_UDP_SENDMSG = 6
KIND_INET_LISTEN = 7
KIND_FILE_OPEN = 8
KIND_FILE_UNLINK = 9
KIND_PTRACE = 10
KIND_BPF_LOAD = 11


def compose_source(enabled: set[str]) -> str:
    """Compose the final BPF source for the requested program bundle."""
    parts = [HEADER]
    for name, program in PROGRAMS.items():
        if name in enabled:
            parts.append(program)
    return "\n".join(parts)


def all_program_names() -> set[str]:
    return set(PROGRAMS.keys())
