/* tcpconnect - trace TCP connect calls */
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    u32 saddr;
    u32 daddr;
    u16 dport;
};

BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(events);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    currsock.update(&pid, &sk);
    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skpp = currsock.lookup(&pid);
    if (skpp == 0) return 0;

    if (ret != 0) {
        currsock.delete(&pid);
        return 0;
    }

    struct sock *skp = *skpp;
    struct event_t event = {};
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.saddr = skp->__sk_common.skc_rcv_saddr;
    event.daddr = skp->__sk_common.skc_daddr;
    event.dport = skp->__sk_common.skc_dport;

    events.perf_submit(ctx, &event, sizeof(event));
    currsock.delete(&pid);
    return 0;
}
