// kprobe on ptrace_attach -- a classic anti-forensics indicator.
// Any ptrace_attach of a non-child process is suspicious on a host.
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct ptrace_event_t {
    u32 attacker_pid;
    u32 target_pid;
    u32 attacker_uid;
    u64 timestamp_ns;
    char attacker_comm[16];
};

BPF_PERF_OUTPUT(ptrace_events);

int kprobe__ptrace_attach(struct pt_regs *ctx, struct task_struct *task) {
    struct ptrace_event_t event = {};
    event.attacker_pid = bpf_get_current_pid_tgid() >> 32;
    event.target_pid = task->tgid;
    event.attacker_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.attacker_comm, sizeof(event.attacker_comm));

    ptrace_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
