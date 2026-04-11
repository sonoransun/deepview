// signal_generate tracepoint: sender/receiver PID + signo. Used for
// anti-forensics detection (kill to init, cross-uid signals).
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct signal_event_t {
    u32 sender_pid;
    u32 target_pid;
    u32 sender_uid;
    int sig;
    u64 timestamp_ns;
    char sender_comm[16];
};

BPF_PERF_OUTPUT(signal_events);

TRACEPOINT_PROBE(signal, signal_generate) {
    struct signal_event_t event = {};
    event.sender_pid = bpf_get_current_pid_tgid() >> 32;
    event.target_pid = args->pid;
    event.sender_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.sig = args->sig;
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.sender_comm, sizeof(event.sender_comm));

    signal_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
