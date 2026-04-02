/* opensnoop - trace file opens */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
    int flags;
    int retval;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    event.flags = args->flags;

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
