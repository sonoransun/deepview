/* filesnoop - trace file read/write operations */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    int fd;
    u64 count;
    char op;  // 'R' for read, 'W' for write
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.fd = args->fd;
    event.count = args->count;
    event.op = 'R';
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.fd = args->fd;
    event.count = args->count;
    event.op = 'W';
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
