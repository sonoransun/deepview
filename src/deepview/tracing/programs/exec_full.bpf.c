// Full exec tracepoint: captures argv[0] and the resolved filename.
// Used by ``deepview trace process`` once Slice 3 replaces Slice 1's
// raw_syscalls plumbing with per-probe templates.
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 timestamp_ns;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->tgid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename),
                            (void *)args->filename);

    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
