// module:module_load / module:module_free tracepoints. Kernel module
// hot-loading is a high-signal forensic event; this is a direct feed.
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct module_event_t {
    u32 pid;
    u32 uid;
    u64 timestamp_ns;
    char comm[16];
    char name[64];
    u32 kind;   // 0 = load, 1 = free
};

BPF_PERF_OUTPUT(module_events);

TRACEPOINT_PROBE(module, module_load) {
    struct module_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.kind = 0;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel_str(&event.name, sizeof(event.name),
                              (void *)args->name);
    module_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(module, module_free) {
    struct module_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.kind = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel_str(&event.name, sizeof(event.name),
                              (void *)args->name);
    module_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
