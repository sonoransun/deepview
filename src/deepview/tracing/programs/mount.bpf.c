// sys_enter_mount / sys_enter_umount2 syscalls. Container escapes and
// rootkit persistence often traverse mount boundaries; surfacing these
// as distinct events makes the timeline much easier to reason about.
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct mount_event_t {
    u32 pid;
    u32 uid;
    u64 timestamp_ns;
    char comm[16];
    char source[128];
    char target[128];
    char fstype[32];
    u32 kind;   // 0 = mount, 1 = umount2
};

BPF_PERF_OUTPUT(mount_events);

TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    struct mount_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.kind = 0;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.source, sizeof(event.source),
                            (void *)args->dev_name);
    bpf_probe_read_user_str(&event.target, sizeof(event.target),
                            (void *)args->dir_name);
    bpf_probe_read_user_str(&event.fstype, sizeof(event.fstype),
                            (void *)args->type);
    mount_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_umount2) {
    struct mount_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.kind = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.target, sizeof(event.target),
                            (void *)args->name);
    mount_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
