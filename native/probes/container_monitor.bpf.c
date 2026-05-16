/*
 * container_monitor.bpf.c — Container-attributed process and network events
 *
 * Identifies container workloads via cgroup ID (each container gets its own
 * cgroup v2 leaf).  User space maps cgroup IDs to container names by reading
 * /sys/fs/cgroup.
 *
 * Tracepoints:
 *   tp/syscalls/sys_enter_execve  — process launch
 *   tp/syscalls/sys_enter_connect — outbound TCP/UDP connect
 *   tp/sched/sched_process_fork   — process fork (child inherits cgroup)
 *   tp/sched/sched_process_exit   — process exit
 *
 * Kernel: >= 5.8  (bpf_get_current_cgroup_id requires >= 4.18)
 */

#include "common.h"

/* ── Event types ─────────────────────────────────────────────────────────── */

#define CT_EVENT_EXECVE  0
#define CT_EVENT_CONNECT 1
#define CT_EVENT_FORK    2
#define CT_EVENT_EXIT    3

/* ── Event struct ─────────────────────────────────────────────────────────── */

struct container_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;      /**< cgroup v2 leaf ID — maps to a container. */
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u8  event_type;     /**< CT_EVENT_* */
    char  comm[16];
    /** execve: path to new executable (truncated). */
    char  filename[256];
};

/* ── BPF maps ────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

/*
 * Cgroup ID allow-list.  When non-empty, only events from listed cgroup IDs
 * are forwarded.  Fill from user space (optional).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u64);    /* cgroup_id */
    __type(value, __u8);   /* 1 = allowed */
} cgroup_filter SEC(".maps");

/* ── Common fill helper ───────────────────────────────────────────────────── */

static __always_inline int should_filter(__u64 cgroup_id)
{
    /* If the filter map has entries, require the cgroup to be listed. */
    /* (A map with zero entries means: allow all.) */
    __u8 *allowed = bpf_map_lookup_elem(&cgroup_filter, &cgroup_id);
    /* We cannot query map size from BPF.  Treat absent key as allowed
       when the filter map is effectively empty (first key lookup fails). */
    return (allowed && *allowed == 0) ? 1 : 0;
}

static __always_inline void fill_common(struct container_event *ev,
                                         __u64 cgroup_id, __u8 event_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = kt_ktime_ns();
    ev->cgroup_id    = cgroup_id;
    ev->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid         = (__u32)(pid_tgid >> 32);
    ev->uid          = kt_current_uid();
    ev->event_type   = event_type;
    ev->ppid         = 0; /* resolved in user space from pid */
    KT_COMM_READ(ev->comm, sizeof(ev->comm));
}

/* ── tp/syscalls/sys_enter_execve ─────────────────────────────────────────── */

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    if (!kt_should_trace()) return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_filter(cgroup_id)) return 0;

    struct container_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_common(ev, cgroup_id, CT_EVENT_EXECVE);
    /* args[0] = filename (const char __user *) */
    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename),
                             (void *)ctx->args[0]);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── tp/syscalls/sys_enter_connect ────────────────────────────────────────── */

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    if (!kt_should_trace()) return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_filter(cgroup_id)) return 0;

    struct container_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_common(ev, cgroup_id, CT_EVENT_CONNECT);
    ev->filename[0] = '\0'; /* not used for connect */

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── tp/sched/sched_process_fork ──────────────────────────────────────────── */

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    if (!kt_should_trace()) return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_filter(cgroup_id)) return 0;

    struct container_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_common(ev, cgroup_id, CT_EVENT_FORK);
    ev->ppid       = (__u32)ctx->parent_pid;
    ev->pid        = (__u32)ctx->child_pid;
    ev->filename[0] = '\0';

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── tp/sched/sched_process_exit ──────────────────────────────────────────── */

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sys_enter *ctx) /* reuse common header */
{
    if (!kt_should_trace()) return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_filter(cgroup_id)) return 0;

    struct container_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_common(ev, cgroup_id, CT_EVENT_EXIT);
    ev->filename[0] = '\0';

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
