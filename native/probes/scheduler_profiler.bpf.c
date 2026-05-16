/*
 * scheduler_profiler.bpf.c
 *
 * Traces context switches via the sched_switch tracepoint.  Emits one
 * sched_switch_event for every CPU preemption, providing both the outgoing
 * and incoming PID.  User-space aggregates these to build off-CPU profiles.
 *
 * Attaches to: tracepoint/sched/sched_switch
 * Kernel:      >= 5.8
 */

#include "common.h"

/* ── Event struct — must match C# SchedSwitchEvent (Pack=1) ─────────────── */

struct sched_switch_event {
    __u64 timestamp_ns;
    __u32 prev_pid;
    __u32 next_pid;
    __u32 cpu_id;
    __s32 prev_prio;   /* nice value of outgoing task */
    __s32 next_prio;   /* nice value of incoming task */
    __u8  prev_state;  /* task state of outgoing (TASK_RUNNING=0, etc.) */
    char  prev_comm[16];
    char  next_comm[16];
    __u8  _pad[3];
};

/* ── BPF maps ────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23); /* 8 MiB — sched events are very frequent */
} events SEC(".maps");

/* ── Tracepoint handler ───────────────────────────────────────────────────── */

/*
 * The sched_switch tracepoint format (from /sys/kernel/debug/tracing/events/sched/sched_switch/format):
 *   prev_comm[16], prev_pid, prev_prio, prev_state, next_comm[16], next_pid, next_prio
 * Accessed via BTF CO-RE.
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch,
             bool preempt,
             struct task_struct *prev,
             struct task_struct *next)
{
    if (!kt_should_trace()) return 0;

    struct sched_switch_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = kt_ktime_ns();
    ev->cpu_id       = bpf_get_smp_processor_id();
    ev->prev_pid     = BPF_CORE_READ(prev, pid);
    ev->next_pid     = BPF_CORE_READ(next, pid);
    ev->prev_prio    = BPF_CORE_READ(prev, prio);
    ev->next_prio    = BPF_CORE_READ(next, prio);
    ev->prev_state   = (__u8)(BPF_CORE_READ(prev, __state) & 0xFF);

    BPF_CORE_READ_STR_INTO(&ev->prev_comm, prev, comm);
    BPF_CORE_READ_STR_INTO(&ev->next_comm, next, comm);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
