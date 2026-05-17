/*
 * kernel_internals.bpf.c — IRQ latency, lock contention, and CPU state tracing
 *
 * Covers low-level kernel internals that affect latency and CPU scheduling:
 *   - Hardware IRQ handler entry/exit (latency per IRQ line)
 *   - Software IRQ (softirq) entry/exit
 *   - Kernel lock contention begin/end (kernel >= 5.14)
 *   - CPU frequency changes (P-state)
 *   - CPU idle state changes (C-state)
 *
 * Tracepoints:
 *   tp/irq/irq_handler_entry  + irq_handler_exit
 *   tp/irq/softirq_entry      + softirq_exit
 *   tp/lock/contention_begin  + contention_end
 *   tp/power/cpu_frequency
 *   tp/power/cpu_idle
 *
 * Kernel: >= 5.14 for lock tracepoints; others >= 5.8.
 */

#include "common.h"

/*
 * trace_event_raw_cpu_frequency / trace_event_raw_cpu_idle
 *
 * These tracepoint context structs are generated dynamically by the kernel and
 * are NOT present in the BTF/vmlinux.h dump.  We define them manually here,
 * matching the layout reported by:
 *   /sys/kernel/tracing/events/power/cpu_frequency/format
 *   /sys/kernel/tracing/events/power/cpu_idle/format
 *
 * Layout (both structs are identical):
 *   offset 0:  u16 common_type
 *   offset 2:  u8  common_flags
 *   offset 3:  u8  common_preempt_count
 *   offset 4:  s32 common_pid
 *   offset 8:  u32 state
 *   offset 12: u32 cpu_id
 */
struct trace_event_raw_cpu_frequency {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    __u32 state;   /* CPU frequency in kHz */
    __u32 cpu_id;
};

struct trace_event_raw_cpu_idle {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    __u32 state;   /* idle level; 0xFFFFFFFF = leaving idle */
    __u32 cpu_id;
};

/* ── Event types ─────────────────────────────────────────────────────────── */

#define KI_IRQ_ENTRY     0
#define KI_IRQ_EXIT      1
#define KI_SOFTIRQ_ENTRY 2
#define KI_SOFTIRQ_EXIT  3

/* ── Event structs ────────────────────────────────────────────────────────── */

/** Emitted for hardware and software IRQ events. */
struct irq_event {
    __u64 timestamp_ns;
    __u64 latency_ns;   /**< 0 on entry; handler duration on exit. */
    __u32 irq;          /**< IRQ number (hardware) or softirq vector. */
    __u32 pid;
    __u8  event_type;   /**< KI_IRQ_* */
    __u8  softirq;      /**< 1 = softirq, 0 = hardware IRQ. */
};

/** Emitted on lock contention begin/end. */
struct lock_event {
    __u64 timestamp_ns;
    __u64 latency_ns;    /**< 0 at begin; wait duration at end. */
    __u64 lock_addr;
    __u32 pid;
    __u32 flags;
    __u8  is_end;
};

/** Emitted on CPU frequency and idle state transitions. */
struct power_event {
    __u64 timestamp_ns;
    __u32 cpu_id;
    __u32 state;          /**< kHz for cpu_frequency; idle level for cpu_idle. */
    __u8  is_idle;        /**< 1 = idle event, 0 = frequency event. */
};

/* ── BPF maps ────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

/* irq_nr (per-CPU) → entry timestamp */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   /* irq number */
    __type(value, __u64); /* entry ts */
} pending_irq SEC(".maps");

/* softirq vec (per-CPU) → entry timestamp */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} pending_softirq SEC(".maps");

/* lock_addr → contention begin timestamp + pid */
struct lock_scratch {
    __u64 begin_ts;
    __u32 pid;
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct lock_scratch);
} pending_lock SEC(".maps");

/* ── Hardware IRQ ─────────────────────────────────────────────────────────── */

SEC("tp/irq/irq_handler_entry")
int handle_irq_entry(struct trace_event_raw_irq_handler_entry *ctx)
{
    if (!kt_should_trace()) return 0;

    __u32 irq = (__u32)ctx->irq;
    __u64 ts  = kt_ktime_ns();
    bpf_map_update_elem(&pending_irq, &irq, &ts, BPF_ANY);

    struct irq_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = ts;
    ev->latency_ns   = 0;
    ev->irq          = irq;
    ev->pid          = kt_current_pid();
    ev->event_type   = KI_IRQ_ENTRY;
    ev->softirq      = 0;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tp/irq/irq_handler_exit")
int handle_irq_exit(struct trace_event_raw_irq_handler_exit *ctx)
{
    if (!kt_should_trace()) return 0;

    __u64 exit_ts  = kt_ktime_ns();
    __u32 irq      = (__u32)ctx->irq;
    __u64 *entry   = bpf_map_lookup_elem(&pending_irq, &irq);
    __u64 duration = 0;
    if (entry) {
        duration = exit_ts > *entry ? exit_ts - *entry : 0;
        bpf_map_delete_elem(&pending_irq, &irq);
    }

    struct irq_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = exit_ts;
    ev->latency_ns   = duration;
    ev->irq          = irq;
    ev->pid          = kt_current_pid();
    ev->event_type   = KI_IRQ_EXIT;
    ev->softirq      = 0;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── Software IRQ ─────────────────────────────────────────────────────────── */

SEC("tp/irq/softirq_entry")
int handle_softirq_entry(struct trace_event_raw_softirq *ctx)
{
    if (!kt_should_trace()) return 0;

    __u32 vec = ctx->vec;
    __u64 ts  = kt_ktime_ns();
    bpf_map_update_elem(&pending_softirq, &vec, &ts, BPF_ANY);

    struct irq_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = ts;
    ev->latency_ns   = 0;
    ev->irq          = vec;
    ev->pid          = kt_current_pid();
    ev->event_type   = KI_SOFTIRQ_ENTRY;
    ev->softirq      = 1;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tp/irq/softirq_exit")
int handle_softirq_exit(struct trace_event_raw_softirq *ctx)
{
    if (!kt_should_trace()) return 0;

    __u64 exit_ts  = kt_ktime_ns();
    __u32 vec      = ctx->vec;
    __u64 *entry   = bpf_map_lookup_elem(&pending_softirq, &vec);
    __u64 duration = 0;
    if (entry) {
        duration = exit_ts > *entry ? exit_ts - *entry : 0;
        bpf_map_delete_elem(&pending_softirq, &vec);
    }

    struct irq_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = exit_ts;
    ev->latency_ns   = duration;
    ev->irq          = vec;
    ev->pid          = kt_current_pid();
    ev->event_type   = KI_SOFTIRQ_EXIT;
    ev->softirq      = 1;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── Lock contention ──────────────────────────────────────────────────────── */

SEC("tp/lock/contention_begin")
int handle_lock_begin(struct trace_event_raw_contention_begin *ctx)
{
    if (!kt_should_trace()) return 0;

    __u64 lock_addr = (__u64)ctx->lock_addr;
    struct lock_scratch s = {
        .begin_ts = kt_ktime_ns(),
        .pid      = kt_current_pid(),
        .flags    = ctx->flags,
    };
    bpf_map_update_elem(&pending_lock, &lock_addr, &s, BPF_ANY);

    struct lock_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = s.begin_ts;
    ev->latency_ns   = 0;
    ev->lock_addr    = lock_addr;
    ev->pid          = s.pid;
    ev->flags        = ctx->flags;
    ev->is_end       = 0;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tp/lock/contention_end")
int handle_lock_end(struct trace_event_raw_contention_end *ctx)
{
    if (!kt_should_trace()) return 0;

    __u64 exit_ts   = kt_ktime_ns();
    __u64 lock_addr = (__u64)ctx->lock_addr;
    struct lock_scratch *s = bpf_map_lookup_elem(&pending_lock, &lock_addr);
    __u64 duration  = 0;
    __u32 pid       = kt_current_pid();
    __u32 flags     = 0;
    if (s) {
        duration = exit_ts > s->begin_ts ? exit_ts - s->begin_ts : 0;
        pid      = s->pid;
        flags    = s->flags;
        bpf_map_delete_elem(&pending_lock, &lock_addr);
    }

    struct lock_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = exit_ts;
    ev->latency_ns   = duration;
    ev->lock_addr    = lock_addr;
    ev->pid          = pid;
    ev->flags        = flags;
    ev->is_end       = 1;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── CPU frequency ────────────────────────────────────────────────────────── */

SEC("tp/power/cpu_frequency")
int handle_cpu_frequency(struct trace_event_raw_cpu_frequency *ctx)
{
    if (!kt_should_trace()) return 0;

    struct power_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = kt_ktime_ns();
    ev->cpu_id       = ctx->cpu_id;
    ev->state        = ctx->state; /* kHz */
    ev->is_idle      = 0;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── CPU idle ─────────────────────────────────────────────────────────────── */

SEC("tp/power/cpu_idle")
int handle_cpu_idle(struct trace_event_raw_cpu_idle *ctx)
{
    if (!kt_should_trace()) return 0;

    struct power_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = kt_ktime_ns();
    ev->cpu_id       = ctx->cpu_id;
    ev->state        = ctx->state; /* 0xFFFFFFFF = leaving idle */
    ev->is_idle      = 1;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}
