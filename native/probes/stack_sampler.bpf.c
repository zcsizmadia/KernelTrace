/* stack_sampler.bpf.c — Stack-trace sampling probe for KernelTrace.
 *
 * Attaches to the openat(2) tracepoint; captures the kernel and user-space
 * call stack at the time of each open() call and emits an event that carries
 * both stack IDs.  The .NET consumer reads the actual addresses from the
 * "stacks" BPF_MAP_TYPE_STACK_TRACE map via BpfMap<int, StackFrame>.
 *
 * Build: cmake --build native/build
 */

#include "common.h"

#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 127

/* ── Event structure (mirrors StackSampleEvent in C#) ───────────────────── */

struct stack_sample_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __s32 kernel_stack_id; /* -1 if unavailable */
    __s32 user_stack_id;   /* -1 if unavailable */
    char  comm[TASK_COMM_LEN];
};

/* ── Maps ────────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MiB */
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stacks SEC(".maps");

/* ── Probe handler ───────────────────────────────────────────────────────── */

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    if (!kt_should_trace())
        return 0;

    struct stack_sample_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns    = kt_ktime_ns();
    ev->pid             = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid            = (__u32)(pid_tgid >> 32);
    ev->kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    ev->user_stack_id   = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
