/*
 * memory_profiler.bpf.c — Kernel heap and page allocator tracing
 *
 * Captures kernel slab (kmalloc/kfree) and page allocator events,
 * plus page-fault counters.
 *
 * Tracepoints:
 *   tp/kmem/kmalloc         — slab allocation
 *   tp/kmem/kfree           — slab free
 *   tp/kmem/mm_page_alloc   — buddy-allocator page allocation
 *   tp/kmem/mm_page_free    — buddy-allocator page free
 *   kprobe/handle_mm_fault  — user-space page faults
 *
 * Kernel: >= 5.8
 */

#include "common.h"

/* ── Event structs ────────────────────────────────────────────────────────── */

/** Emitted on kmalloc (and implicitly on kfree by setting bytes_req = 0). */
struct kmalloc_event {
    __u64 timestamp_ns;
    __u64 call_site;      /**< Caller instruction pointer. */
    __u64 ptr;            /**< Allocated / freed pointer. */
    __u64 bytes_req;      /**< 0 on kfree. */
    __u64 bytes_alloc;    /**< Actual allocation size; 0 on kfree. */
    __u32 gfp_flags;
    __u32 pid;
    char  comm[16];
    __u8  is_free;        /**< 1 = kfree, 0 = kmalloc. */
};

/** Emitted on page alloc/free. */
struct page_alloc_event {
    __u64 timestamp_ns;
    __u64 pfn;
    __u32 order;          /**< 2^order pages. */
    __u32 gfp_flags;
    __u32 pid;
    __u8  is_free;
};

/** Emitted on page fault (kprobe handle_mm_fault). */
struct page_fault_event {
    __u64 timestamp_ns;
    __u64 address;        /**< Faulting virtual address. */
    __u32 pid;
    __u32 tgid;
    __u32 flags;          /**< VM_FAULT_* flags. */
    char  comm[16];
};

/* ── BPF maps ────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

/* ── kmem/kmalloc ────────────────────────────────────────────────────────── */

SEC("tp/kmem/kmalloc")
int handle_kmalloc(struct trace_event_raw_kmalloc *ctx)
{
    if (!kt_should_trace()) return 0;

    struct kmalloc_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = kt_ktime_ns();
    ev->call_site    = ctx->call_site;
    ev->ptr          = (__u64)ctx->ptr;
    ev->bytes_req    = ctx->bytes_req;
    ev->bytes_alloc  = ctx->bytes_alloc;
    ev->gfp_flags    = (__u32)ctx->gfp_flags;
    ev->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->is_free      = 0;
    KT_COMM_READ(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── kmem/kfree ──────────────────────────────────────────────────────────── */

SEC("tp/kmem/kfree")
int handle_kfree(struct trace_event_raw_kfree *ctx)
{
    if (!kt_should_trace()) return 0;

    struct kmalloc_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = kt_ktime_ns();
    ev->call_site    = ctx->call_site;
    ev->ptr          = (__u64)ctx->ptr;
    ev->bytes_req    = 0;
    ev->bytes_alloc  = 0;
    ev->gfp_flags    = 0;
    ev->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->is_free      = 1;
    KT_COMM_READ(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── kmem/mm_page_alloc ──────────────────────────────────────────────────── */

SEC("tp/kmem/mm_page_alloc")
int handle_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
    if (!kt_should_trace()) return 0;

    struct page_alloc_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = kt_ktime_ns();
    ev->pfn          = ctx->pfn;
    ev->order        = ctx->order;
    ev->gfp_flags    = (__u32)ctx->gfp_flags;
    ev->pid          = kt_current_pid();
    ev->is_free      = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── kmem/mm_page_free ───────────────────────────────────────────────────── */

SEC("tp/kmem/mm_page_free")
int handle_page_free(struct trace_event_raw_mm_page_free *ctx)
{
    if (!kt_should_trace()) return 0;

    struct page_alloc_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = kt_ktime_ns();
    ev->pfn          = ctx->pfn;
    ev->order        = ctx->order;
    ev->gfp_flags    = 0;
    ev->pid          = kt_current_pid();
    ev->is_free      = 1;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── kprobe/handle_mm_fault ──────────────────────────────────────────────── */

/*
 * handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
 *                 unsigned int flags, ...)
 *
 * PT_REGS_PARM1 = vma, PT_REGS_PARM2 = address, PT_REGS_PARM3 = flags
 */
/* BPF_KPROBE extracts arguments from arch-specific registers without
 * requiring a complete 'struct user_pt_regs', making it portable across
 * x86_64, arm64, and other supported BPF architectures.
 *
 * handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
 *                 unsigned int flags, ...) */
SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_page_fault,
               void *vma, __u64 address, __u32 flags)
{
    if (!kt_should_trace()) return 0;

    struct page_fault_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = kt_ktime_ns();
    ev->address      = address;
    ev->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid         = (__u32)(pid_tgid >> 32);
    ev->flags        = flags;
    KT_COMM_READ(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
