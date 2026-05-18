/*
 * dotnet_runtime.bpf.c — .NET CLR uprobes for GC, JIT, and exception events
 *
 * Each BPF program section targets a specific CLR internal symbol offset
 * supplied by the user-space code (via KernelTrace DotNetRuntimeOptions).
 * Because .NET is a managed runtime, function offsets are resolved with
 * `objdump` or the included SymbolResolver helper class.
 *
 * NOTE: Offsets are binary-specific.  Rebuild when the CLR is updated.
 *
 * Sections (pass the section name as UprobeSpec.ProgramSection):
 *
 *   uprobe/dotnet_gc_start          — GarbageCollect() entry
 *   uprobe/dotnet_gc_end            — GarbageCollect() return (uretprobe)
 *   uprobe/dotnet_exception_thrown  — RealCOMPlusThrow() entry
 *   uprobe/dotnet_method_jitted     — MethodCompiled() entry  (JIT)
 *
 * Kernel: >= 5.8
 */

#include "common.h"

/* ── Event structs ────────────────────────────────────────────────────────── */

/**
 * Emitted at GC start and (with duration_ns set) at GC end.
 * The user-space pair-matcher correlates by tid.
 */
struct dotnet_gc_event {
    __u64 timestamp_ns;
    __u64 duration_ns;  /**< 0 at entry; filled at return. */
    __u32 pid;
    __u32 tgid;
    __u32 generation;   /**< 0/1/2 from PT_REGS_PARM1 (best-effort). */
    __u8  is_end;
    char  comm[16];
};

/** Emitted when an exception is thrown (RealCOMPlusThrow). */
struct dotnet_exception_event {
    __u64 timestamp_ns;
    __u64 exception_ptr;  /**< EE object pointer (raw, for grouping). */
    __u32 pid;
    __u32 tgid;
    char  comm[16];
};

/** Emitted when a managed method is JIT-compiled (MethodCompiled). */
struct dotnet_method_event {
    __u64 timestamp_ns;
    __u64 method_handle;  /**< MethodDesc * (raw). */
    __u32 pid;
    __u32 tgid;
    char  comm[16];
};

/* ── BPF maps ────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

/* tid → GC entry timestamp (for duration calculation) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} pending_gc SEC(".maps");

/* ── GC start ─────────────────────────────────────────────────────────────── */

/* BPF_UPROBE extracts arguments from arch-specific registers without
 * requiring a complete 'struct user_pt_regs', making it portable across
 * x86_64, arm64, and other supported BPF architectures. */
SEC("uprobe/dotnet_gc_start")
int BPF_UPROBE(handle_gc_start, __u64 generation)
{
    if (!kt_should_trace()) return 0;

    __u64 ts    = kt_ktime_ns();
    __u32 tid   = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_gc, &tid, &ts, BPF_ANY);

    struct dotnet_gc_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = ts;
    ev->duration_ns  = 0;
    ev->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid         = (__u32)(pid_tgid >> 32);
    ev->generation   = (__u32)generation;
    ev->is_end       = 0;
    KT_COMM_READ(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── GC end (uretprobe) ───────────────────────────────────────────────────── */

SEC("uretprobe/dotnet_gc_end")
int handle_gc_end(struct pt_regs *ctx)
{
    if (!kt_should_trace()) return 0;

    __u64 exit_ts  = kt_ktime_ns();
    __u32 tid      = (__u32)bpf_get_current_pid_tgid();
    __u64 *entry   = bpf_map_lookup_elem(&pending_gc, &tid);
    __u64 duration = 0;
    if (entry) {
        duration = exit_ts > *entry ? exit_ts - *entry : 0;
        bpf_map_delete_elem(&pending_gc, &tid);
    }

    struct dotnet_gc_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = exit_ts;
    ev->duration_ns  = duration;
    ev->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid         = (__u32)(pid_tgid >> 32);
    ev->generation   = 0;
    ev->is_end       = 1;
    KT_COMM_READ(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── Exception thrown ────────────────────────────────────────────────────── */

/*
 * RealCOMPlusThrow(Object* throwable, ...)
 *   First argument = throwable EE object pointer
 */
SEC("uprobe/dotnet_exception_thrown")
int BPF_UPROBE(handle_exception_thrown, __u64 throwable)
{
    if (!kt_should_trace()) return 0;

    struct dotnet_exception_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns   = kt_ktime_ns();
    ev->exception_ptr  = throwable;
    ev->pid            = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid           = (__u32)(pid_tgid >> 32);
    KT_COMM_READ(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── JIT method compiled ─────────────────────────────────────────────────── */

/*
 * MethodCompiled(MethodDesc* pMD, ...)
 *   First argument = MethodDesc pointer
 */
SEC("uprobe/dotnet_method_jitted")
int BPF_UPROBE(handle_method_jitted, __u64 method_desc)
{
    if (!kt_should_trace()) return 0;

    struct dotnet_method_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 pid_tgid  = bpf_get_current_pid_tgid();
    ev->timestamp_ns  = kt_ktime_ns();
    ev->method_handle = method_desc;
    ev->pid           = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid          = (__u32)(pid_tgid >> 32);
    KT_COMM_READ(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
