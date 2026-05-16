/*
 * fs_io.bpf.c — File system I/O tracing
 *
 * Captures open, read, and write syscalls with per-call latency.
 * Uses a per-TID scratch hash map to bridge entry→exit timestamps.
 *
 * Tracepoints:
 *   tp/syscalls/sys_enter_openat  + sys_exit_openat
 *   tp/syscalls/sys_enter_read    + sys_exit_read
 *   tp/syscalls/sys_enter_write   + sys_exit_write
 *   tp/syscalls/sys_enter_pread64 + sys_exit_pread64
 *   tp/syscalls/sys_enter_pwrite64+ sys_exit_pwrite64
 *
 * Kernel: >= 5.8
 */

#include "common.h"

/* ── Event structs ────────────────────────────────────────────────────────── */

/** Emitted on every open/openat syscall completion. */
struct fs_open_event {
    __u64 timestamp_ns;   /**< Exit timestamp (ns). */
    __u64 latency_ns;     /**< Exit - entry duration (ns). */
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 flags;          /**< O_RDONLY/O_WRONLY/O_RDWR/O_CREAT/... */
    __s32 ret_fd;         /**< Returned fd, or negative errno on error. */
    char  comm[16];
    char  filename[256];
};

/** Emitted on every read/write/pread/pwrite syscall completion. */
struct fs_rw_event {
    __u64 timestamp_ns;
    __u64 latency_ns;
    __u32 pid;
    __u32 tgid;
    __s32 fd;
    __s64 bytes;          /**< Positive = bytes transferred; negative = errno. */
    __u8  is_write;       /**< 0 = read, 1 = write. */
    char  comm[16];
};

/* ── BPF maps ────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MiB */
} events SEC(".maps");

/* Scratch: tid → {entry_ts, filename_ptr, flags, fd} */
struct open_scratch {
    __u64 entry_ts;
    __u64 filename_ptr;  /* userspace const char * */
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);             /* tid */
    __type(value, struct open_scratch);
} pending_opens SEC(".maps");

struct rw_scratch {
    __u64 entry_ts;
    __s32 fd;
    __u8  is_write;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct rw_scratch);
} pending_rw SEC(".maps");

/* ── open / openat ───────────────────────────────────────────────────────── */

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!kt_should_trace()) return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct open_scratch s = {
        .entry_ts    = kt_ktime_ns(),
        .filename_ptr = (__u64)ctx->args[1],
        .flags       = (__u32)ctx->args[2],
    };
    bpf_map_update_elem(&pending_opens, &tid, &s, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!kt_should_trace()) return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct open_scratch *s = bpf_map_lookup_elem(&pending_opens, &tid);
    if (!s) return 0;

    __u64 exit_ts  = kt_ktime_ns();
    __u64 entry_ts = s->entry_ts;
    __u64 fn_ptr   = s->filename_ptr;
    __u32 flags    = s->flags;
    bpf_map_delete_elem(&pending_opens, &tid);

    struct fs_open_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = exit_ts;
    ev->latency_ns   = exit_ts > entry_ts ? exit_ts - entry_ts : 0;
    ev->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid         = (__u32)(pid_tgid >> 32);
    ev->uid          = kt_current_uid();
    ev->flags        = flags;
    ev->ret_fd       = (__s32)ctx->ret;
    KT_COMM_READ(ev->comm, sizeof(ev->comm));
    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)fn_ptr);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── read / pread64 ──────────────────────────────────────────────────────── */

static __always_inline int rw_enter(struct trace_event_raw_sys_enter *ctx, __u8 is_write)
{
    if (!kt_should_trace()) return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct rw_scratch s = {
        .entry_ts = kt_ktime_ns(),
        .fd       = (__s32)ctx->args[0],
        .is_write = is_write,
    };
    bpf_map_update_elem(&pending_rw, &tid, &s, BPF_ANY);
    return 0;
}

static __always_inline int rw_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct rw_scratch *s = bpf_map_lookup_elem(&pending_rw, &tid);
    if (!s) return 0;

    __u64 exit_ts  = kt_ktime_ns();
    __u64 entry_ts = s->entry_ts;
    __s32 fd       = s->fd;
    __u8  is_write = s->is_write;
    bpf_map_delete_elem(&pending_rw, &tid);

    struct fs_rw_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = exit_ts;
    ev->latency_ns   = exit_ts > entry_ts ? exit_ts - entry_ts : 0;
    ev->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid         = (__u32)(pid_tgid >> 32);
    ev->fd           = fd;
    ev->bytes        = ctx->ret;
    ev->is_write     = is_write;
    KT_COMM_READ(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx) { return rw_enter(ctx, 0); }

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx) { return rw_exit(ctx); }

SEC("tp/syscalls/sys_enter_write")
int handle_write_enter(struct trace_event_raw_sys_enter *ctx) { return rw_enter(ctx, 1); }

SEC("tp/syscalls/sys_exit_write")
int handle_write_exit(struct trace_event_raw_sys_exit *ctx) { return rw_exit(ctx); }

SEC("tp/syscalls/sys_enter_pread64")
int handle_pread_enter(struct trace_event_raw_sys_enter *ctx) { return rw_enter(ctx, 0); }

SEC("tp/syscalls/sys_exit_pread64")
int handle_pread_exit(struct trace_event_raw_sys_exit *ctx) { return rw_exit(ctx); }

SEC("tp/syscalls/sys_enter_pwrite64")
int handle_pwrite_enter(struct trace_event_raw_sys_enter *ctx) { return rw_enter(ctx, 1); }

SEC("tp/syscalls/sys_exit_pwrite64")
int handle_pwrite_exit(struct trace_event_raw_sys_exit *ctx) { return rw_exit(ctx); }
