/*
 * block_io.bpf.c — Block I/O latency tracing
 *
 * Correlates block_rq_issue with block_rq_complete using a per-request hash
 * map keyed by (dev, sector).  Emits one event per completed request with the
 * full issue-to-completion latency.
 *
 * Tracepoints:
 *   tp/block/block_rq_issue    — request enters the device queue
 *   tp/block/block_rq_complete — request returns from the device
 *
 * Kernel: >= 5.8
 */

#include "common.h"

/* ── Event struct ─────────────────────────────────────────────────────────── */

/** Single block I/O event.  Emitted on completion. */
struct block_rq_event {
    __u64 timestamp_ns;   /**< Completion timestamp (ns). */
    __u64 latency_ns;     /**< Complete − issue duration (ns). */
    __u64 sector;         /**< Sector number. */
    __u32 dev;            /**< Device MKDEV(major, minor). */
    __u32 nr_sector;      /**< Transfer length in sectors. */
    __u32 bytes;          /**< Transfer length in bytes (where available). */
    __u32 pid;            /**< PID that issued the request. */
    char  rwbs[8];        /**< R/W/S/F/D flags string. */
    char  comm[16];       /**< Process name of the issuer. */
    __u8  is_write;       /**< 1 = write (rwbs[0] == 'W'). */
};

/* ── BPF maps ────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

/* Scratch: (dev<<32 | sector) → issue_info */
struct issue_info {
    __u64 issue_ts;
    __u32 pid;
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);          /* (dev << 32) | (sector & 0xFFFFFFFF) */
    __type(value, struct issue_info);
} pending_rq SEC(".maps");

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static __always_inline __u64 rq_key(__u32 dev, __u64 sector)
{
    return ((__u64)dev << 32) | (sector & 0xFFFFFFFFULL);
}

/* ── block/block_rq_issue ────────────────────────────────────────────────── */

SEC("tp/block/block_rq_issue")
int handle_rq_issue(struct trace_event_raw_block_rq *ctx)
{
    if (!kt_should_trace()) return 0;

    __u64 key = rq_key(ctx->dev, ctx->sector);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct issue_info info = {
        .issue_ts = kt_ktime_ns(),
        .pid      = (__u32)(pid_tgid & 0xFFFFFFFF),
    };
    KT_COMM_READ(info.comm, sizeof(info.comm));

    bpf_map_update_elem(&pending_rq, &key, &info, BPF_ANY);
    return 0;
}

/* ── block/block_rq_complete ─────────────────────────────────────────────── */

SEC("tp/block/block_rq_complete")
int handle_rq_complete(struct trace_event_raw_block_rq *ctx)
{
    if (!kt_should_trace()) return 0;

    __u64 key = rq_key(ctx->dev, ctx->sector);

    struct issue_info *info = bpf_map_lookup_elem(&pending_rq, &key);
    if (!info) return 0;

    __u64 complete_ts = kt_ktime_ns();
    __u64 issue_ts    = info->issue_ts;
    __u32 pid         = info->pid;
    char  comm[16];
    __builtin_memcpy(comm, info->comm, 16);
    bpf_map_delete_elem(&pending_rq, &key);

    struct block_rq_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = complete_ts;
    ev->latency_ns   = complete_ts > issue_ts ? complete_ts - issue_ts : 0;
    ev->sector       = ctx->sector;
    ev->dev          = ctx->dev;
    ev->nr_sector    = ctx->nr_sector;
    ev->bytes        = ctx->bytes;
    ev->pid          = pid;
    ev->is_write     = (ctx->rwbs[0] == 'W' || ctx->rwbs[0] == 'D') ? 1 : 0;
    __builtin_memcpy(ev->rwbs, ctx->rwbs, sizeof(ev->rwbs));
    __builtin_memcpy(ev->comm, comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
