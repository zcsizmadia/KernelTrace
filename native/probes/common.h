/* common.h — Shared definitions for all KernelTrace eBPF probe programs. */
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* ── Convenience macros ──────────────────────────────────────────────────── */

/** Read a field from a kernel struct via CO-RE (Compile Once – Run Everywhere). */
#define KT_READ(dst, src_ptr, field) \
    BPF_CORE_READ_INTO(&(dst), src_ptr, field)

/** Safe string copy into a fixed buffer. */
#define KT_COMM_READ(dst, len) \
    bpf_get_current_comm(dst, len)

/** Current PID (lower 32 bits of pid_tgid). */
static __always_inline __u32 kt_current_pid(void)
{
    return (__u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
}

/** Current TGID (upper 32 bits of pid_tgid), i.e., the process PID. */
static __always_inline __u32 kt_current_tgid(void)
{
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

/** Current UID (lower 32 bits of uid_gid). */
static __always_inline __u32 kt_current_uid(void)
{
    return (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
}

/** Current GID (upper 32 bits of uid_gid). */
static __always_inline __u32 kt_current_gid(void)
{
    return (__u32)(bpf_get_current_uid_gid() >> 32);
}

/** Return kernel monotonic timestamp in nanoseconds. */
static __always_inline __u64 kt_ktime_ns(void)
{
    return bpf_ktime_get_ns();
}

/* ── Per-process filter ──────────────────────────────────────────────────── */

/*
 * When the .NET host sets SessionOptions.CurrentProcessOnly = true it writes
 * its own TGID (process ID) into this map via kt_session_set_tgid_filter().
 * Every probe checks this value; a zero entry means "trace all processes".
 *
 * Array map with a single element is the lightest possible lookup — the
 * verifier can often constant-fold it away entirely.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} kt_tgid_filter SEC(".maps");

/**
 * Returns 1 if the current task belongs to the traced process (or if no
 * filter has been set), 0 if the event should be dropped.
 *
 * Call at the very beginning of every probe handler:
 *     if (!kt_should_trace()) return 0;
 */
static __always_inline int kt_should_trace(void)
{
    __u32 key = 0;
    __u32 *filter_tgid = bpf_map_lookup_elem(&kt_tgid_filter, &key);
    if (!filter_tgid || *filter_tgid == 0)
        return 1; /* no filter — trace all */
    return kt_current_tgid() == *filter_tgid;
}

/* ── Standard BPF license (required for most helpers) ───────────────────── */
char LICENSE[] SEC("license") = "Dual BSD/GPL";
