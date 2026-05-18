// SPDX-License-Identifier: GPL-2.0
// KernelTrace — usdt_python.bpf.c
// Attaches to Python 3 USDT probes to trace garbage-collection events.
//
// Works with any Python 3 binary that has USDT probes compiled in
// (gc__start / gc__done are present in all standard CPython 3.x builds).
// The function__entry / function__return probes require a debug build
// (python3-dbg on Debian/Ubuntu) and are NOT used here.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

char LICENSE[] SEC("license") = "GPL";

// Event layout — must match PythonGcEvent in Program.cs exactly.
struct python_gc_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  tgid;
    __s64  value;      // gc__start: generation (0/1/2); gc__done: collected count
    __u8   is_end;     // 0 = gc__start, 1 = gc__done
    __u8   _pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);   // 4 MiB
} events SEC(".maps");

// python:gc__start(int generation)
SEC("usdt/python:gc__start")
int BPF_USDT(handle_gc_start, long generation)
{
    struct python_gc_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid  = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    e->tgid         = (__u32)(pid_tgid >> 32);
    e->value        = generation;
    e->is_end       = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// python:gc__done(long collected)
SEC("usdt/python:gc__done")
int BPF_USDT(handle_gc_done, long collected)
{
    struct python_gc_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid  = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    e->tgid         = (__u32)(pid_tgid >> 32);
    e->value        = collected;
    e->is_end       = 1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
