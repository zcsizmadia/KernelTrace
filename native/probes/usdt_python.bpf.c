// SPDX-License-Identifier: GPL-2.0
// KernelTrace — usdt_python.bpf.c
// Attaches to Python 3 USDT probes to trace function calls.
//
// Requires: Python 3.6+ compiled with --enable-dtrace / --with-dtrace,
//           or a distribution package that includes USDT probes
//           (e.g. python3-dbg on Debian/Ubuntu).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

char LICENSE[] SEC("license") = "GPL";

struct python_call_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  tgid;
    char   filename[64];
    char   funcname[64];
    __s32  lineno;
    __u32  _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);   // 4 MiB
} events SEC(".maps");

// Attach to python:function__entry USDT probe.
// Probe arguments (SDT note):
//   arg1 = (const char*) filename
//   arg2 = (const char*) funcname
//   arg3 = (int)         lineno
SEC("usdt/python:function__entry")
int handle_python_function_entry(struct pt_regs *ctx)
{
    struct python_call_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    e->tgid         = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->lineno       = (s32)ctx->dx; // arg3

    // Read filename and funcname from user-space pointers.
    const char *filename = (const char *)(uintptr_t)ctx->di; // arg1
    const char *funcname = (const char *)(uintptr_t)ctx->si; // arg2

    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
    bpf_probe_read_user_str(e->funcname, sizeof(e->funcname), funcname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
