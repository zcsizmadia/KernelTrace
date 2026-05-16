/*
 * security_guard.bpf.c
 *
 * Intercepts execve syscalls to provide process execution visibility for
 * security monitoring.  Emits an execve_event for every exec call, carrying
 * process identity (pid, uid, parent pid) and the filename being executed.
 *
 * Attaches to: tracepoint/syscalls/sys_enter_execve
 * Kernel:      >= 5.8
 */

#include "common.h"

/* ── Event struct — must match C# ExecveEvent (Pack=1) ───────────────────── */

struct execve_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __s32 return_code;   /* only valid on sys_exit_execve */
    char  comm[16];      /* parent's comm */
    char  filename[256]; /* executable being exec'd */
    __u8  _pad[4];
};

/* ── BPF maps ────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MiB */
} events SEC(".maps");

/*
 * Scratch map: tid → pointer to filename string (from sys_enter) so that
 * sys_exit can attach the return code and emit a complete event.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);   /* userspace const char * */
} pending_exec SEC(".maps");

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static __always_inline __u32 get_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

/* ── Tracepoint handlers ──────────────────────────────────────────────────── */

SEC("tp/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!kt_should_trace()) return 0;

    __u32 tid    = (__u32)bpf_get_current_pid_tgid();
    __u64 fnptr  = (__u64)ctx->args[0]; /* const char __user *filename */

    bpf_map_update_elem(&pending_exec, &tid, &fnptr, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_execve")
int handle_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!kt_should_trace()) return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    __u64 *fnptrp = bpf_map_lookup_elem(&pending_exec, &tid);
    if (!fnptrp) return 0;
    __u64 fnptr = *fnptrp;
    bpf_map_delete_elem(&pending_exec, &tid);

    struct execve_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = kt_ktime_ns();
    ev->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid         = (__u32)(pid_tgid >> 32);
    ev->ppid         = get_ppid();
    ev->uid          = kt_current_uid();
    ev->gid          = kt_current_gid();
    ev->return_code  = (__s32)ctx->ret;

    KT_COMM_READ(ev->comm, sizeof(ev->comm));
    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)fnptr);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
