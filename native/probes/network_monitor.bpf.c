/*
 * network_monitor.bpf.c
 *
 * Captures outbound TCP/UDP connect() syscalls.  Emits a sock_connect_event
 * per connection attempt into the "events" ring buffer.
 *
 * Attaches to: tracepoint/syscalls/sys_enter_connect
 * Kernel:      >= 5.8 (BPF_MAP_TYPE_RINGBUF)
 */

#include "common.h"

/* ── Event struct — must match C# SocketConnectEvent (Pack=1) ────────────── */

struct sock_connect_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 src_ip;     /* network byte order */
    __u32 dst_ip;     /* network byte order */
    __u16 src_port;   /* host byte order */
    __u16 dst_port;   /* host byte order */
    char  comm[16];
    __u8  family;     /* AF_INET=2, AF_INET6=10 */
    __u8  _pad[3];
};

/* ── BPF maps ────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MiB */
} events SEC(".maps");

/*
 * Per-socket scratch map: store the user-supplied sockaddr pointer between
 * sys_enter_connect and sys_exit_connect so we can read it after the call.
 * Key = tid, Value = pointer to user sockaddr.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);   /* userspace sockaddr * */
} pending_connects SEC(".maps");

/* ── Tracepoint handler ───────────────────────────────────────────────────── */

SEC("tp/syscalls/sys_enter_connect")
int handle_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!kt_should_trace()) return 0;

    /* Only interested in internet sockets (fd >= 0, family == AF_INET). */
    __u32 tid  = (__u32)bpf_get_current_pid_tgid();
    __u64 addr = (__u64)ctx->args[1]; /* sockaddr __user * */
    __u16 family = 0;

    bpf_probe_read_user(&family, sizeof(family), (void *)addr);
    if (family != 2 /* AF_INET */) return 0;

    /* Save the sockaddr pointer for sys_exit. */
    bpf_map_update_elem(&pending_connects, &tid, &addr, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int handle_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!kt_should_trace()) return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    __u64 *addrp = bpf_map_lookup_elem(&pending_connects, &tid);
    if (!addrp) return 0;
    __u64 addr = *addrp;
    bpf_map_delete_elem(&pending_connects, &tid);

    /* Skip failed connects (EINPROGRESS is ok — it means non-blocking). */
    long ret = ctx->ret;
    if (ret < 0 && ret != -115 /* EINPROGRESS */) return 0;

    /* Read sockaddr_in from user space. */
    struct {
        __u16 family;
        __be16 port;
        __be32 sin_addr;
    } sin = {};
    if (bpf_probe_read_user(&sin, sizeof(sin), (void *)addr) != 0) return 0;

    /* Reserve a ring-buffer slot. */
    struct sock_connect_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = kt_ktime_ns();
    ev->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid         = (__u32)(pid_tgid >> 32);
    ev->uid          = kt_current_uid();
    ev->dst_ip       = bpf_ntohl(sin.sin_addr);
    ev->dst_port     = bpf_ntohs(sin.port);
    ev->src_ip       = 0; /* filled by user-space if needed */
    ev->src_port     = 0;
    ev->family       = sin.family;
    KT_COMM_READ(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
