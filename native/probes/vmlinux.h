/* vmlinux.h — Minimal kernel type definitions for KernelTrace eBPF probes.
 *
 * This is a HAND-WRITTEN STUB covering only the types used by the probes in
 * this repository.  It is sufficient for compilation and BPF CO-RE relocation.
 *
 * For production use on a specific kernel, regenerate with:
 *
 *   native/scripts/gen-vmlinux.sh
 *
 * which runs:  bpftool btf dump file /sys/kernel/btf/vmlinux format c
 *
 * The full generated file is 100 000+ lines; this stub is ~350 lines.
 * CO-RE (BPF_CORE_READ) resolves field offsets from the *running* kernel's
 * BTF at load time, so struct layouts here only need to have the right field
 * names and types — not necessarily the right offsets.
 */

#pragma once

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* ── Compiler attributes used by BPF programs ────────────────────────────── */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif
#define __user
#define __kernel
#define __rcu
#define __percpu

/* ── BPF-specific annotations (no-ops outside the BPF toolchain) ─────────── */
#ifndef __bpf_section
#define __bpf_section(name) __attribute__((section(name), used))
#endif

/* ── Integer typedefs ────────────────────────────────────────────────────── */
typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed char        __s8;
typedef signed short       __s16;
typedef signed int         __s32;
typedef signed long long   __s64;

typedef __u8   u8;
typedef __u16  u16;
typedef __u32  u32;
typedef __u64  u64;
typedef __s8   s8;
typedef __s16  s16;
typedef __s32  s32;
typedef __s64  s64;

typedef __u16  __be16;
typedef __u32  __be32;
typedef __u64  __be64;
typedef __u16  __le16;
typedef __u32  __le32;
typedef __u64  __le64;

typedef unsigned long  ulong;
typedef unsigned int   uint;
typedef int            bool;
#define true  1
#define false 0

typedef unsigned long size_t;
typedef long          ssize_t;
typedef long          ptrdiff_t;

/* ── Kernel GFP flags (subset) ───────────────────────────────────────────── */
typedef unsigned int gfp_t;
#define GFP_KERNEL  0x6000u
#define GFP_ATOMIC  0x20u
#define GFP_NOWAIT  0x0u

/* ── Page flags ──────────────────────────────────────────────────────────── */
typedef unsigned long pgflags_t;

/* ── Minimal task_struct — CO-RE fields accessed by our probes ───────────── */
struct nsproxy;
struct mm_struct;
struct files_struct;
struct signal_struct;

struct task_struct {
    volatile long           __state;           /* TASK_RUNNING=0, TASK_INTERRUPTIBLE=1, ... */
    void                   *stack;
    int                     pid;               /* thread id */
    int                     tgid;              /* process id */
    char                    comm[16];          /* process name (not null-terminated if full) */
    int                     prio;              /* effective nice value */
    int                     static_prio;
    unsigned int            cpu;
    struct task_struct     *real_parent;
    struct task_struct     *parent;
    struct nsproxy         *nsproxy;
    struct mm_struct       *mm;
    struct files_struct    *files;
    struct signal_struct   *signal;
    __u32                   loginuid;          /* login UID */
    __u32                   sessionid;
};

/* ── Namespaces ──────────────────────────────────────────────────────────── */
struct net;
struct pid_namespace;
struct user_namespace;

struct nsproxy {
    struct net             *net_ns;
    struct pid_namespace   *pid_ns_for_children;
    struct user_namespace  *user_ns;
};

/* ── Tracepoint common header (all raw tracepoints share this) ───────────── */
struct trace_entry {
    __u16 type;
    __u8  flags;
    __u8  preempt_count;
    int   pid;
};

/* ── syscalls: sys_enter ─────────────────────────────────────────────────── */
struct trace_event_raw_sys_enter {
    struct trace_entry  ent;
    long                id;      /* syscall nr */
    unsigned long       args[6];
};

/* ── syscalls: sys_exit ──────────────────────────────────────────────────── */
struct trace_event_raw_sys_exit {
    struct trace_entry  ent;
    long                id;
    long                ret;
};

/* ── sched: sched_switch (used by tp_btf variant) ───────────────────────── */
struct trace_event_raw_sched_switch {
    struct trace_entry  ent;
    char                prev_comm[16];
    int                 prev_pid;
    int                 prev_prio;
    long                prev_state;
    char                next_comm[16];
    int                 next_pid;
    int                 next_prio;
};

/* ── sched: process_fork ─────────────────────────────────────────────────── */
struct trace_event_raw_sched_process_fork {
    struct trace_entry  ent;
    char                parent_comm[16];
    int                 parent_pid;
    char                child_comm[16];
    int                 child_pid;
};

/* ── kmem: kmalloc ───────────────────────────────────────────────────────── */
struct trace_event_raw_kmalloc {
    struct trace_entry  ent;
    unsigned long       call_site;
    const void         *ptr;
    size_t              bytes_req;
    size_t              bytes_alloc;
    unsigned long       gfp_flags;
    int                 node;
};

/* ── kmem: kfree ─────────────────────────────────────────────────────────── */
struct trace_event_raw_kfree {
    struct trace_entry  ent;
    unsigned long       call_site;
    const void         *ptr;
};

/* ── kmem: mm_page_alloc ─────────────────────────────────────────────────── */
struct trace_event_raw_mm_page_alloc {
    struct trace_entry  ent;
    unsigned long       pfn;
    unsigned int        order;
    unsigned long       gfp_flags;
    int                 migratetype;
};

/* ── kmem: mm_page_free ──────────────────────────────────────────────────── */
struct trace_event_raw_mm_page_free {
    struct trace_entry  ent;
    unsigned long       pfn;
    unsigned int        order;
};

/* ── block: block_rq_issue / block_rq_complete ───────────────────────────── */
struct trace_event_raw_block_rq {
    struct trace_entry  ent;
    unsigned int        dev;          /* MKDEV(major, minor) */
    unsigned long long  sector;
    unsigned int        nr_sector;
    unsigned int        bytes;
    char                rwbs[8];      /* R/W/S/F/D flags as string */
    char                comm[16];
    /* __data_loc fields follow but we access via BPF helpers */
};

/* ── irq: irq_handler_entry / irq_handler_exit ───────────────────────────── */
struct trace_event_raw_irq_handler_entry {
    struct trace_entry  ent;
    int                 irq;
    /* __data_loc_name follows */
};

struct trace_event_raw_irq_handler_exit {
    struct trace_entry  ent;
    int                 irq;
    int                 ret;
};

/* ── irq: softirq_entry / softirq_exit ──────────────────────────────────── */
struct trace_event_raw_softirq {
    struct trace_entry  ent;
    unsigned int        vec;   /* 0=HI, 1=TIMER, 2=NET_TX, 3=NET_RX, ... */
};

/* ── lock: contention_begin / contention_end (kernel >= 5.14) ───────────── */
struct trace_event_raw_contention_begin {
    struct trace_entry  ent;
    void               *lock_addr;
    unsigned int        flags;
};

struct trace_event_raw_contention_end {
    struct trace_entry  ent;
    void               *lock_addr;
    int                 ret;
};

/* ── power: cpu_frequency / cpu_idle ─────────────────────────────────────── */
struct trace_event_raw_cpu_frequency {
    struct trace_entry  ent;
    unsigned int        state;
    unsigned int        cpu_id;
};

struct trace_event_raw_cpu_idle {
    struct trace_entry  ent;
    unsigned int        state;
    unsigned int        cpu_id;
};

/* ── VFS structures (minimal, for fs_io probes) ──────────────────────────── */
struct inode;
struct dentry;
struct super_block;

struct file {
    struct inode   *f_inode;
    struct dentry  *f_path_dentry;  /* approximate — use CO-RE for exact field */
};

/* ── pt_regs — for uprobe argument access ────────────────────────────────── */
#if defined(__x86_64__)
struct pt_regs {
    unsigned long r15, r14, r13, r12;
    unsigned long rbp, rbx;
    unsigned long r11, r10, r9, r8;
    unsigned long rax, rcx, rdx, rsi, rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
};
#elif defined(__aarch64__)
struct pt_regs {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};
#endif

#endif /* __VMLINUX_H__ */
