# Built-in Probes

KernelTrace ships pre-compiled eBPF probes for the most common observability
use-cases.  All probe objects are installed to
`/usr/share/kerneltrace/probes/*.bpf.o` by the native package.

Each probe section below lists:
- The `.bpf.o` filename to pass as `SessionOptions.ProbePath`.
- The `ProbeSpec` entries to include in `SessionOptions.Probes`.
- The event struct emitted, with field descriptions.

---

## Network Monitor (`network_monitor.bpf.o`)

Captures every outbound TCP/UDP connection attempt.

### Probe configuration

```csharp
new SessionOptions
{
    ProbePath = "network_monitor.bpf.o",
    Probes =
    [
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" },
        new TracepointSpec { Category = "syscalls", Name = "sys_exit_connect"  },
    ],
}
```

### Event struct

```csharp
[KernelEvent("sock_connect_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe partial struct SocketConnectEvent
{
    public ulong  TimestampNs;   // kernel monotonic time (ns)
    public uint   Pid;           // thread ID
    public uint   Tgid;          // process ID (what /proc shows)
    public uint   Uid;
    public uint   SrcIp;         // host byte order; 0 = unknown
    public uint   DstIp;         // host byte order
    public ushort SrcPort;
    public ushort DstPort;
    public fixed byte Comm[16];  // process name
    public byte   Family;        // AF_INET = 2
}
```

### Filtering example

```csharp
await foreach (var ev in session.ReadAsync<SocketConnectEvent>())
{
    if (ev.DstPort == 443) Console.WriteLine("HTTPS connection");
}
```

---

## Scheduler Profiler (`scheduler_profiler.bpf.o`)

Emits one event per context switch for off-CPU profiling.

### Probe configuration

```csharp
new SessionOptions
{
    ProbePath = "scheduler_profiler.bpf.o",
    Probes    = [new TracepointSpec { Category = "sched", Name = "sched_switch" }],
    ChannelCapacity = 131_072,  // sched events are very frequent
}
```

### Event struct

```csharp
[KernelEvent("sched_switch_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe partial struct SchedSwitchEvent
{
    public ulong TimestampNs;
    public uint  PrevPid;
    public uint  NextPid;
    public uint  CpuId;
    public int   PrevPrio;    // nice value of outgoing task
    public int   NextPrio;    // nice value of incoming task
    public byte  PrevState;   // TASK_RUNNING=0, TASK_INTERRUPTIBLE=1, etc.
    public fixed byte PrevComm[16];
    public fixed byte NextComm[16];
}
```

### Computing off-CPU time

```csharp
var sleeping = new Dictionary<uint, ulong>(); // pid → timestamp when descheduled

await session.ProcessAsync<SchedSwitchEvent>((in SchedSwitchEvent ev, CancellationToken _) =>
{
    sleeping[ev.PrevPid] = ev.TimestampNs;
    if (sleeping.Remove(ev.NextPid, out ulong slept))
    {
        ulong offCpuNs = ev.TimestampNs - slept;
        // aggregate by pid...
    }
    return ValueTask.CompletedTask;
});
```

---

## Security Guard (`security_guard.bpf.o`)

Intercepts `execve` syscalls for process execution auditing.

### Probe configuration

```csharp
new SessionOptions
{
    ProbePath = "security_guard.bpf.o",
    Probes =
    [
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_execve" },
        new TracepointSpec { Category = "syscalls", Name = "sys_exit_execve"  },
    ],
}
```

### Event struct

```csharp
[KernelEvent("execve_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe partial struct ExecveEvent
{
    public ulong TimestampNs;
    public uint  Pid;
    public uint  Tgid;
    public uint  Ppid;
    public uint  Uid;
    public uint  Gid;
    public int   ReturnCode;      // 0 = success; only valid on exit tracepoint
    public fixed byte Comm[16];   // calling process name
    public fixed byte Filename[256]; // binary being executed
}
```

---

## File I/O Monitor (`fs_io.bpf.o`)

Captures `openat`, `read`, `write`, `pread64`, and `pwrite64` syscalls with
per-call entry–exit latency.

### Probe configuration

```csharp
new SessionOptions
{
    ProbePath = "fs_io.bpf.o",
    Probes =
    [
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_openat"  },
        new TracepointSpec { Category = "syscalls", Name = "sys_exit_openat"   },
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_read"    },
        new TracepointSpec { Category = "syscalls", Name = "sys_exit_read"     },
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_write"   },
        new TracepointSpec { Category = "syscalls", Name = "sys_exit_write"    },
        // optionally also pread64 / pwrite64 enter+exit
    ],
    ChannelCapacity = 32_768,
}
```

### Event structs

```csharp
// Emitted on sys_exit_openat
[KernelEvent("fs_open_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe partial struct FsOpenEvent
{
    public ulong TimestampNs;   // exit timestamp
    public ulong LatencyNs;     // exit − entry duration
    public uint  Pid;
    public uint  Tgid;
    public uint  Uid;
    public uint  Flags;         // O_RDONLY / O_WRONLY / O_RDWR / O_CREAT / …
    public fixed byte Comm[16];
    public fixed byte Filename[256];
}

// Emitted on sys_exit_read / sys_exit_write
[KernelEvent("fs_rw_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct FsRwEvent
{
    public ulong TimestampNs;
    public ulong LatencyNs;
    public uint  Pid;
    public uint  Tgid;
    public byte  IsWrite;       // 0 = read, 1 = write
    public fixed byte Comm[16];
}
```

> **High event volume warning:** `sys_enter_read` and `sys_enter_write` fire
> for every process on the system.  Increase `ChannelCapacity` and consider
> setting `CurrentProcessOnly = true` if you only need events from your own
> application.

---

## Block I/O Analyzer (`block_io.bpf.o`)

Captures block-layer request issue and completion events, enabling per-device
I/O latency measurement.

### Probe configuration

```csharp
new SessionOptions
{
    ProbePath = "block_io.bpf.o",
    Probes =
    [
        new TracepointSpec { Category = "block", Name = "block_rq_issue"    },
        new TracepointSpec { Category = "block", Name = "block_rq_complete" },
    ],
    ChannelCapacity = 32_768,
}
```

### Event struct

This probe uses `ReadRawAsync()` because a single event carries device,
latency, sector, byte count, and direction in a packed layout.

```
Offset  Size  Field
0       8     timestamp_ns   — completion timestamp (ns)
8       8     latency_ns     — complete − issue duration (ns)
16      8     sector         — sector number
24      4     dev            — device MKDEV(major, minor)
28      4     nr_sector      — transfer length in sectors
32      4     bytes          — transfer length in bytes
36      4     pid            — PID that issued the request
40      8     rwbs[8]        — R/W/S/F/D flags string
48      16    comm[16]       — process name of the issuer
64      1     is_write       — 1 = write, 0 = read
```

### Parsing example

```csharp
await foreach (var rawEvent in session.ReadRawAsync(cts.Token))
{
    var s = rawEvent.Span;
    ulong latencyNs = MemoryMarshal.Read<ulong>(s[8..]);
    uint  dev       = MemoryMarshal.Read<uint>(s[24..]);
    bool  isWrite   = s[64] != 0;

    uint major = dev >> 8, minor = dev & 0xFF;
    Console.WriteLine($"{major}:{minor}  {(isWrite ? "W" : "R")}  {latencyNs / 1000} µs");
}
```

---

## Memory Profiler (`memory_profiler.bpf.o`)

Tracks kernel slab allocator, page allocator, and page fault events.

### Probe configuration

```csharp
new SessionOptions
{
    ProbePath = "memory_profiler.bpf.o",
    Probes =
    [
        new TracepointSpec { Category = "kmem", Name = "kmalloc"       },
        new TracepointSpec { Category = "kmem", Name = "kfree"         },
        new TracepointSpec { Category = "kmem", Name = "mm_page_alloc" },
        new TracepointSpec { Category = "kmem", Name = "mm_page_free"  },
        new KprobeSpec     { FunctionName = "handle_mm_fault"          },
    ],
    ChannelCapacity = 32_768,
}
```

### Event structs

```csharp
// kmalloc / kfree (is_free distinguishes the two)
[KernelEvent("kmalloc_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct KmallocEvent
{
    public ulong TimestampNs;
    public ulong CallSite;      // caller instruction pointer
    public ulong Ptr;           // allocated / freed pointer
    public ulong BytesReq;      // 0 on kfree
    public ulong BytesAlloc;    // actual allocation size; 0 on kfree
    public uint  GfpFlags;
    public uint  Pid;
    public fixed byte Comm[16];
    public byte  IsFree;        // 1 = kfree, 0 = kmalloc
}

// mm_page_alloc / mm_page_free (is_free distinguishes the two)
[KernelEvent("page_alloc_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct PageAllocEvent
{
    public ulong TimestampNs;
    public ulong Pfn;           // page frame number
    public uint  Order;         // 2^order pages
    public uint  GfpFlags;
    public uint  Pid;
    public byte  IsFree;
}

// handle_mm_fault kprobe
[KernelEvent("page_fault_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct PageFaultEvent
{
    public ulong TimestampNs;
    public ulong Address;       // faulting virtual address
    public uint  Pid;
    public uint  Tgid;
    public uint  Flags;         // VM_FAULT_* flags
    public fixed byte Comm[16];
}
```

---

## Kernel Internals (`kernel_internals.bpf.o`)

Captures IRQ handler latency, kernel lock contention, and CPU power-state
transitions.

### Probe configuration

```csharp
new SessionOptions
{
    ProbePath = "kernel_internals.bpf.o",
    Probes =
    [
        new TracepointSpec { Category = "irq",   Name = "irq_handler_entry" },
        new TracepointSpec { Category = "irq",   Name = "irq_handler_exit"  },
        new TracepointSpec { Category = "irq",   Name = "softirq_entry"     },
        new TracepointSpec { Category = "irq",   Name = "softirq_exit"      },
        new TracepointSpec { Category = "lock",  Name = "contention_begin"  },  // ≥ 5.14
        new TracepointSpec { Category = "lock",  Name = "contention_end"    },  // ≥ 5.14
        new TracepointSpec { Category = "power", Name = "cpu_frequency"     },
        new TracepointSpec { Category = "power", Name = "cpu_idle"          },
    ],
    ChannelCapacity = 32_768,
}
```

> `lock/contention_begin` and `lock/contention_end` require Linux ≥ 5.14.

### Event structs

```csharp
// irq_handler_entry / _exit and softirq_entry / _exit
[KernelEvent("irq_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct IrqEvent
{
    public ulong TimestampNs;
    public ulong LatencyNs;   // 0 on entry; handler duration on exit
    public uint  Irq;         // IRQ number (hw) or softirq vector
    public uint  Pid;
    public byte  EventType;   // KI_IRQ_ENTER=0, KI_IRQ_EXIT=1, KI_SOFTIRQ_ENTER=2, KI_SOFTIRQ_EXIT=3
    public byte  IsSoftirq;   // 1 = softirq, 0 = hardware IRQ
}

// lock/contention_begin / _end
[KernelEvent("lock_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct LockEvent
{
    public ulong TimestampNs;
    public ulong LatencyNs;   // 0 at begin; wait duration at end
    public ulong LockAddr;    // kernel lock address
    public uint  Pid;
    public uint  Flags;
    public byte  IsEnd;       // 0 = contention_begin, 1 = contention_end
}

// power/cpu_frequency and power/cpu_idle
[KernelEvent("power_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct PowerEvent
{
    public ulong TimestampNs;
    public uint  CpuId;
    public uint  State;       // kHz for cpu_frequency; idle C-state for cpu_idle
    public byte  IsIdle;      // 1 = cpu_idle event, 0 = cpu_frequency event
}
```

---

## Container Monitor (`container_monitor.bpf.o`)

Attributes process events to containers via cgroup v2 IDs.  Captures `execve`,
`connect`, `fork`, and `exit` events enriched with the cgroup leaf ID.

### Probe configuration

```csharp
new SessionOptions
{
    ProbePath = "container_monitor.bpf.o",
    Probes =
    [
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_execve"   },
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect"  },
        new TracepointSpec { Category = "sched",    Name = "sched_process_fork" },
        new TracepointSpec { Category = "sched",    Name = "sched_process_exit" },
    ],
    ChannelCapacity = 32_768,
}
```

### Event struct

```csharp
[KernelEvent("container_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe partial struct ContainerEvent
{
    public ulong TimestampNs;
    public ulong CgroupId;       // cgroup v2 leaf ID
    public uint  Pid;
    public uint  Tgid;
    public uint  Ppid;
    public uint  Uid;
    public byte  EventType;      // 0=EXECVE, 1=CONNECT, 2=FORK, 3=EXIT
    public fixed byte Comm[16];
    public fixed byte Filename[256]; // populated for EXECVE events only
}
```

### Resolving cgroup IDs to container names

```csharp
// Walk /sys/fs/cgroup to build id → name cache
var cgroupNames = new Dictionary<ulong, string>();
foreach (string dir in Directory.EnumerateDirectories("/sys/fs/cgroup", "*",
                                                       SearchOption.AllDirectories))
{
    string idFile = Path.Combine(dir, "cgroup.id");
    if (File.Exists(idFile) && ulong.TryParse(File.ReadAllText(idFile).Trim(), out ulong id))
        cgroupNames[id] = Path.GetFileName(dir);
}
```

> Requires cgroup v2 (unified hierarchy).  Most modern distros with systemd
> default to cgroup v2.

---

## .NET Runtime Tracer (`dotnet_runtime.bpf.o`)

Attaches uprobes to the live .NET CLR binary to trace GC collections,
exceptions, and JIT compilations.  Symbol offsets are resolved at runtime using
`nm -D`.

### Probe configuration

```csharp
// Resolve symbol offsets from the running CLR
string clrPath = FindClrLibrary(); // reads /proc/self/maps for libcoreclr.so
ulong  gcOffset = ResolveSymbol(clrPath, "GarbageCollect");    // via nm -D
ulong  exOffset = ResolveSymbol(clrPath, "RealCOMPlusThrow");
ulong  jitOffset = ResolveSymbol(clrPath, "MethodCompiled");

new SessionOptions
{
    ProbePath = "dotnet_runtime.bpf.o",
    Probes =
    [
        new UprobeSpec { BinaryPath = clrPath, Offset = gcOffset,
                         ProgramSection = "uprobe/dotnet_gc_start" },
        new UprobeSpec { BinaryPath = clrPath, Offset = gcOffset,
                         ReturnProbe = true,
                         ProgramSection = "uretprobe/dotnet_gc_end" },
        new UprobeSpec { BinaryPath = clrPath, Offset = exOffset,
                         ProgramSection = "uprobe/dotnet_exception_thrown" },
        new UprobeSpec { BinaryPath = clrPath, Offset = jitOffset,
                         ProgramSection = "uprobe/dotnet_method_jitted" },
    ],
}
```

### Event structs

```csharp
// GC start (is_end=0) and end (is_end=1)
[KernelEvent("dotnet_gc_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct DotNetGcEvent
{
    public ulong TimestampNs;
    public ulong DurationNs;    // 0 at entry; filled at return
    public uint  Pid;
    public uint  Tgid;
    public uint  Generation;    // 0 / 1 / 2
    public byte  IsEnd;
    public fixed byte Comm[16];
}

// Exception thrown
[KernelEvent("dotnet_exception_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct DotNetExceptionEvent
{
    public ulong TimestampNs;
    public ulong ExceptionPtr;  // EE object pointer (for correlation)
    public uint  Pid;
    public uint  Tgid;
    public fixed byte Comm[16];
}

// JIT compilation
[KernelEvent("dotnet_method_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct DotNetMethodEvent
{
    public ulong TimestampNs;
    public ulong MethodHandle;  // MethodDesc* (for correlation)
    public uint  Pid;
    public uint  Tgid;
    public fixed byte Comm[16];
}
```

> **Requirements:** `nm` must be installed (`binutils` package).  The CLR must
> export the symbols listed above (standard `linux-x64` runtimes do).  Symbol
> names and offsets differ across CLR versions — the sample resolves them
> dynamically at startup.

---

## Writing Custom Probes

### 1. Create `my_probe.bpf.c`

```c
#include "common.h"

struct my_event {
    __u64 timestamp_ns;
    __u32 pid;
    // add fields here
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx)
{
    struct my_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = (u32)bpf_get_current_pid_tgid();
    bpf_ringbuf_submit(ev, 0);
    return 0;
}
```

### 2. Compile

```bash
clang -O2 -g -target bpf \
      -I/path/to/kerneltrace/native/probes \
      -c my_probe.bpf.c -o my_probe.bpf.o
```

### 3. Use in .NET

```csharp
[KernelEvent("my_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct MyEvent
{
    public ulong TimestampNs;
    public uint  Pid;
}

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = "my_probe.bpf.o",
    Probes    = [new TracepointSpec { Category = "syscalls", Name = "sys_enter_write" }],
});

await foreach (var ev in session.ReadAsync<MyEvent>())
    Console.WriteLine($"write() by PID {ev.Pid}");
```

### Finding tracepoint names

```bash
# List all categories
ls /sys/kernel/debug/tracing/events/

# List events in a category
ls /sys/kernel/debug/tracing/events/syscalls/ | grep enter

# Inspect a tracepoint's field format
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
```

### Finding kprobe targets

```bash
# Searchable kernel symbol list
grep tcp /proc/kallsyms | grep " T " | head -20
```
