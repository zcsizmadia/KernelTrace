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
