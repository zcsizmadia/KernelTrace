# Getting Started with KernelTrace

KernelTrace is an in-process eBPF kernel tracing library for .NET.  It lets you
attach to kernel tracepoints, kprobes, and uprobes from managed code, stream
kernel events as strongly-typed .NET structs, and export metrics to Prometheus
or OpenTelemetry — all without spawning a sidecar process.

## Prerequisites

| Requirement | Details |
|---|---|
| **OS** | Linux kernel 5.8+ (ring-buffer API required) |
| **Capability** | `CAP_BPF` + `CAP_PERFMON` (or run as root) |
| **BTF** | `/sys/kernel/btf/vmlinux` must exist (enabled by `CONFIG_DEBUG_INFO_BTF=y`) |
| **.NET SDK** | .NET 8, 9, or 10 |
| **libbpf** | 1.0+ (`apt install libbpf-dev` / `dnf install libbpf-devel`) |

## Installation

```bash
dotnet add package KernelTrace
```

For ASP.NET Core hosted sessions:

```bash
dotnet add package KernelTrace.AspNetCore
```

## Quick Start

### 1. Write (or use) a compiled eBPF probe

KernelTrace ships pre-built `.bpf.o` files for common use-cases.  For custom
probes, compile with clang:

```bash
clang -O2 -g -target bpf -c my_probe.bpf.c -o my_probe.bpf.o
```

### 2. Define your event struct

Use the source generator to auto-generate the C# struct from your BPF C file:

```csharp
// MyProbeEvents.cs
using KernelTrace.Events;
using System.Runtime.InteropServices;

[KernelEvent("sock_connect_event")]   // name of the C struct in .bpf.c
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe partial struct SocketConnectEvent
{
    public ulong  TimestampNs;
    public uint   Pid;
    public uint   DstIp;
    public ushort DstPort;
    public fixed byte Comm[16];
}
```

Add the `.bpf.c` file as an `EbpfSource` item in your `.csproj`:

```xml
<ItemGroup>
  <AdditionalFiles Include="network_monitor.bpf.c" BuildAction="EbpfSource" />
</ItemGroup>
```

The generator will verify that your struct layout matches the kernel definition
at compile time.

### 3. Stream events with `IAsyncEnumerable<T>`

```csharp
using KernelTrace.Sessions;
using KernelTrace.Probes;

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = "/usr/share/kerneltrace/probes/network_monitor.bpf.o",
    Probes    = [new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" }],
});

await foreach (var ev in session.ReadAsync<SocketConnectEvent>())
{
    Console.WriteLine($"PID={ev.Pid}  dst={ev.DstIp}:{ev.DstPort}");
}
```

### 4. Zero-copy callback API

For the highest throughput avoid the channel copy and use `ProcessAsync`:

```csharp
await session.ProcessAsync<SocketConnectEvent>(
    handler: async (in SocketConnectEvent ev, CancellationToken ct) =>
    {
        // ev is a ref to the ring-buffer record — no allocation.
        await myMetric.RecordAsync(ev.DstPort, ct);
    });
```

## Probe Types

| Probe | Class | When to use |
|---|---|---|
| Tracepoint | `TracepointSpec` | Stable kernel ABI. Prefer over kprobes. |
| kprobe | `KprobeSpec` | Arbitrary kernel function entry or return. |
| uprobe | `UprobeSpec` | User-space function entry or return (e.g., libc, .NET runtime). |

```csharp
// Tracepoint
new TracepointSpec { Category = "sched", Name = "sched_switch" }

// kprobe — function entry
new KprobeSpec { FunctionName = "tcp_connect" }

// kretprobe — function return
new KprobeSpec { FunctionName = "tcp_connect", ReturnProbe = true }

// uprobe
new UprobeSpec { BinaryPath = "/usr/lib/x86_64-linux-gnu/libc.so.6", Offset = 0x1234 }
```

## Hot Attach / Detach

Probes can be added and removed while the session is running:

```csharp
var token = await session.AttachAsync(new KprobeSpec { FunctionName = "tcp_retransmit_skb" });

// ... later ...
await session.DetachAsync(token);
```

## ASP.NET Core Integration

```csharp
builder.Services.AddKernelTrace(options =>
{
    options.ProbePath = "/usr/share/kerneltrace/probes/network_monitor.bpf.o";
    options.Probes    = [new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" }];
});
```

The `KernelTraceHostedService` manages the session lifetime automatically.

## Metrics

### Prometheus

```bash
dotnet add package KernelTrace.Prometheus
```

```csharp
builder.Services.AddKernelTraceMetrics();
app.MapMetrics("/metrics");
```

### OpenTelemetry

```bash
dotnet add package KernelTrace.OpenTelemetry
```

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m.AddKernelTraceInstrumentation());
```

## Next Steps

- [Architecture](architecture.md) — ring buffer internals, threading model
- [Probe Reference](probes.md) — all built-in probe categories
- [API Reference](api-reference.md) — full public surface
