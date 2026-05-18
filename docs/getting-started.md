# Getting Started with KernelTrace

KernelTrace is an in-process eBPF kernel tracing library for .NET.  It lets you
attach to kernel tracepoints, kprobes, and uprobes from managed code, stream
kernel events as strongly-typed .NET structs — all without spawning a sidecar process.

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

// Set up Ctrl+C cancellation
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = "/usr/share/kerneltrace/probes/network_monitor.bpf.o",
    // Both enter AND exit tracepoints are required — the BPF program records
    // the entry timestamp and emits the event on exit.
    Probes    =
    [
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" },
        new TracepointSpec { Category = "syscalls", Name = "sys_exit_connect"  },
    ],
});

try
{
    await foreach (var ev in session.ReadAsync<SocketConnectEvent>(cts.Token))
    {
        Console.WriteLine($"PID={ev.Pid}  dst={ev.DstIp}:{ev.DstPort}");
    }
}
catch (OperationCanceledException) { }  // normal exit via Ctrl+C
```

> **Why both enter and exit?**  Many BPF programs use the enter hook to save
> syscall arguments (e.g. the destination address) and the exit hook to emit
> the event because the return value is only available on exit.  Always check
> the `SEC(...)` annotations in your `.bpf.c` source and include a
> `TracepointSpec` for every section the program defines.

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
| USDT | `UsdtSpec` | DTrace/SystemTap probe points in Python, Node.js, and SDT-annotated binaries. |

```csharp
// Tracepoint
new TracepointSpec { Category = "sched", Name = "sched_switch" }

// kprobe — function entry
new KprobeSpec { FunctionName = "tcp_connect" }

// kretprobe — function return
new KprobeSpec { FunctionName = "tcp_connect", ReturnProbe = true }

// uprobe
new UprobeSpec { BinaryPath = "/usr/lib/x86_64-linux-gnu/libc.so.6", Offset = 0x1234 }

// USDT — Python function__entry probe
new UsdtSpec
{
    BinaryPath     = "/usr/bin/python3",
    Provider       = "python",
    Name           = "function__entry",
    ProgramSection = "usdt/python:function__entry",
    Pid            = -1,  // -1 = all processes
}
```

## BPF Map Access

Read or write any BPF map from .NET using `GetMap<TKey,TValue>`:

```csharp
// Open a hash map named "counts" exposed by the probe
var counts = session.GetMap<uint, ulong>("counts");

// Point lookup
ulong? hits = counts.Lookup(myPid);

// Iterate all entries (snapshot)
foreach (var (pid, count) in counts.Iterate())
    Console.WriteLine($"PID {pid}: {count} events");

// Write a config value into a BPF array map
var cfg = session.GetMap<uint, uint>("config");
cfg.Update(0, 42);
```

See [`BpfMap<TKey,TValue>` in the API reference](api-reference.md#bpfmaptkey-tvalue) for the full surface.

## Stack Traces

Capture and symbolize kernel and user-space stacks:

```csharp
var stackMap = session.GetStackTraceMap("stacks");  // BPF_MAP_TYPE_STACK_TRACE
var resolver = KernelSymbolResolver.Load();          // reads /proc/kallsyms

await foreach (var ev in session.ReadAsync<MySampleEvent>())
{
    ulong[] frames = stackMap.Lookup(ev.KernelStackId);
    string[] symbols = resolver.ResolveStack(frames);
    Console.WriteLine(string.Join("\n  ", symbols));
}
```

## ILogger Integration

Log every event without changing your existing event loop:

```csharp
// Transparent tap — logs each event, then yields it downstream
await foreach (var ev in session.ReadAsync<MyEvent>()
                                .WithLogging(logger, LogLevel.Debug))
{
    Process(ev);
}

// Fire-and-forget background logger
await session.LogEventsAsync<MyEvent>(
    logger,
    formatter: ev => $"PID={ev.Pid}",
    cancellationToken: cts.Token);
```

## CO-RE (Compile Once – Run Everywhere)

Supply a custom BTF archive when the target kernel has no built-in BTF:

```csharp
bool hasBtf = KernelTraceSession.IsBtfAvailable();

new SessionOptions
{
    ProbePath     = "my_probe.bpf.o",
    // Optional: path from BTFHub or pahole for kernels without /sys/kernel/btf/vmlinux
    BtfCustomPath = hasBtf ? null : "/path/to/vmlinux-5.15.btf",
    // Enable verbose libbpf loader logging for troubleshooting
    DebugOutput   = Environment.GetEnvironmentVariable("KT_DEBUG") == "1",
}
```

BTF archives for common kernel versions are available from
[BTFHub](https://github.com/aquasecurity/btfhub).



```csharp
var token = await session.AttachAsync(new KprobeSpec { FunctionName = "tcp_retransmit_skb" });

// ... later ...
await session.DetachAsync(token);
```

## Current-process-only mode

When you only care about your own application's kernel activity, set
`CurrentProcessOnly = true`.  The eBPF program will drop events from all other
processes **inside the kernel**, before they ever reach the ring buffer:

```csharp
new SessionOptions
{
    ProbePath          = "fs_io.bpf.o",
    Probes             = [ ... ],
    CurrentProcessOnly = true,   // massive reduction in ring-buffer pressure
}
```

This is especially useful for high-volume probes like `sys_enter_read` and
`sys_enter_write`, which fire for every process on the system.

> Loading eBPF programs still requires `CAP_BPF` + `CAP_PERFMON` regardless of
> this setting.

## Raw event streaming

Use `ReadRawAsync()` when a single `.bpf.o` emits events of multiple types
(distinguished by a discriminator field) or when the layout is dynamic:

```csharp
await foreach (var raw in session.ReadRawAsync(cts.Token))
{
    // raw is a ReadOnlyMemory<byte> — do not retain it beyond the loop body.
    byte eventType = raw.Span[0];
    switch (eventType)
    {
        case 0: HandleFoo(raw.Span); break;
        case 1: HandleBar(raw.Span); break;
    }
}
```

For single-event-type probes prefer the type-safe `ReadAsync<T>`.

## Cancellation and clean shutdown

All streaming methods accept a `CancellationToken`.  The recommended pattern:

```csharp
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;   // prevent process kill on first Ctrl+C
    cts.Cancel();
};

try
{
    await foreach (var ev in session.ReadAsync<MyEvent>(cts.Token))
    {
        // process event
    }
}
catch (OperationCanceledException) { }   // normal exit — do not rethrow

await session.DisposeAsync();
```

`OperationCanceledException` is the expected, normal result of cancellation.
Catch it at the outermost event loop and do not rethrow it.

## ASP.NET Core Integration

```csharp
builder.Services.AddKernelTrace(options =>
{
    options.ProbePath = "/usr/share/kerneltrace/probes/network_monitor.bpf.o";
    options.Probes    = [new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" }];
});
```

The `KernelTraceHostedService` manages the session lifetime automatically.

## Building the native library from source

If you are working from a source checkout (rather than installing via NuGet),
you must build the native library before running `dotnet build` or `dotnet run`.
Two scripts in `native/scripts/` automate this:

| Script | Purpose |
|---|---|
| `gen-vmlinux.sh` | Generates `native/probes/vmlinux.h` from the running kernel's BTF via `bpftool` |
| `build-and-install.sh` | Builds `libkerneltrace.so` and all `.bpf.o` probe objects, then copies them into `runtimes/<RID>/native/` |

### Build-time prerequisites

| Tool | Version | Ubuntu/Debian | Alpine |
|---|---|---|---|
| `clang` | ≥ 14 | `apt install clang` | `apk add clang` |
| `cmake` | ≥ 3.20 | `apt install cmake` | `apk add cmake` |
| `libbpf-dev` | ≥ 1.0 | `apt install libbpf-dev` | `apk add libbpf-dev` |
| `pkg-config` | any | `apt install pkg-config` | `apk add pkgconf` |
| `bpftool` | ≥ 5.13 | `apt install linux-tools-$(uname -r) linux-tools-common` | `apk add bpftool` |

### Step 1 — Generate `vmlinux.h` (once per kernel version)

`vmlinux.h` is a single-file BTF dump of all kernel types.  It is **not**
committed to the repository because it is kernel-version-specific.

```bash
bash native/scripts/gen-vmlinux.sh
```

This writes `native/probes/vmlinux.h` from `/sys/kernel/btf/vmlinux`.  Re-run
it whenever you upgrade the kernel or switch to a different machine.

### Step 2 — Build and install the native artefacts

```bash
bash native/scripts/build-and-install.sh
```

The script automatically:

1. Detects the host architecture (`x86_64` → `linux-x64`, `aarch64` → `linux-arm64`).
2. Detects the libc variant — checks `/etc/alpine-release` first (reliable in
   CI Alpine containers), then falls back to `ldd --version` for other musl
   distros (Void Linux, OpenWRT, …). Adds a `-musl` RID suffix when detected
   (e.g. `linux-musl-x64`).
3. Runs CMake with `-DCMAKE_BUILD_TYPE=Release -DKERNELTRACE_BUILD_PROBES=ON`.
4. Copies `libkerneltrace.so` and all `*.bpf.o` files into
   `runtimes/<RID>/native/` — the path the .NET native-asset resolver and
   `dotnet pack` use automatically.

After both steps, ordinary `dotnet build` / `dotnet run` commands work with no
additional configuration.

### Skipping BPF probe compilation

If `clang` or `bpftool` is unavailable, you can build only the native shim
(no `.bpf.o` probes):

```bash
cmake -S native -B native/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DKERNELTRACE_BUILD_PROBES=OFF
cmake --build native/build --parallel $(nproc)
mkdir -p runtimes/$(uname -m | sed 's/x86_64/linux-x64/;s/aarch64/linux-arm64/')/native
cp native/build/libkerneltrace.so runtimes/.../native/
```

Note that pre-built `.bpf.o` files are required to create a
`KernelTraceSession` at runtime; without them only unit tests that use
`FakeNativeInterop` will work.

---

## Next Steps

- [Architecture](architecture.md) — ring buffer internals, threading model
- [Probe Reference](probes.md) — all built-in probe categories
- [Samples](samples.md) — annotated walk-through of all 9 sample programs
- [API Reference](api-reference.md) — full public surface
