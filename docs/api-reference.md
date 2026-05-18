# API Reference

Complete public API surface for KernelTrace.

---

## KernelTrace (core)

### `KernelTraceSession`

> `sealed class` · `IAsyncDisposable`  
> Namespace: `KernelTrace.Sessions`

Represents an active eBPF tracing session.  Owns the kernel probe handle,
ring buffer reader, and polling thread.  All instances must be disposed.

#### Factory methods

```csharp
// Creates a session using the real libbpf native interop (Linux only).
static Task<KernelTraceSession> CreateAsync(
    SessionOptions       options,
    ILogger?             logger            = null,
    CancellationToken    cancellationToken = default);
```

#### Static methods

```csharp
// Returns true when the running kernel exposes BTF (required for CO-RE).
[SupportedOSPlatform("linux")]
static bool IsBtfAvailable();
```

#### Properties

| Property | Type | Description |
|---|---|---|
| `Metrics` | `KernelTraceMetrics` | Live counters and histograms for this session. |

#### Methods

```csharp
// Stream events as a strongly-typed async sequence.
// Validates struct layout against BTF on first call (when ValidateStructLayouts=true).
IAsyncEnumerable<T> ReadAsync<T>(CancellationToken ct = default)
    where T : unmanaged;

// Stream raw byte buffers — use when events have a dynamic schema
// or when a single .bpf.o emits multiple event types.
// Each Memory<byte> is a view of a pooled buffer; do not retain it beyond the loop body.
IAsyncEnumerable<ReadOnlyMemory<byte>> ReadRawAsync(CancellationToken ct = default);

// Zero-copy callback API. The handler receives a `ref readonly T`
// backed by the mmap'd ring buffer — do not cache the reference.
Task ProcessAsync<T>(
    KernelEventHandler<T> handler,
    CancellationToken     cancellationToken = default)
    where T : unmanaged;

// Dynamically attach a probe to the running session.
Task<SessionAttachmentToken> AttachAsync(ProbeSpec probe, CancellationToken ct = default);

// Detach a probe attached via AttachAsync.
Task DetachAsync(SessionAttachmentToken token);

// Open a typed BPF map for read/write from .NET (Feature 1).
BpfMap<TKey, TValue> GetMap<TKey, TValue>(string mapName)
    where TKey   : unmanaged
    where TValue : unmanaged;

// Open a BPF_MAP_TYPE_STACK_TRACE map for kernel/user stack lookup (Feature 3).
StackTraceMap GetStackTraceMap(string mapName = "stacks");

// Release all kernel resources.
ValueTask DisposeAsync();
```

#### Delegate

```csharp
// Handler for ProcessAsync. Must complete quickly (< ~10 µs).
delegate ValueTask KernelEventHandler<T>(in T kernelEvent, CancellationToken ct)
    where T : unmanaged;
```

---

### `SessionOptions`

> `sealed class`  
> Namespace: `KernelTrace.Sessions`

Configuration for a `KernelTraceSession`.

| Property | Type | Default | Description |
|---|---|---|---|
| `ProbePath` | `string` | *(required)* | Path to the compiled `.bpf.o` file. |
| `Probes` | `IReadOnlyList<ProbeSpec>` | `[]` | Probes to attach on session start. |
| `RingBufferMapName` | `string` | `"events"` | Name of the `BPF_MAP_TYPE_RINGBUF` map. |
| `ChannelCapacity` | `int` | `65_536` | Bounded channel capacity (records). |
| `PollTimeoutMs` | `int` | `100` | epoll_wait timeout per iteration (ms). |
| `PollingThreadAffinity` | `long` | `0` | CPU affinity bitmask (0 = no affinity). |
| `PollingThreadPriority` | `ThreadPriority` | `AboveNormal` | Priority of the polling thread. |
| `CurrentProcessOnly` | `bool` | `false` | Emit events only from the current process (filtered in-kernel). |
| `ValidateStructLayouts` | `bool` | `true` | Validate struct sizes against BTF on first read. |
| `BtfCustomPath` | `string?` | `null` | Path to a custom BTF archive for CO-RE on kernels without BTF. |
| `DebugOutput` | `bool` | `false` | Enable verbose libbpf loader debug logging. |
| `TimeProvider` | `TimeProvider` | `TimeProvider.System` | For testability. |

---

### `ProbeSpec` hierarchy

> `abstract class`  
> Namespace: `KernelTrace.Probes`

#### `TracepointSpec`

```csharp
new TracepointSpec
{
    Category = "syscalls",              // required
    Name     = "sys_enter_connect",    // required
    Label    = "my-label",             // optional — overrides Describe()
}
```

#### `KprobeSpec`

```csharp
new KprobeSpec
{
    FunctionName = "tcp_connect",  // required
    ReturnProbe  = false,          // true → kretprobe
}
```

#### `UprobeSpec`

```csharp
new UprobeSpec
{
    BinaryPath  = "/usr/lib/libc.so.6",  // required
    Offset      = 0x1234UL,              // required — byte offset in ELF
    ReturnProbe = false,
}
```

#### `UsdtSpec`  *(Feature 2)*

Attaches to a User Statically Defined Trace (USDT) probe embedded in a
compiled binary (e.g. Python, Node.js, or any binary built with `dtrace`
annotations).

```csharp
new UsdtSpec
{
    BinaryPath     = "/usr/bin/python3",   // required
    Provider       = "python",             // required — SDT provider name
    Name           = "function__entry",    // required — SDT probe name
    ProgramSection = "usdt/python:function__entry",  // optional — BPF section name
    Pid            = -1,                   // -1 = all processes; set to a specific PID to filter
}
```

The `ProgramSection` must match the `SEC(...)` string in the `.bpf.c` file.
When `null`, the loader uses the default section derived from the probe description.

---

### `KernelTraceMetrics`

> `sealed class` · `IDisposable`  
> Namespace: `KernelTrace.Diagnostics`

Thread-safe counters and histograms.  Available via `KernelTraceSession.Metrics`.

| Member | Type | Description |
|---|---|---|
| `TotalReceived` | `long` | Events successfully drained from ring buffer. |
| `TotalDropped` | `long` | Events dropped due to channel backpressure. |
| `TotalPolls` | `long` | Number of `epoll_wait` iterations. |
**Instrument names**:

| Instrument | Type | Description |
|---|---|---|
| `kerneltrace.events.received.total` | Counter | Total events received |
| `kerneltrace.events.dropped.total` | Counter | Total events dropped |
| `kerneltrace.ring_buffer.polls.total` | Counter | Poll iterations |
| `kerneltrace.ring_buffer.drain.duration` | Histogram (ms) | Time to drain one batch |

---

### Event attributes

#### `[KernelEvent(string structName)]`

> `[AttributeUsage(AttributeTargets.Struct)]`  
> Namespace: `KernelTrace.Events`

Marks a C# struct as the managed projection of a kernel BPF event struct.

- `structName` must match the C struct name in the `.bpf.c` source file.
- The struct must be `partial`, `unmanaged`, and have
  `[StructLayout(LayoutKind.Sequential, Pack = 1)]`.
- The source generator will emit the struct fields automatically.
- At runtime, `ValidateStructLayouts=true` verifies the size via BTF.

---

### Exceptions

| Exception | Base | Key properties |
|---|---|---|
| `KernelTraceException` | `Exception` | Base for all library exceptions |
| `NativeInteropException` | `KernelTraceException` | `NativeErrorCode` (errno) |
| `ProbeAttachException` | `KernelTraceException` | Probe name + reason |
| `KernelStructMismatchException` | `KernelTraceException` | `StructTypeName`, `ExpectedSize`, `ActualSize` |

---

## KernelTrace.AspNetCore

### `IServiceCollection.AddKernelTrace`

```csharp
builder.Services.AddKernelTrace(options =>
{
    options.ProbePath = "my.bpf.o";
    options.Probes    = [new TracepointSpec { Category = "sched", Name = "sched_switch" }];
});
```

Registers:
- `SessionOptions` (singleton) via the configure delegate.
- `KernelTraceHostedService` as `IHostedService`.

### `KernelTraceHostedService`

> `sealed class` · `IHostedService` · `IAsyncDisposable`  
> `[SupportedOSPlatform("linux")]`

Manages the `KernelTraceSession` lifetime within the ASP.NET Core host.
`StartAsync` creates the session; `StopAsync` disposes it.

---

## Source Generator Diagnostics

| ID | Severity | Message |
|---|---|---|
| `KT0001` | Error | Struct `{name}` not found in any `.bpf.c` EbpfSource file |
| `KT0002` | Warning | Field `{field}` has unsupported C type `{type}` — skipped |
| `KT0003` | Error | `{type}` must be declared `partial` to receive generated members |
| `KT0004` | Warning | `{type}` should be `unmanaged` for safe use with `ReadAs<T>` |
| `KT0010` | Info | Successfully generated layout for `{type}` from `{struct}` |

---

## Maps  *(Feature 1 & 4)*

### `BpfMap<TKey, TValue>`

> `sealed class`  
> Namespace: `KernelTrace.Maps`  
> Constraints: `TKey : unmanaged`, `TValue : unmanaged`

Represents an open BPF map for read/write access from .NET.
Obtain an instance via `KernelTraceSession.GetMap<TKey, TValue>(mapName)`.

```csharp
// Point-lookup — returns null when the key is absent.
TValue? Lookup(TKey key);

// Returns false when the key is absent; avoids boxing.
bool TryLookup(TKey key, out TValue value);

// Insert or update a map entry.
void Update(TKey key, TValue value, BpfMapUpdateFlags flags = BpfMapUpdateFlags.Any);

// Remove a key; returns false if the key was not present.
bool Delete(TKey key);

// Synchronous enumeration of all entries (snapshot at call time).
IEnumerable<KeyValuePair<TKey, TValue>> Iterate();

// Asynchronous enumeration — yields one key-value pair per iteration.
IAsyncEnumerable<KeyValuePair<TKey, TValue>> IterateAsync(CancellationToken ct = default);

// Read map metadata from the kernel.
BpfMapInfo GetInfo();
```

### `BpfMapUpdateFlags`

```csharp
public enum BpfMapUpdateFlags : ulong
{
    Any     = 0,  // insert or update
    NoExist = 1,  // insert only — throws if key exists
    Exist   = 2,  // update only — throws if key is absent
}
```

### `BpfMapInfo`

```csharp
public sealed class BpfMapInfo
{
    public uint Type       { get; }  // BPF_MAP_TYPE_* enum value
    public uint KeySize    { get; }  // bytes
    public uint ValueSize  { get; }  // bytes
    public uint MaxEntries { get; }
}
```

---

## Stack traces  *(Feature 3)*

### `StackTraceMap`

> `sealed class`  
> Namespace: `KernelTrace.Maps`

Typed accessor for `BPF_MAP_TYPE_STACK_TRACE` maps.
Obtain via `KernelTraceSession.GetStackTraceMap(mapName)`.

```csharp
// Maximum stack depth (frames per entry).
int MaxDepth { get; }

// Look up a stack by its ID (stored in the per-event `kernel_stack_id` /
// `user_stack_id` fields).  Returns an empty array for negative IDs or
// when the entry has already been evicted.
ulong[] Lookup(int stackId);
```

### `KernelSymbolResolver`

> `sealed class`  
> Namespace: `KernelTrace.Diagnostics`

Resolves kernel instruction-pointer addresses to human-readable symbol names
using `/proc/kallsyms`.

```csharp
// Load symbols from a kallsyms file (requires read access — may need root).
// path defaults to "/proc/kallsyms".
static KernelSymbolResolver Load(string path = "/proc/kallsyms");

// Total number of symbols loaded.
int Count { get; }

// Resolve a single address.  Returns "0x{addr:x16}" when no symbol is found.
string Resolve(ulong address);

// Resolve an array of addresses (e.g. a full stack frame).
string[] ResolveStack(ulong[] addresses);
```

---

## ILogger integration  *(Feature 5)*

### `KernelTraceLoggerExtensions`

> `static class`  
> Namespace: `KernelTrace`

```csharp
// Transparently log each event while forwarding it downstream.
IAsyncEnumerable<T> WithLogging<T>(
    this IAsyncEnumerable<T> source,
    ILogger                  logger,
    LogLevel                 level     = LogLevel.Information,
    Func<T, string>?         formatter = null)
    where T : unmanaged;

// Consume all events from a session, logging each one until the token is cancelled.
[SupportedOSPlatform("linux")]
Task LogEventsAsync<T>(
    this KernelTraceSession session,
    ILogger                 logger,
    Func<T, string>?        formatter         = null,
    LogLevel                level             = LogLevel.Information,
    CancellationToken       cancellationToken = default)
    where T : unmanaged;
```

**Example:**

```csharp
// Option A — log and process in the same loop.
await foreach (var ev in session.ReadAsync<MyEvent>()
                                .WithLogging(logger, LogLevel.Debug))
{
    Process(ev);
}

// Option B — fire-and-forget background logging.
await session.LogEventsAsync<MyEvent>(logger, ev => $"PID={ev.Pid}", cancellationToken: cts.Token);
```



