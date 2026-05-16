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
| `ValidateStructLayouts` | `bool` | `true` | Validate struct sizes against BTF on first read. |
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
| `MeterName` | `const string "KernelTrace"` | Meter name for OpenTelemetry. |

**Instrument names** (for Prometheus / OTEL dashboards):

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

## KernelTrace.Prometheus

### `IServiceCollection.AddKernelTraceMetrics`

```csharp
builder.Services.AddKernelTraceMetrics();
```

Registers a `KernelTracePrometheusCollector` that publishes
`KernelTraceMetrics` counters to the default Prometheus registry.

### Exposed Prometheus metrics

| Metric | Labels |
|---|---|
| `kerneltrace_events_received_total` | — |
| `kerneltrace_events_dropped_total` | — |
| `kerneltrace_ring_buffer_polls_total` | — |

---

## KernelTrace.OpenTelemetry

### `MeterProviderBuilder.AddKernelTraceInstrumentation`

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m.AddKernelTraceInstrumentation());
```

Adds the `"KernelTrace"` meter to the OpenTelemetry pipeline.  All instruments
registered in `KernelTraceMetrics` are automatically exported.

---

## Source Generator Diagnostics

| ID | Severity | Message |
|---|---|---|
| `KT0001` | Error | Struct `{name}` not found in any `.bpf.c` EbpfSource file |
| `KT0002` | Warning | Field `{field}` has unsupported C type `{type}` — skipped |
| `KT0003` | Error | `{type}` must be declared `partial` to receive generated members |
| `KT0004` | Warning | `{type}` should be `unmanaged` for safe use with `ReadAs<T>` |
| `KT0010` | Info | Successfully generated layout for `{type}` from `{struct}` |
