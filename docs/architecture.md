# Architecture

This document describes the internal design of KernelTrace — how kernel events
flow from the eBPF ring buffer in the kernel to your .NET application code.

## High-level overview

```
Kernel space                          User space (.NET process)
──────────────────────────────────────────────────────────────────────────────

   Tracepoint / kprobe / uprobe
            │
            ▼
   BPF program (clang-compiled)
            │ bpf_ringbuf_submit()
            ▼
   BPF_MAP_TYPE_RINGBUF                 mmap'd ring buffer
   ┌────────────────────┐               ┌──────────────────────────────────┐
   │  [consumer page]   │◄──────────────│  RingBufferReader                │
   │  [producer page]   │               │  (reads ProducerPos, ConsumerPos │
   │  [data pages × 2]  │               │   via Volatile.Read/Write)       │
   └────────────────────┘               └───────────────┬──────────────────┘
                                                        │ DrainInto()
                                                        ▼
                                         Channel<RingBufferRecord> (bounded)
                                                        │
                                             ┌──────────┴──────────┐
                                             │                     │
                                     IAsyncEnumerable<T>    ProcessAsync<T>
                                     (ReadAsync<T>)         (zero-copy callback)
```

## Threading model

KernelTrace uses a single **polling thread** per session.  This thread:

1. Creates an `epoll` fd that watches the ring-buffer map fd.
2. Calls `epoll_wait(timeout_ms)` in a tight loop.
3. On activity, calls `RingBufferReader.DrainInto(channelWriter)`.
4. Updates `KernelTraceMetrics` counters via `Interlocked`.
5. Exits gracefully when `CancellationToken` is cancelled.

The thread is created with `IsBackground = false` (preventing process exit
while events are in flight) and `ThreadPriority.AboveNormal` by default.

### Why a dedicated thread and not a Timer or Task?

- `Task.Run` uses the thread-pool.  On a busy system, pool starvation would
  delay event polling and cause ring-buffer overflow.
- A dedicated thread with `AboveNormal` priority ensures the kernel's ring
  buffer is drained promptly before the kernel recycles slots.

### CPU affinity

Set `SessionOptions.PollingThreadAffinity` to a CPU bitmask to pin the polling
thread to a specific core, reducing cache misses on NUMA systems.

## Ring buffer memory layout

The Linux kernel ring buffer (BPF_MAP_TYPE_RINGBUF) uses a self-describing
mmap layout:

```
Offset 0                    : consumer page (64-bit consumer position)
Offset PAGE_SIZE            : producer page (64-bit producer position, read-only)
Offset PAGE_SIZE * 2        : data pages (first copy)
Offset PAGE_SIZE * 2 + DATA : data pages (mirror — wraps seamlessly)
```

Each record in the data area has an 8-byte header:

```
Bits 31    : BUSY   — kernel is still writing this record
Bits 30    : DISCARD — kernel marked this record as discarded
Bits 29:0  : length — payload byte count (not including the 8-byte header)
Bits 63:32 : page_offset (reserved, not used by the consumer)
```

`RingBufferReader.TryReadRecord` implements lock-free single-consumer logic:

1. `Volatile.Read(ProducerPos)` — check if new data arrived.
2. At the current consumer offset, read the record header.
3. If `BUSY` bit is set, stop (kernel still writing).
4. If `DISCARD` bit is set, skip and advance past this record.
5. Copy payload bytes into an `ArrayPool<byte>.Shared.Rent(length)` buffer.
6. `Volatile.Write(ConsumerPos, newPos)` — advance consumer (signals kernel).
7. Wrap the pooled buffer in a `RingBufferRecord` (stack-allocated `readonly struct`).

The copy-before-advance ordering is critical: the kernel will reclaim the slot
the moment `ConsumerPos` advances, so the data must already be safe in the
pooled array.

## Channel and backpressure

The polling thread writes `RingBufferRecord` values into a
`Channel<RingBufferRecord>` with `BoundedChannelFullMode.DropOldest`.

- If the consumer is slow, the channel fills up and older records are dropped.
- Dropped records are tracked in `KernelTraceMetrics.TotalDropped`.
- The channel capacity is configurable (`SessionOptions.ChannelCapacity`,
  default 65 536).  Increase it if you observe drops under load.

## Zero-allocation fast path: ProcessAsync

`ProcessAsync<T>` avoids the channel entirely.  The polling thread calls
`RingBufferRecord.ReadAs<T>()` inline and invokes the `KernelEventHandler<T>`
callback before advancing the consumer pointer.

This means:
- No `Channel<RingBufferRecord>` allocation.
- No `ArrayPool` rent — the callback receives a `ref readonly T` directly from
  the mmap'd ring-buffer memory.
- The callback must be fast (< ~10 µs); long-running callbacks stall the
  polling loop and cause ring-buffer overflow.

## Source generator

`KernelTrace.SourceGenerators` is a Roslyn `IIncrementalGenerator` that runs
at compile time.  For each C# struct annotated with `[KernelEvent("name")]`:

1. It finds all `.bpf.c` files registered as `EbpfSource` additional files.
2. Parses C struct declarations from those files using a regex-based parser.
3. Emits a `partial struct` with `[StructLayout(LayoutKind.Sequential, Pack=1)]`
   and fields matching the C definition.
4. Emits a compile-time size assertion (`static readonly int _sizeCheck`).

If the struct name is not found in any `.bpf.c` file, the generator emits
diagnostic `KT0001` (error).

## BTF validation (runtime)

When `SessionOptions.ValidateStructLayouts = true` (the default), the first
time you call `ReadAsync<T>()` or `ProcessAsync<T>()`, KernelTrace:

1. Reads the `[KernelEvent]` attribute from `T` to get the C struct name.
2. Calls `kt_btf_struct_size(structName)` in the native shim, which queries
   `/sys/kernel/btf/vmlinux`.
3. Compares the BTF-reported size to `Marshal.SizeOf<T>()`.
4. If they differ, throws `KernelStructMismatchException`.

This catches kernel-version skew early rather than silently reading garbage.

## Native shim (libkerneltrace.so)

The native shim is a thin C99 wrapper around `libbpf`.  Its responsibilities:

- Load and verify `.bpf.o` files (`bpf_object__open` / `bpf_object__load`).
- Attach probes via `bpf_program__attach`, `bpf_program__attach_uprobe`.
- Return the ring-buffer map fd (`bpf_map__fd`).
- `mmap` / `munmap` the ring-buffer memory region.
- Create and manage `epoll` instances.
- Query BTF struct sizes.

The shim exports only symbols prefixed with `kt_`; all other symbols have
hidden visibility.

## Error handling

| Error class | When |
|---|---|
| `PlatformNotSupportedException` | Non-Linux OS |
| `FileNotFoundException` | `.bpf.o` path does not exist |
| `NativeInteropException` | libbpf / syscall returned an error |
| `ProbeAttachException` | Probe section not found in BPF object |
| `KernelStructMismatchException` | BTF size ≠ managed struct size |
| `OperationCanceledException` | Normal cancellation via `CancellationToken` |
