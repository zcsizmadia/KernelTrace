# Samples

KernelTrace ships twelve ready-to-run samples that demonstrate the full range of
the library's capabilities.  Each sample is a self-contained .NET console
application that can be run with `dotnet run` (with the appropriate Linux
capabilities).

---

## Prerequisites for all samples

```bash
# Build the native shim and eBPF probe objects
cd native
cmake -B build -DCMAKE_BUILD_TYPE=Release -DKERNELTRACE_BUILD_PROBES=ON
cmake --build build -j$(nproc)
sudo cmake --install build

# Grant capabilities to the dotnet host (or your published binary)
sudo setcap cap_bpf,cap_perfmon+ep $(which dotnet)
```

All samples handle **Ctrl+C** gracefully — they cancel the session and exit
cleanly with exit code 0.

---

## NetworkMonitor

**Path:** `samples/NetworkMonitor/`  
**Probe:** `network_monitor.bpf.o`

Displays a live table of outbound TCP/UDP connections system-wide.  Each row
shows the timestamp, PID, process name, source address, destination address,
and port.  Connections to well-known ports (80, 443, 22, 3306, …) are
highlighted in colour.  Connections to unusual high ports print a security
warning.

### Run

```bash
cd samples/NetworkMonitor
dotnet run
```

### What it demonstrates

- Attaching **both** `sys_enter_connect` and `sys_exit_connect` — the BPF
  program records the entry timestamp and emits the event on exit.
- Strongly-typed `[KernelEvent]` struct with `ReadAsync<T>`.
- Parsing packed IPv4 addresses from a `uint` field.
- Cancellation-aware `await foreach`.

### Key probe config

```csharp
Probes =
[
    new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" },
    new TracepointSpec { Category = "syscalls", Name = "sys_exit_connect"  },
],
```

> **Note:** Both enter and exit tracepoints must be listed.  The BPF program
> uses the enter hook to save the syscall arguments and the exit hook to emit
> the event — omitting either will produce no output.

---

## SchedulerProfiler

**Path:** `samples/SchedulerProfiler/`  
**Probe:** `scheduler_profiler.bpf.o`

Implements an **off-CPU profiler** by listening to `sched_switch` events.
Tracks how long each thread spends off-CPU and prints a sorted ranking every
few seconds, showing the threads with the most total sleep time.

### Run

```bash
cd samples/SchedulerProfiler
dotnet run
```

### What it demonstrates

- High-frequency tracepoint (`sched_switch` fires on every context switch).
- Computing derived metrics from event pairs (enter timestamp → exit timestamp).
- Using `ProcessAsync<T>` zero-copy callback for high-throughput paths.
- Increasing `ChannelCapacity` for high-volume probes.

---

## SecurityGuard

**Path:** `samples/SecurityGuard/`  
**Probe:** `security_guard.bpf.o`

Audits every `execve` call system-wide.  For each process execution it prints
the timestamp, PID, UID, parent process, and the binary path.  Executions of
binaries in suspicious locations (`/tmp`, `/dev/shm`, scripts with
world-writable paths) are highlighted with a red warning.

### Run

```bash
cd samples/SecurityGuard
dotnet run
```

### What it demonstrates

- Pairing `sys_enter_execve` and `sys_exit_execve` to capture both the
  filename argument and the return code.
- Reading a fixed-size `char[256]` field as a null-terminated UTF-8 string.
- Security-focused event processing.

---

## FileIoMonitor

**Path:** `samples/FileIoMonitor/`  
**Probe:** `fs_io.bpf.o`

Streams every `openat`, `read`, `write`, `pread64`, and `pwrite64` syscall
with per-call latency in microseconds.  Maintains a rolling top-20 list of the
slowest `openat` calls, refreshed every 5 seconds.

### Run

```bash
cd samples/FileIoMonitor
dotnet run
```

### What it demonstrates

- Attaching six tracepoints (enter+exit pairs for three syscalls).
- Per-call latency measurement: the BPF program saves the entry timestamp in a
  scratch map and emits the event on exit with the computed `latency_ns`.
- Using a `PeriodicTimer` reporting task alongside the event loop.
- High event volume — file I/O tracepoints fire on every read/write for the
  entire system, making proper cancellation handling essential.

> **Cancellation note:** Because `sys_enter_read` / `sys_enter_write` fire for
> every process on the system, the channel may always be non-empty.
> KernelTrace checks `CancellationToken` before each event is processed so
> Ctrl+C exits promptly even under heavy load.

---

## BlockIoAnalyzer

**Path:** `samples/BlockIoAnalyzer/`  
**Probe:** `block_io.bpf.o`

Displays a per-device block I/O dashboard showing read count, write count,
average read latency, and average write latency for every storage device on the
system.  The dashboard refreshes every 2 seconds.

### Run

```bash
cd samples/BlockIoAnalyzer
dotnet run
```

### What it demonstrates

- Using `ReadRawAsync()` instead of typed `ReadAsync<T>` — the sample manually
  parses the raw byte buffer using `MemoryMarshal.Read<T>`.
- The `block_rq_issue` / `block_rq_complete` tracepoint pair for latency
  measurement.
- Aggregating metrics into a live dashboard with `PeriodicTimer`.

### When to use `ReadRawAsync`

Use `ReadRawAsync` when a single `.bpf.o` emits events of multiple types
(distinguished by a type discriminator field), or when the struct layout is
determined at runtime.  For single-event-type probes, prefer the type-safe
`ReadAsync<T>`.

---

## MemoryProfiler

**Path:** `samples/MemoryProfiler/`  
**Probe:** `memory_profiler.bpf.o`

Tracks kernel memory activity in real time:

- **Slab allocator** — counts every `kmalloc` and `kfree`, grouped by call
  site (instruction pointer), and computes net outstanding bytes per site.
- **Page allocator** — counts `mm_page_alloc` / `mm_page_free` events.
- **Page faults** — counts `handle_mm_fault` kprobe hits.

The dashboard refreshes every 3 seconds.

### Run

```bash
cd samples/MemoryProfiler
dotnet run
```

### What it demonstrates

- Mixing tracepoints (`kmem/kmalloc`, `kmem/kfree`, `kmem/mm_page_alloc`,
  `kmem/mm_page_free`) with a **kprobe** (`handle_mm_fault`) in a single
  session.
- Multi-event-type `ReadRawAsync` with size-based discriminator.
- Call-site attribution via the `call_site` instruction pointer field.

---

## KernelInternals

**Path:** `samples/KernelInternals/`  
**Probe:** `kernel_internals.bpf.o`

A three-panel live dashboard covering:

1. **IRQ latency** — per-IRQ number, average and maximum handler duration
   (hardware + softirq).
2. **Lock contention** — per lock address, count and total wait time.
3. **CPU P/C-states** — latest frequency per CPU (kHz) and idle state
   transitions.

Refreshes every 2 seconds.

### Run

```bash
# lock tracepoints require kernel >= 5.14
cd samples/KernelInternals
dotnet run
```

### What it demonstrates

- Attaching eight tracepoints from four categories (`irq`, `lock`, `power`) in
  a single session.
- Using `ReadRawAsync` to dispatch events to different accumulators based on
  payload size.
- Kernel version requirements: `lock/contention_begin` and
  `lock/contention_end` require Linux ≥ 5.14.

---

## ContainerMonitor

**Path:** `samples/ContainerMonitor/`  
**Probe:** `container_monitor.bpf.o`

Attributes kernel events to containers using **cgroup v2** IDs.  At startup,
it walks `/sys/fs/cgroup` to build a cgroup-ID → container-name cache.  Each
event row shows which container triggered the event (or its raw cgroup ID if
unmapped).

Captured events: `execve`, outbound `connect`, `fork`, and `exit`.

### Run

```bash
# requires cgroup v2 (unified hierarchy)
cd samples/ContainerMonitor
dotnet run
```

### What it demonstrates

- Reading the `cgroup_id` field emitted by the BPF program
  (`bpf_get_current_cgroup_id()`).
- Resolving cgroup IDs to human-readable container names by reading
  `/sys/fs/cgroup/<name>/cgroup.id` at startup.
- A single session covering four different tracepoints from two categories.
- `ReadRawAsync` with a type-discriminator byte (`event_type`).

### Requirements

- Linux with cgroup v2 mounted at `/sys/fs/cgroup` (default on most modern
  distros with systemd).
- Each container must have its own leaf cgroup (true for Docker and containerd
  with the cgroupv2 driver).

---

## DotNetRuntime

**Path:** `samples/DotNetRuntime/`  
**Probe:** `dotnet_runtime.bpf.o`

Attaches **uprobes** directly to the .NET CLR (`libcoreclr.so`) to trace:

- **GC** — every garbage collection with generation and duration.
- **Exceptions** — every exception thrown via `RealCOMPlusThrow`.
- **JIT** — every method compiled via `MethodCompiled`.

Symbol offsets are resolved at runtime using `nm -D` on the live CLR binary.

### Run

```bash
cd samples/DotNetRuntime
dotnet run
```

### What it demonstrates

- **uprobe / uretprobe** attachment with `UprobeSpec`.
- Specifying a `ProgramSection` to disambiguate multiple uprobe handlers in a
  single `.bpf.o`.
- Runtime symbol resolution using `nm` — the offsets differ between CLR
  versions, so they cannot be hard-coded.
- Conditional probe attachment (skips a symbol if `nm` cannot resolve it).

### Requirements

- The CLR must have exported symbols (standard `linux-x64` .NET runtime does).
- `nm` must be installed (`binutils` package).
- The sample must run on a Linux .NET process (it inspects `/proc/self/maps`
  to locate `libcoreclr.so`).

---

## Running all samples

```bash
# From the repo root — run each sample for 10 seconds then stop
for sample in NetworkMonitor SchedulerProfiler SecurityGuard FileIoMonitor \
              BlockIoAnalyzer MemoryProfiler KernelInternals ContainerMonitor \
              DotNetRuntime StackSampler UsdtPythonTracer CoreRelocations; do
    echo "=== $sample ==="
    timeout 10 dotnet run --project "samples/$sample" || true
done
```

---

## StackSampler  *(New — Feature 3)*

**Path:** `samples/StackSampler/`  
**Probe:** `stack_sampler.bpf.o`

Captures kernel and user-space stack traces on every `openat()` syscall and
symbolizes kernel frames in real time using `/proc/kallsyms`.  Stops after 20
events.

### Run

```bash
cd samples/StackSampler
dotnet run
```

### What it demonstrates

- `KernelTraceSession.GetStackTraceMap("stacks")` — opens a
  `BPF_MAP_TYPE_STACK_TRACE` map.
- `StackTraceMap.Lookup(stackId)` — retrieves an array of instruction pointers
  for a given stack ID.
- `KernelSymbolResolver.Load()` — loads `/proc/kallsyms` for kernel frame
  symbolization.
- `KernelSymbolResolver.ResolveStack(frames)` — maps `ulong[]` addresses to
  `string[]` symbol names.

### Key probe config

```csharp
Probes = [new TracepointSpec { Category = "syscalls", Name = "sys_enter_openat" }],
```

### Requirements

- `/proc/kallsyms` read access (usually requires root or `CAP_SYSLOG`).
- `BPF_MAP_TYPE_STACK_TRACE` support (kernel ≥ 4.9).

---

## UsdtPythonTracer  *(New — Feature 2)*

**Path:** `samples/UsdtPythonTracer/`  
**Probe:** `usdt_python.bpf.o`

Attaches to Python 3's built-in `function__entry` USDT probe and prints every
Python function call — filename, function name, and line number — in real time.

Optionally set the `PYTHON_PID` environment variable to restrict tracing to a
single Python process.

### Run

```bash
# In one terminal: run any Python script
python3 -c "import http.server; http.server.test()"

# In another terminal:
cd samples/UsdtPythonTracer
PYTHON_PID=$(pgrep python3) dotnet run
```

### What it demonstrates

- `UsdtSpec` — attaching to a USDT probe point by provider and probe name.
- `UsdtSpec.Pid` — filtering by a specific process ID (`-1` = all processes).
- `UsdtSpec.ProgramSection` — specifying the BPF program section that handles
  the USDT tracepoint.
- Reading `char[64]` C-string fields (`filename`, `funcname`) from BPF events.

### Key probe config

```csharp
new UsdtSpec
{
    BinaryPath     = "/usr/bin/python3",
    Provider       = "python",
    Name           = "function__entry",
    ProgramSection = "usdt/python:function__entry",
    Pid            = targetPid,  // -1 for all processes
}
```

### Requirements

- Python 3 compiled with USDT probes (package `python3-dbg` on Debian/Ubuntu,
  or build with `--enable-dtrace`).
- Check with: `readelf -n /usr/bin/python3 | grep -i sdt`

---

## CoreRelocations  *(New — Feature 6)*

**Path:** `samples/CoreRelocations/`  
**Probe:** `network_monitor.bpf.o`

Demonstrates CO-RE (Compile Once – Run Everywhere) support:

- Calls `KernelTraceSession.IsBtfAvailable()` to check whether the kernel
  exposes BTF.
- Reads the `BTF_PATH` environment variable to optionally supply a custom BTF
  archive (useful on older kernels or container images without BTF).
- Reads `KT_DEBUG=1` to enable verbose libbpf loader logging.

The sample then runs the same `network_monitor` probe as the `NetworkMonitor`
sample — the key difference is the `SessionOptions` configuration.

### Run

```bash
cd samples/CoreRelocations

# Normal CO-RE (kernel has BTF):
dotnet run

# Custom BTF archive (kernel lacks BTF):
BTF_PATH=/path/to/vmlinux-5.15.btf dotnet run

# Verbose libbpf output:
KT_DEBUG=1 dotnet run
```

### What it demonstrates

- `KernelTraceSession.IsBtfAvailable()` — static runtime BTF check.
- `SessionOptions.BtfCustomPath` — path to an alternative BTF archive (e.g.
  from [BTFHub](https://github.com/aquasecurity/btfhub)).
- `SessionOptions.DebugOutput` — enables `libbpf_set_print` verbose output for
  troubleshooting loader errors.

### Key session config

```csharp
new SessionOptions
{
    ProbePath     = "network_monitor.bpf.o",
    BtfCustomPath = Environment.GetEnvironmentVariable("BTF_PATH"),
    DebugOutput   = Environment.GetEnvironmentVariable("KT_DEBUG") == "1",
    ...
}
```
