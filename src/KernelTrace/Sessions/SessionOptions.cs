using KernelTrace.Probes;

namespace KernelTrace.Sessions;

/// <summary>
/// Configuration for a <see cref="KernelTraceSession"/>.
/// All required properties must be set; optional properties have sensible defaults.
/// </summary>
public class SessionOptions
{
    /// <summary>
    /// Path to the compiled eBPF object file (<c>.bpf.o</c>) to load.
    /// The file must exist and be a valid BPF ELF object.
    /// </summary>
    public required string ProbePath { get; set; }

    /// <summary>
    /// The set of probes to attach after loading the eBPF object.
    /// At least one probe is required for the session to produce events.
    /// </summary>
    public IReadOnlyList<ProbeSpec> Probes { get; set; } = [];

    /// <summary>
    /// Name of the <c>BPF_MAP_TYPE_RINGBUF</c> map inside the eBPF object.
    /// Defaults to <c>"events"</c> — the conventional name used in KernelTrace
    /// probe templates.
    /// </summary>
    public string RingBufferMapName { get; set; } = "events";

    /// <summary>
    /// Maximum number of records that can be buffered in the
    /// <see cref="System.Threading.Channels.Channel{T}"/> between the kernel
    /// polling thread and the consumer.  When the channel is full, incoming
    /// records are dropped and counted as <c>events_dropped_total</c>.
    /// Default: <c>65_536</c> records.
    /// </summary>
    public int ChannelCapacity { get; set; } = 65_536;

    /// <summary>
    /// Timeout passed to <c>epoll_wait</c> on each polling iteration.
    /// A shorter value improves latency; a longer value reduces CPU usage when
    /// the ring buffer is idle.  Default: <c>100 ms</c>.
    /// </summary>
    public int PollTimeoutMs { get; set; } = 100;

    /// <summary>
    /// CPU affinity mask for the dedicated ring buffer polling thread.
    /// <c>0</c> means no affinity is set (OS scheduler decides).
    /// Set to a specific CPU bitmask to pin the thread for NUMA-aware
    /// deployments (e.g., <c>1 &lt;&lt; cpuId</c>).
    /// </summary>
    public long PollingThreadAffinity { get; set; } = 0;

    /// <summary>
    /// <see cref="System.Threading.ThreadPriority"/> for the dedicated polling
    /// thread.  Default: <see cref="ThreadPriority.AboveNormal"/>.
    /// </summary>
    public ThreadPriority PollingThreadPriority { get; set; } = ThreadPriority.AboveNormal;

    /// <summary>
    /// When <see langword="true"/>, the session will validate that the C# struct
    /// size matches the BTF-reported size on the first call to
    /// <c>ReadAsync&lt;T&gt;</c>.  Disable only if the eBPF object does not
    /// embed BTF.  Default: <see langword="true"/>.
    /// </summary>
    public bool ValidateStructLayouts { get; set; } = true;

    /// <summary>
    /// Allows injecting a custom <see cref="System.TimeProvider"/> for testability.
    /// Production code should leave this as <see cref="TimeProvider.System"/>.
    /// </summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>
    /// When <see langword="true"/>, the eBPF programs are instructed to emit
    /// events only from the current process (identified by its thread-group ID /
    /// <c>getpid()</c>).  All other processes are silently dropped inside the
    /// kernel before the data ever reaches the ring buffer.
    /// <para>
    /// This drastically reduces ring-buffer pressure and CPU overhead when you
    /// are only interested in the kernel activity of your own application.
    /// </para>
    /// <para>
    /// Note: loading eBPF programs still requires <c>CAP_BPF</c> +
    /// <c>CAP_PERFMON</c> (or root) regardless of this setting.
    /// </para>
    /// </summary>
    public bool CurrentProcessOnly { get; set; } = false;
}
