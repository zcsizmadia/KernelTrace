namespace KernelTrace.Probes;

/// <summary>
/// Base class for all eBPF probe attachment specifications.
/// Use one of the concrete subtypes:
/// <list type="bullet">
///   <item><see cref="TracepointSpec"/> — kernel tracepoints</item>
///   <item><see cref="KprobeSpec"/> — kprobes on kernel functions</item>
///   <item><see cref="UprobeSpec"/> — uprobes on user-space functions</item>
/// </list>
/// </summary>
public abstract class ProbeSpec
{
    /// <summary>
    /// Optional human-readable label used in logging and metrics.
    /// Defaults to a type-specific string if not set.
    /// </summary>
    public string? Label { get; init; }

    /// <summary>Returns a human-readable description of this probe.</summary>
    public abstract string Describe();
}

/// <summary>
/// Attaches to a Linux kernel tracepoint identified by
/// <c>category/name</c> (e.g., <c>net/net_dev_xmit</c>).
/// </summary>
/// <example>
/// <code>
/// new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" }
/// </code>
/// </example>
public sealed class TracepointSpec : ProbeSpec
{
    /// <summary>The tracepoint category (e.g., <c>sched</c>, <c>net</c>).</summary>
    public required string Category { get; init; }

    /// <summary>The tracepoint name (e.g., <c>sched_switch</c>).</summary>
    public required string Name { get; init; }

    /// <inheritdoc/>
    public override string Describe() =>
        Label ?? $"tracepoint/{Category}/{Name}";
}

/// <summary>
/// Attaches a kprobe (or kretprobe) to a kernel function.
/// </summary>
/// <example>
/// <code>
/// // Entry probe
/// new KprobeSpec { FunctionName = "tcp_connect" }
///
/// // Return probe
/// new KprobeSpec { FunctionName = "tcp_connect", ReturnProbe = true }
/// </code>
/// </example>
public sealed class KprobeSpec : ProbeSpec
{
    /// <summary>The exact kernel symbol name to probe.</summary>
    public required string FunctionName { get; init; }

    /// <summary>
    /// When <see langword="true"/>, attaches to the function return
    /// (kretprobe) instead of entry (kprobe).
    /// </summary>
    public bool ReturnProbe { get; init; }

    /// <inheritdoc/>
    public override string Describe() =>
        Label ?? $"{(ReturnProbe ? "kretprobe" : "kprobe")}/{FunctionName}";
}

/// <summary>
/// Attaches a uprobe (or uretprobe) to a specific offset inside a
/// user-space ELF binary.
/// </summary>
/// <example>
/// <code>
/// new UprobeSpec
/// {
///     BinaryPath = "/usr/lib/x86_64-linux-gnu/libc.so.6",
///     Offset = 0x12345,
/// }
/// </code>
/// </example>
public sealed class UprobeSpec : ProbeSpec
{
    /// <summary>Absolute path to the ELF binary.</summary>
    public required string BinaryPath { get; init; }

    /// <summary>Byte offset of the probe site within the binary.</summary>
    public required ulong Offset { get; init; }

    /// <summary>When <see langword="true"/>, attaches to function return.</summary>
    public bool ReturnProbe { get; init; }

    /// <summary>
    /// Optional BPF program section name to attach at this offset.
    /// When <see langword="null"/>, the native shim uses the first uprobe
    /// section found in the loaded BPF object.
    /// Use this when a single <c>.bpf.o</c> contains multiple uprobe handlers
    /// (e.g., <c>"uprobe/dotnet_gc_start"</c>, <c>"uprobe/dotnet_exception"</c>).
    /// </summary>
    public string? ProgramSection { get; init; }

    /// <inheritdoc/>
    public override string Describe() =>
        Label ?? $"{(ReturnProbe ? "uretprobe" : "uprobe")}:{System.IO.Path.GetFileName(BinaryPath)}+0x{Offset:x}";
}
