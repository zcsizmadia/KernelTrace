using KernelTrace.Interop;

namespace KernelTrace.Tests.Fakes;

/// <summary>
/// In-memory implementation of <see cref="INativeInterop"/> for unit tests.
/// No native library or Linux kernel required.
/// </summary>
internal sealed class FakeNativeInterop : INativeInterop
{
    // ── State ────────────────────────────────────────────────────────────────

    /// <summary>Records each attach call for assertion in tests.</summary>
    public List<string> AttachedProbes { get; } = [];

    /// <summary>Tracks how many times Poll was called.</summary>
    public int PollCallCount { get; private set; }

    /// <summary>
    /// Controls whether Poll returns data (1) or timeout (0) on the next call.
    /// </summary>
    public Queue<int> PollResults { get; } = new();

    /// <summary>The ring buffer used by this fake.</summary>
    public FakeRingBuffer RingBuffer { get; } = new();

    /// <summary>Throws the given exception on the next LoadSession call.</summary>
    public Exception? LoadException { get; set; }

    /// <summary>Simulated BTF struct sizes (struct name → byte size).</summary>
    public Dictionary<string, int> BtfSizes { get; } = new(StringComparer.Ordinal);

    /// <summary>Records the TGID set by SetTgidFilter, or null if never called.</summary>
    public uint? TgidFilter { get; private set; }

    // ── INativeInterop ───────────────────────────────────────────────────────

    public KernelProbeHandle LoadSession(string objPath)
    {
        if (LoadException is not null)
        {
            throw LoadException;
        }
        // Return a fake non-zero handle.
        return new FakeKernelProbeHandle(1);
    }

    public AttachmentHandle AttachTracepoint(KernelProbeHandle session, string category, string name)
    {
        AttachedProbes.Add($"tracepoint/{category}/{name}");
        return new FakeAttachmentHandle(AttachedProbes.Count);
    }

    public AttachmentHandle AttachKprobe(KernelProbeHandle session, string functionName, bool returnProbe = false)
    {
        AttachedProbes.Add($"{(returnProbe ? "kretprobe" : "kprobe")}/{functionName}");
        return new FakeAttachmentHandle(AttachedProbes.Count);
    }

    public AttachmentHandle AttachUprobe(KernelProbeHandle session, string binaryPath, ulong offset, bool returnProbe = false, string? programSection = null)
    {
        AttachedProbes.Add($"{(returnProbe ? "uretprobe" : "uprobe")}:{binaryPath}+0x{offset:x}");
        return new FakeAttachmentHandle(AttachedProbes.Count);
    }

    public void Detach(AttachmentHandle attachment)
    {
        // No-op in fake.
    }

    public int GetRingBufFd(KernelProbeHandle session, string mapName) => 42; // fake fd

    public MappedRingBuffer MapRingBuffer(int fd) => RingBuffer.CreateMapping();

    public int CreateEpoll(int ringBufFd) => 99; // fake epoll fd

    public int Poll(int epollFd, int timeoutMs)
    {
        PollCallCount++;
        return PollResults.Count > 0 ? PollResults.Dequeue() : 0;
    }

    public void CloseFd(int fd) { /* no-op */ }

    public int GetBtfStructSize(KernelProbeHandle session, string structName) =>
        BtfSizes.TryGetValue(structName, out int size) ? size : -1;

    public void SetTgidFilter(KernelProbeHandle session, uint tgid) =>
        TgidFilter = tgid;
}

// ── Fake SafeHandle implementations ─────────────────────────────────────────

internal sealed class FakeKernelProbeHandle : KernelProbeHandle
{
    public FakeKernelProbeHandle(nint value) : base(value) { }

    protected override bool ReleaseHandle() => true; // no-op
}

internal sealed class FakeAttachmentHandle : AttachmentHandle
{
    public FakeAttachmentHandle(nint value) : base(value) { }

    protected override bool ReleaseHandle() => true; // no-op
}
