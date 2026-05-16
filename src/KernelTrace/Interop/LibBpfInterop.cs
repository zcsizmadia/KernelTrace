using KernelTrace.Exceptions;

namespace KernelTrace.Interop;

/// <summary>
/// Thin managed wrapper around the raw P/Invoke layer (<see cref="NativeMethods"/>).
/// This is the production implementation of <see cref="INativeInterop"/>.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class LibBpfInterop : INativeInterop
{
    /// <summary>
    /// The singleton instance used in production. Prefer constructor injection
    /// in tests; use this only from <see cref="Sessions.KernelTraceSession"/>.
    /// </summary>
    internal static readonly LibBpfInterop Instance = new();

    private LibBpfInterop() { }

    // ── Session ──────────────────────────────────────────────────────────────

    public KernelProbeHandle LoadSession(string objPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(objPath);

        var handle = NativeMethods.SessionLoad(objPath, out var err);
        err.ThrowIfError();

        return new KernelProbeHandle(handle);
    }

    // ── Probe attachment ─────────────────────────────────────────────────────

    public AttachmentHandle AttachTracepoint(KernelProbeHandle session, string category, string name)
    {
        var ptr = NativeMethods.AttachTracepoint(session.DangerousGetHandle(), category, name, out var err);

        if (err.IsError)
        {
            throw new ProbeAttachException($"tracepoint/{category}/{name}", err.Message);
        }

        return new AttachmentHandle(ptr);
    }

    public AttachmentHandle AttachKprobe(KernelProbeHandle session, string functionName, bool returnProbe = false)
    {
        var ptr = NativeMethods.AttachKprobe(
            session.DangerousGetHandle(), functionName, returnProbe, out var err);

        if (err.IsError)
        {
            throw new ProbeAttachException(
                $"{(returnProbe ? "kretprobe" : "kprobe")}/{functionName}", err.Message);
        }

        return new AttachmentHandle(ptr);
    }

    public AttachmentHandle AttachUprobe(KernelProbeHandle session, string binaryPath, ulong offset, bool returnProbe = false, string? programSection = null)
    {
        var ptr = NativeMethods.AttachUprobe(
            session.DangerousGetHandle(), binaryPath, offset, returnProbe, programSection, out var err);

        if (err.IsError)
        {
            throw new ProbeAttachException(
                $"{(returnProbe ? "uretprobe" : "uprobe")}:{binaryPath}+0x{offset:x}", err.Message);
        }

        return new AttachmentHandle(ptr);
    }

    public void Detach(AttachmentHandle attachment) =>
        NativeMethods.Detach(attachment.DangerousGetHandle());

    // ── Ring buffer ──────────────────────────────────────────────────────────

    public int GetRingBufFd(KernelProbeHandle session, string mapName)
    {
        int fd = NativeMethods.GetRingBufFd(session.DangerousGetHandle(), mapName, out var err);
        err.ThrowIfError();
        return fd;
    }

    public unsafe MappedRingBuffer MapRingBuffer(int fd)
    {
        void* ptr = NativeMethods.MmapRingBuf(fd, out nuint totalSize, out nuint dataSize, out var err);
        err.ThrowIfError();

        if (ptr is null)
        {
            throw new NativeInteropException(0, "mmap returned null pointer");
        }

        return new MappedRingBuffer(ptr, totalSize, dataSize);
    }

    // ── Epoll ────────────────────────────────────────────────────────────────

    public int CreateEpoll(int ringBufFd)
    {
        int epfd = NativeMethods.CreateEpoll(ringBufFd, out var err);
        err.ThrowIfError();
        return epfd;
    }

    public int Poll(int epollFd, int timeoutMs) =>
        NativeMethods.Poll(epollFd, timeoutMs);

    public void CloseFd(int fd) => NativeMethods.CloseFd(fd);

    // ── BTF ──────────────────────────────────────────────────────────────────

    public int GetBtfStructSize(KernelProbeHandle session, string structName) =>
        NativeMethods.BtfStructSize(session.DangerousGetHandle(), structName);

    // ── Per-process filter ────────────────────────────────────────────────────

    public void SetTgidFilter(KernelProbeHandle session, uint tgid)
    {
        var err = NativeMethods.SetTgidFilter(session.DangerousGetHandle(), tgid);
        err.ThrowIfError();
    }
}
