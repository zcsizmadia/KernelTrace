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
    // LoadSession is implemented further down with CO-RE options support.

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

    public bool IsBtfAvailable() => NativeMethods.BtfAvailable() != 0;

    // ── Per-process filter ────────────────────────────────────────────────────

    public void SetTgidFilter(KernelProbeHandle session, uint tgid)
    {
        NativeMethods.SetTgidFilter(session.DangerousGetHandle(), tgid, out var err);
        err.ThrowIfError();
    }

    // ── CO-RE / extended session load ─────────────────────────────────────────

    public KernelProbeHandle LoadSession(string objPath,
        string? btfCustomPath = null, bool debugOutput = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(objPath);

        if (btfCustomPath is null && !debugOutput)
        {
            // Fast path: no extended options needed.
            var h = NativeMethods.SessionLoad(objPath, out var e);
            e.ThrowIfError();
            return new KernelProbeHandle(h);
        }

        byte[]? btfBytes = btfCustomPath is null
            ? null
            : System.Text.Encoding.UTF8.GetBytes(btfCustomPath + '\0');

        unsafe
        {
            fixed (byte* btfPtr = btfBytes)
            {
                var opts = new NativeSessionOpts
                {
                    BtfCustomPathPtr = btfBytes is null ? nint.Zero : (nint)btfPtr,
                    DebugOutput      = debugOutput ? 1 : 0,
                };
                var handle = NativeMethods.SessionLoadExt(objPath, in opts, out var err);
                err.ThrowIfError();
                return new KernelProbeHandle(handle);
            }
        }
    }

    // ── USDT probes ───────────────────────────────────────────────────────────

    public AttachmentHandle AttachUsdt(KernelProbeHandle session, int pid,
        string binaryPath, string provider, string name, string? programSection = null)
    {
        var ptr = NativeMethods.AttachUsdt(
            session.DangerousGetHandle(), pid, binaryPath, provider, name,
            programSection, out var err);

        if (err.IsError)
            throw new Exceptions.ProbeAttachException(
                $"usdt:{provider}:{name}", err.Message);

        return new AttachmentHandle(ptr);
    }

    // ── BPF map operations ────────────────────────────────────────────────────

    public int MapGetFd(KernelProbeHandle session, string mapName)
    {
        int fd = NativeMethods.MapGetFd(session.DangerousGetHandle(), mapName, out var err);
        err.ThrowIfError();
        return fd;
    }

    public NativeMapInfo MapGetInfo(int mapFd)
    {
        var err = NativeMethods.MapGetInfo(mapFd, out var info);
        err.ThrowIfError();
        return info;
    }

    public unsafe int MapLookup(int mapFd, nint keyPtr, nint valuePtr) =>
        NativeMethods.MapLookup(mapFd, (void*)keyPtr, (void*)valuePtr);

    public unsafe int MapUpdate(int mapFd, nint keyPtr, nint valuePtr, ulong flags) =>
        NativeMethods.MapUpdate(mapFd, (void*)keyPtr, (void*)valuePtr, flags);

    public unsafe int MapDelete(int mapFd, nint keyPtr) =>
        NativeMethods.MapDelete(mapFd, (void*)keyPtr);

    public unsafe int MapGetNextKey(int mapFd, nint currentKeyPtr, nint nextKeyPtr) =>
        NativeMethods.MapGetNextKey(mapFd, (void*)currentKeyPtr, (void*)nextKeyPtr);
}
