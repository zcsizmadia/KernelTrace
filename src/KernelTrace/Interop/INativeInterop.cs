namespace KernelTrace.Interop;

/// <summary>
/// Abstraction over the native libkerneltrace interop layer.
/// Injected into <see cref="Sessions.KernelTraceSession"/> to allow full
/// unit-testing without a real Linux kernel or loaded eBPF object.
/// </summary>
internal interface INativeInterop
{
    // ── Session ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Loads the compiled eBPF object at <paramref name="objPath"/> into the
    /// kernel and returns an opaque session handle.
    /// </summary>
    /// <exception cref="Exceptions.NativeInteropException">
    /// Thrown if the object cannot be loaded (e.g., bad bytecode, missing CAP_BPF).
    /// </exception>
    KernelProbeHandle LoadSession(string objPath);

    // ── Probe attachment ─────────────────────────────────────────────────────

    /// <summary>Attaches to a kernel tracepoint (category/name pair).</summary>
    AttachmentHandle AttachTracepoint(KernelProbeHandle session, string category, string name);

    /// <summary>Attaches a kprobe to a kernel function entry (or return).</summary>
    AttachmentHandle AttachKprobe(KernelProbeHandle session, string functionName, bool returnProbe = false);

    /// <summary>Attaches a uprobe to a user-space binary at the given offset.</summary>
    /// <param name="session">The loaded eBPF session handle.</param>
    /// <param name="binaryPath">Absolute path to the target binary.</param>
    /// <param name="offset">Byte offset of the function entry within the binary.</param>
    /// <param name="returnProbe">When <see langword="true"/>, attaches to the function return instead.</param>
    /// <param name="programSection">
    /// Optional BPF program section name (e.g. <c>"uprobe/dotnet_gc_start"</c>).
    /// When <see langword="null"/>, the first uprobe program in the object is used.
    /// </param>
    AttachmentHandle AttachUprobe(KernelProbeHandle session, string binaryPath, ulong offset, bool returnProbe = false, string? programSection = null);

    /// <summary>Detaches and frees an attachment.</summary>
    void Detach(AttachmentHandle attachment);

    // ── Ring buffer ──────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the file descriptor of the named BPF map (must be
    /// <c>BPF_MAP_TYPE_RINGBUF</c>).
    /// </summary>
    int GetRingBufFd(KernelProbeHandle session, string mapName);

    /// <summary>
    /// Memory-maps the ring buffer. The caller owns the returned
    /// <see cref="MappedRingBuffer"/> and must dispose it.
    /// </summary>
    MappedRingBuffer MapRingBuffer(int fd);

    // ── Epoll ────────────────────────────────────────────────────────────────

    /// <summary>Creates an epoll fd that watches the ring buffer fd.</summary>
    int CreateEpoll(int ringBufFd);

    /// <summary>
    /// Waits for data on the epoll fd.  Returns the number of ready fds
    /// (0 on timeout, -1 on error).
    /// </summary>
    int Poll(int epollFd, int timeoutMs);

    /// <summary>Closes a raw file descriptor.</summary>
    void CloseFd(int fd);

    // ── BTF ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the BTF-reported byte size of a named C struct, or -1 if not found.
    /// </summary>
    int GetBtfStructSize(KernelProbeHandle session, string structName);

    // ── Per-process filter ────────────────────────────────────────────────────

    /// <summary>
    /// Writes <paramref name="tgid"/> into the <c>kt_tgid_filter</c> BPF map so
    /// that every probe handler drops events from all other processes.
    /// Pass <c>0</c> to clear the filter.
    /// </summary>
    void SetTgidFilter(KernelProbeHandle session, uint tgid);
}
