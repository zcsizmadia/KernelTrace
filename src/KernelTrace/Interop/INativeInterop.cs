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
    /// <param name="objPath">Absolute path to the <c>.bpf.o</c> file.</param>
    /// <param name="btfCustomPath">
    /// Optional path to a custom BTF file for CO-RE on non-standard kernels.
    /// </param>
    /// <param name="debugOutput">
    /// When <see langword="true"/>, libbpf debug messages are written to stderr
    /// during load.
    /// </param>
    /// <exception cref="Exceptions.NativeInteropException">
    /// Thrown if the object cannot be loaded (e.g., bad bytecode, missing CAP_BPF).
    /// </exception>
    KernelProbeHandle LoadSession(string objPath,
        string? btfCustomPath = null, bool debugOutput = false);

    // ── Probe attachment ─────────────────────────────────────────────────────

    /// <summary>Attaches to a kernel tracepoint (category/name pair).</summary>
    AttachmentHandle AttachTracepoint(KernelProbeHandle session, string category, string name);

    /// <summary>Attaches a kprobe to a kernel function entry (or return).</summary>
    AttachmentHandle AttachKprobe(KernelProbeHandle session, string functionName, bool returnProbe = false);

    /// <summary>Attaches a uprobe to a user-space binary at the given offset.</summary>
    AttachmentHandle AttachUprobe(KernelProbeHandle session, string binaryPath, ulong offset, bool returnProbe = false, string? programSection = null);

    /// <summary>
    /// Attaches a USDT (Userland Statically Defined Trace) probe.
    /// </summary>
    /// <param name="session">The loaded eBPF session handle.</param>
    /// <param name="pid">Process ID to trace, or -1 for all processes.</param>
    /// <param name="binaryPath">Absolute path to the binary containing the USDT probe.</param>
    /// <param name="provider">USDT provider name (e.g. <c>"python"</c>).</param>
    /// <param name="name">USDT probe name (e.g. <c>"function__entry"</c>).</param>
    /// <param name="programSection">
    /// BPF program function name, or <see langword="null"/> to use the first
    /// <c>usdt</c> program in the object.
    /// </param>
    AttachmentHandle AttachUsdt(KernelProbeHandle session, int pid, string binaryPath,
        string provider, string name, string? programSection = null);

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
    /// (0 on timeout, negative on error).
    /// </summary>
    int Poll(int epollFd, int timeoutMs);

    /// <summary>Closes a raw file descriptor.</summary>
    void CloseFd(int fd);

    // ── BTF ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the BTF-reported byte size of a named C struct, or -1 if not found.
    /// </summary>
    int GetBtfStructSize(KernelProbeHandle session, string structName);

    /// <summary>
    /// Returns <see langword="true"/> when vmlinux BTF is available on the running
    /// kernel (<c>/sys/kernel/btf/vmlinux</c> is present and readable).
    /// </summary>
    bool IsBtfAvailable();

    // ── BPF maps ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the file descriptor of any named BPF map in the session.
    /// Works for all map types (HASH, ARRAY, STACK_TRACE, etc.).
    /// </summary>
    int MapGetFd(KernelProbeHandle session, string mapName);

    /// <summary>Queries the kernel for map metadata.</summary>
    NativeMapInfo MapGetInfo(int mapFd);

    /// <summary>
    /// Looks up a single entry.  Returns 0 on success, -2 (ENOENT) when the key
    /// is not present.
    /// </summary>
    int MapLookup(int mapFd, nint keyPtr, nint valuePtr);

    /// <summary>Inserts or updates an entry. Returns 0 on success.</summary>
    int MapUpdate(int mapFd, nint keyPtr, nint valuePtr, ulong flags);

    /// <summary>Deletes an entry. Returns 0 on success, -2 (ENOENT) if missing.</summary>
    int MapDelete(int mapFd, nint keyPtr);

    /// <summary>
    /// Iterates keys in arbitrary order.  Pass <see cref="nint.Zero"/> for the
    /// first key.  Returns 0 on success, -2 (ENOENT) when iteration is complete.
    /// </summary>
    int MapGetNextKey(int mapFd, nint currentKeyPtr, nint nextKeyPtr);

    // ── Per-process filter ────────────────────────────────────────────────────

    /// <summary>
    /// Writes <paramref name="tgid"/> into the <c>kt_tgid_filter</c> BPF map so
    /// that every probe handler drops events from all other processes.
    /// Pass <c>0</c> to clear the filter.
    /// </summary>
    void SetTgidFilter(KernelProbeHandle session, uint tgid);
}
