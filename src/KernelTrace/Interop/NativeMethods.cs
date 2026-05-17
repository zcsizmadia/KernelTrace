using KernelTrace.Exceptions;

namespace KernelTrace.Interop;

/// <summary>
/// Low-level P/Invoke declarations that map directly to the C API exposed by
/// <c>libkerneltrace.so</c>. All methods are <c>partial</c> and source-generated
/// by <see cref="LibraryImportAttribute"/> — AOT-safe, no runtime IL emit.
/// </summary>
/// <remarks>
/// This class is an implementation detail. Callers should use
/// <see cref="LibBpfInterop"/> (the managed wrapper) or inject
/// <see cref="INativeInterop"/> for testability.
/// </remarks>
[SupportedOSPlatform("linux")]
internal static partial class NativeMethods
{
    private const string LibName = "libkerneltrace";

    // ── Session lifecycle ────────────────────────────────────────────────────

    /// <summary>Loads a compiled eBPF object file into the kernel.</summary>
    [LibraryImport(LibName, EntryPoint = "kt_session_load",
        StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nint SessionLoad(string objPath, out NativeError error);

    /// <summary>Unloads all probes and frees the session.</summary>
    [LibraryImport(LibName, EntryPoint = "kt_session_close")]
    internal static partial void SessionClose(nint session);

    // ── Probe attachment ─────────────────────────────────────────────────────

    [LibraryImport(LibName, EntryPoint = "kt_attach_tracepoint",
        StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nint AttachTracepoint(
        nint session, string category, string name, out NativeError error);

    [LibraryImport(LibName, EntryPoint = "kt_attach_kprobe",
        StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nint AttachKprobe(
        nint session, string funcName,
        [MarshalAs(UnmanagedType.Bool)] bool retProbe,
        out NativeError error);

    [LibraryImport(LibName, EntryPoint = "kt_attach_uprobe",
        StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nint AttachUprobe(
        nint session, string binaryPath, ulong funcOffset,
        [MarshalAs(UnmanagedType.Bool)] bool retProbe,
        string? progSection,
        out NativeError error);

    [LibraryImport(LibName, EntryPoint = "kt_detach")]
    internal static partial void Detach(nint attachment);

    // ── Ring buffer ──────────────────────────────────────────────────────────

    [LibraryImport(LibName, EntryPoint = "kt_get_ringbuf_fd",
        StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int GetRingBufFd(
        nint session, string mapName, out NativeError error);

    [LibraryImport(LibName, EntryPoint = "kt_mmap_ringbuf")]
    internal static unsafe partial void* MmapRingBuf(
        int fd, out nuint totalSize, out nuint dataSize, out NativeError error);

    [LibraryImport(LibName, EntryPoint = "kt_munmap")]
    internal static unsafe partial void Munmap(void* ptr, nuint totalSize);

    // ── Polling ──────────────────────────────────────────────────────────────

    [LibraryImport(LibName, EntryPoint = "kt_create_epoll")]
    internal static partial int CreateEpoll(int ringBufFd, out NativeError error);

    /// <summary>
    /// Blocks until data is available or <paramref name="timeoutMs"/> elapses.
    /// Returns the number of ready file descriptors (0 = timeout, -1 = error).
    /// </summary>
    [LibraryImport(LibName, EntryPoint = "kt_poll")]
    internal static partial int Poll(int epollFd, int timeoutMs);

    [LibraryImport(LibName, EntryPoint = "kt_close_fd")]
    internal static partial void CloseFd(int fd);

    // ── Utilities ────────────────────────────────────────────────────────────

    /// <summary>Returns the OS page size in bytes (typically 4096).</summary>
    [LibraryImport(LibName, EntryPoint = "kt_get_page_size")]
    internal static partial ulong GetPageSize();

    // ── BTF metadata ─────────────────────────────────────────────────────────

    /// <summary>
    /// Looks up the byte size of a named C struct in the BTF metadata embedded
    /// inside the loaded eBPF object. Returns -1 if the struct is not found.
    /// </summary>
    [LibraryImport(LibName, EntryPoint = "kt_btf_struct_size",
        StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int BtfStructSize(nint session, string structName);

    /// <summary>
    /// Restrict event emission to a single process by writing the target TGID
    /// into the <c>kt_tgid_filter</c> BPF array map.  Pass 0 to clear the filter.
    /// </summary>
    [LibraryImport(LibName, EntryPoint = "kt_session_set_tgid_filter")]
    internal static partial void SetTgidFilter(nint session, uint tgid, out NativeError error);
}

// ── Error descriptor struct ──────────────────────────────────────────────────

/// <summary>
/// Blittable error descriptor returned by every libkerneltrace function.
/// Code 0 means success; any other value is an error.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeError
{
    /// <summary>Zero on success; non-zero on failure.</summary>
    public int Code;

    /// <summary>Raw ANSI error message buffer (max 255 chars + null terminator).</summary>
    public fixed byte MessageBuffer[256];

    /// <summary>Human-readable error message decoded from the native buffer.</summary>
    public readonly string Message
    {
        get
        {
            fixed (byte* p = MessageBuffer)
                return Marshal.PtrToStringAnsi((nint)p) ?? string.Empty;
        }
    }

    /// <summary>Whether this struct represents an error condition.</summary>
    public readonly bool IsError => Code != 0;

    /// <summary>Throws a <see cref="NativeInteropException"/> if this is an error.</summary>
    public readonly void ThrowIfError()
    {
        if (IsError)
        {
            throw new NativeInteropException(Code, Message);
        }
    }

    /// <inheritdoc/>
    public override readonly string ToString() => IsError ? $"[{Code}] {Message}" : "OK";
}
