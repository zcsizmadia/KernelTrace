namespace KernelTrace.Interop;

/// <summary>
/// Represents a memory-mapped eBPF ring buffer region.
/// The memory layout mirrors the kernel's <c>bpf_ringbuf</c>:
/// <list type="bullet">
///   <item><description>[0 .. PAGE_SIZE)        — consumer page (read pointer)</description></item>
///   <item><description>[PAGE_SIZE .. 2*PAGE_SIZE) — producer page (write pointer)</description></item>
///   <item><description>[2*PAGE_SIZE .. end)     — data pages (mapped twice for seamless wrap)</description></item>
/// </list>
/// </summary>
internal sealed unsafe class MappedRingBuffer : IDisposable
{
    private readonly void* _ptr;
    private readonly nuint _totalSize;
    private bool _disposed;

    /// <summary>Size of the data section in bytes (always a power of two).</summary>
    internal nuint DataSize { get; }

    /// <summary>Raw pointer to the start of the mapping (consumer page).</summary>
    internal void* BasePointer => _ptr;

    internal MappedRingBuffer(void* ptr, nuint totalSize, nuint dataSize)
    {
        _ptr = ptr;
        _totalSize = totalSize;
        DataSize = dataSize;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (OperatingSystem.IsLinux())
        {
            NativeMethods.Munmap(_ptr, _totalSize);
        }
    }
}
