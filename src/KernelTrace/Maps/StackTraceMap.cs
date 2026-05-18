using KernelTrace.Interop;

namespace KernelTrace.Maps;

/// <summary>
/// Provides typed access to a <c>BPF_MAP_TYPE_STACK_TRACE</c> map.
/// Keys are <c>int</c> stack IDs (returned as part of each event by
/// <c>bpf_get_stackid</c>); values are arrays of instruction-pointer addresses.
/// </summary>
/// <remarks>
/// Pair with <see cref="Diagnostics.KernelSymbolResolver"/> to convert raw
/// addresses into human-readable kernel symbol names.
/// </remarks>
public sealed class StackTraceMap
{
    private readonly INativeInterop _interop;
    private readonly int _mapFd;
    private readonly int _maxDepth;

    internal StackTraceMap(INativeInterop interop, int mapFd, int maxDepth)
    {
        _interop  = interop;
        _mapFd    = mapFd;
        _maxDepth = maxDepth > 0 ? maxDepth : 127;
    }

    /// <summary>Maximum stack depth this map was configured for.</summary>
    public int MaxDepth => _maxDepth;

    /// <summary>
    /// Retrieves the instruction-pointer array for a given stack ID.
    /// Returns an empty array when the ID is not present (e.g. it was evicted).
    /// </summary>
    /// <param name="stackId">
    /// The stack ID obtained from a BPF event (kernel or user-space stack ID
    /// emitted by <c>bpf_get_stackid</c>).  Negative values (error codes) are
    /// ignored — an empty array is returned.
    /// </param>
    public unsafe ulong[] Lookup(int stackId)
    {
        if (stackId < 0) return [];

        // Allocate a buffer large enough for _maxDepth × 8-byte addresses.
        var buf = new ulong[_maxDepth];
        fixed (ulong* bufPtr = buf)
        {
            int rc = _interop.MapLookup(_mapFd, (nint)(&stackId), (nint)bufPtr);
            if (rc == -2) return [];   // -ENOENT
            if (rc != 0)  return [];   // treat other errors as unavailable
        }

        // Trim trailing zero entries (unused slots).
        int len = _maxDepth;
        while (len > 0 && buf[len - 1] == 0)
            len--;

        return buf[..len];
    }
}
