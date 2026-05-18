using KernelTrace.Exceptions;
using KernelTrace.Interop;

namespace KernelTrace.Maps;

/// <summary>
/// Provides typed read/write access to a BPF map from .NET.
/// </summary>
/// <typeparam name="TKey">
/// An <c>unmanaged</c> struct whose in-memory layout matches the BPF map key.
/// </typeparam>
/// <typeparam name="TValue">
/// An <c>unmanaged</c> struct whose in-memory layout matches the BPF map value.
/// </typeparam>
/// <remarks>
/// <para>
/// Obtain an instance via
/// <see cref="Sessions.KernelTraceSession.GetMap{TKey,TValue}(string)"/>.
/// The map fd is owned by the session — do not dispose this object; it becomes
/// invalid when the session is disposed.
/// </para>
/// <para>All operations are synchronous at the BPF syscall level but are
/// wrapped in <see cref="ValueTask"/> to allow future async back-pressure.</para>
/// </remarks>
public sealed class BpfMap<TKey, TValue>
    where TKey   : unmanaged
    where TValue : unmanaged
{
    private readonly INativeInterop _interop;
    private readonly int _mapFd;
    private readonly string _mapName;

    internal BpfMap(INativeInterop interop, int mapFd, string mapName)
    {
        _interop = interop;
        _mapFd   = mapFd;
        _mapName = mapName;
    }

    /// <summary>Name of the BPF map as declared in the eBPF source.</summary>
    public string Name => _mapName;

    /// <summary>
    /// Retrieves metadata (type, key/value sizes, capacity) for this map.
    /// </summary>
    public BpfMapInfo GetInfo()
    {
        var raw = _interop.MapGetInfo(_mapFd);
        return new BpfMapInfo
        {
            Type        = raw.Type,
            KeySize     = raw.KeySize,
            ValueSize   = raw.ValueSize,
            MaxEntries  = raw.MaxEntries,
        };
    }

    /// <summary>
    /// Looks up a single entry by key.
    /// Returns <see langword="null"/> when the key is not present.
    /// </summary>
    public unsafe TValue? Lookup(TKey key)
    {
        TValue value = default;
        int rc = _interop.MapLookup(_mapFd, (nint)(&key), (nint)(&value));
        if (rc == -2) return null;  // -ENOENT
        if (rc != 0)
            throw new NativeInteropException(rc, $"bpf_map_lookup_elem failed on '{_mapName}': errno {-rc}");
        return value;
    }

    /// <summary>
    /// Looks up a single entry.  Returns <see langword="default"/> when absent
    /// and sets <paramref name="value"/> to the default of <typeparamref name="TValue"/>.
    /// </summary>
    public unsafe bool TryLookup(TKey key, out TValue value)
    {
        TValue localValue = default;
        int rc = _interop.MapLookup(_mapFd, (nint)(&key), (nint)(&localValue));
        value = localValue;
        if (rc == -2) return false;
        if (rc != 0)
            throw new NativeInteropException(rc, $"bpf_map_lookup_elem failed on '{_mapName}': errno {-rc}");
        return true;
    }

    /// <summary>
    /// Inserts or updates an entry according to <paramref name="flags"/>.
    /// </summary>
    /// <exception cref="NativeInteropException">On native failure.</exception>
    public unsafe void Update(TKey key, TValue value,
        BpfMapUpdateFlags flags = BpfMapUpdateFlags.Any)
    {
        int rc = _interop.MapUpdate(_mapFd, (nint)(&key), (nint)(&value), (ulong)flags);
        if (rc == -17) // -EEXIST
            throw new InvalidOperationException($"Map '{_mapName}': key already exists (use BpfMapUpdateFlags.Any to overwrite).");
        if (rc == -2) // -ENOENT
            throw new InvalidOperationException($"Map '{_mapName}': key does not exist (use BpfMapUpdateFlags.Any to insert).");
        if (rc != 0)
            throw new NativeInteropException(rc, $"bpf_map_update_elem failed on '{_mapName}': errno {-rc}");
    }

    /// <summary>
    /// Deletes the entry for <paramref name="key"/>.
    /// Returns <see langword="true"/> if the entry existed, <see langword="false"/> if not.
    /// </summary>
    public unsafe bool Delete(TKey key)
    {
        int rc = _interop.MapDelete(_mapFd, (nint)(&key));
        if (rc == -2) return false;  // -ENOENT
        if (rc != 0)
            throw new NativeInteropException(rc, $"bpf_map_delete_elem failed on '{_mapName}': errno {-rc}");
        return true;
    }

    /// <summary>
    /// Iterates all entries in the map in an unspecified order.
    /// </summary>
    /// <remarks>
    /// Concurrent map mutations during iteration may cause entries to appear
    /// more than once or be skipped — this is a BPF kernel-level constraint.
    /// </remarks>
    public unsafe IEnumerable<KeyValuePair<TKey, TValue>> Iterate()
    {
        TKey currentKey  = default;
        TKey nextKey     = default;
        var  results     = new List<KeyValuePair<TKey, TValue>>();
        bool first       = true;

        while (true)
        {
            int rc;
            rc = first
                ? _interop.MapGetNextKey(_mapFd, nint.Zero, (nint)(&nextKey))
                : _interop.MapGetNextKey(_mapFd, (nint)(&currentKey), (nint)(&nextKey));

            if (rc == -2) break;  // -ENOENT → iteration complete
            if (rc != 0)
                throw new NativeInteropException(rc, $"bpf_map_get_next_key failed on '{_mapName}': errno {-rc}");

            currentKey = nextKey;
            first = false;

            if (TryLookup(currentKey, out var value))
                results.Add(new KeyValuePair<TKey, TValue>(currentKey, value));
        }

        return results;
    }

    /// <summary>
    /// Asynchronously iterates all entries.  The underlying BPF syscalls are
    /// synchronous; the <c>async</c> wrapper allows callers to await the result
    /// on any context.
    /// </summary>
    public async IAsyncEnumerable<KeyValuePair<TKey, TValue>> IterateAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation]
        CancellationToken cancellationToken = default)
    {
        // Offload the synchronous iteration to a thread pool thread so we
        // don't block the calling async context during the syscall loop.
        var snapshot = await Task.Run(Iterate, cancellationToken).ConfigureAwait(false);
        foreach (var entry in snapshot)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return entry;
        }
    }
}
