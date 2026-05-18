namespace KernelTrace.Maps;

/// <summary>
/// Metadata for a BPF map retrieved from the kernel via <c>bpf_obj_get_info_by_fd</c>.
/// </summary>
public sealed class BpfMapInfo
{
    /// <summary>
    /// The raw BPF map type constant (e.g. <c>1</c> = <c>BPF_MAP_TYPE_HASH</c>,
    /// <c>27</c> = <c>BPF_MAP_TYPE_STACK_TRACE</c>).
    /// </summary>
    public uint Type { get; init; }

    /// <summary>Size of one key in bytes.</summary>
    public uint KeySize { get; init; }

    /// <summary>Size of one value in bytes.</summary>
    public uint ValueSize { get; init; }

    /// <summary>Maximum number of entries the map can hold.</summary>
    public uint MaxEntries { get; init; }

    /// <inheritdoc/>
    public override string ToString() =>
        $"BpfMapInfo {{ Type={Type}, Key={KeySize}B, Value={ValueSize}B, MaxEntries={MaxEntries} }}";
}
