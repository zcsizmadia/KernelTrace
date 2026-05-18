namespace KernelTrace.Maps;

/// <summary>
/// Controls how <see cref="BpfMap{TKey,TValue}.Update"/> behaves when the
/// key already exists or does not exist.
/// </summary>
public enum BpfMapUpdateFlags : ulong
{
    /// <summary>Insert if absent, update if present (default).</summary>
    Any = 0,

    /// <summary>Only insert; fail with <see cref="InvalidOperationException"/> if the key already exists.</summary>
    NoExist = 1,

    /// <summary>Only update; fail with <see cref="InvalidOperationException"/> if the key does not exist.</summary>
    Exist = 2,
}
