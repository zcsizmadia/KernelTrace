namespace KernelTrace.Diagnostics;

/// <summary>
/// Reads <c>/proc/kallsyms</c> and resolves kernel virtual addresses to
/// human-readable symbol names with offsets.
/// </summary>
/// <remarks>
/// <para>
/// This is a best-effort resolver: only symbols present in
/// <c>/proc/kallsyms</c> (requires read access, typically root or
/// <c>kernel.kptr_restrict=0</c>) will resolve.
/// </para>
/// <para>
/// The resolver loads the symbol table into memory once at construction time
/// and is immutable thereafter — it is safe to use from multiple threads.
/// </para>
/// </remarks>
public sealed class KernelSymbolResolver
{
    private readonly (ulong Address, string Name)[] _symbols;

    private KernelSymbolResolver((ulong Address, string Name)[] symbols)
    {
        _symbols = symbols;
    }

    /// <summary>Number of symbols loaded.</summary>
    public int Count => _symbols.Length;

    /// <summary>
    /// Loads the kernel symbol table from <c>/proc/kallsyms</c>.
    /// </summary>
    /// <param name="path">Override the path (useful for testing).</param>
    /// <exception cref="System.IO.IOException">
    /// Thrown when <c>/proc/kallsyms</c> cannot be read.
    /// </exception>
    public static KernelSymbolResolver Load(string path = "/proc/kallsyms")
    {
        var symbols = new List<(ulong, string)>();

        foreach (var line in File.ReadLines(path))
        {
            // Format: <address> <type> <name> [<module>]
            // Example: ffffffff81234567 T tcp_connect
            var span = line.AsSpan();
            int first = span.IndexOf(' ');
            if (first < 0) continue;

            var addrSpan = span[..first];
            if (!ulong.TryParse(addrSpan, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
                continue;
            if (addr == 0) continue;  // unresolved / KASLR hidden address

            int second = span[(first + 1)..].IndexOf(' ');
            if (second < 0) continue;

            int nameStart = first + 1 + second + 1;
            if (nameStart >= span.Length) continue;

            // Trim optional module suffix "[module_name]"
            var nameSpan = span[nameStart..];
            int bracket = nameSpan.IndexOf(' ');
            if (bracket >= 0) nameSpan = nameSpan[..bracket];

            symbols.Add((addr, nameSpan.ToString()));
        }

        // Sort ascending by address for binary search.
        symbols.Sort((a, b) => a.Item1.CompareTo(b.Item1));

        return new KernelSymbolResolver([.. symbols]);
    }

    /// <summary>
    /// Resolves a kernel instruction pointer to a symbol name with offset.
    /// </summary>
    /// <param name="address">Raw kernel virtual address.</param>
    /// <returns>
    /// A string of the form <c>"tcp_connect+0x42"</c>, or
    /// <c>"0xffff..."</c> (hex) when no matching symbol is found.
    /// </returns>
    public string Resolve(ulong address)
    {
        if (_symbols.Length == 0)
            return $"0x{address:x}";

        // Binary search for the largest symbol address ≤ address.
        int lo = 0, hi = _symbols.Length - 1;
        while (lo < hi)
        {
            int mid = lo + (hi - lo + 1) / 2;
            if (_symbols[mid].Address <= address)
                lo = mid;
            else
                hi = mid - 1;
        }

        var (symAddr, symName) = _symbols[lo];
        if (symAddr > address)
            return $"0x{address:x}";

        ulong offset = address - symAddr;
        return offset == 0 ? symName : $"{symName}+0x{offset:x}";
    }

    /// <summary>
    /// Resolves an entire stack trace (array of IPs) into symbol names.
    /// </summary>
    public string[] ResolveStack(ulong[] addresses)
    {
        var result = new string[addresses.Length];
        for (int i = 0; i < addresses.Length; i++)
            result[i] = Resolve(addresses[i]);
        return result;
    }
}
