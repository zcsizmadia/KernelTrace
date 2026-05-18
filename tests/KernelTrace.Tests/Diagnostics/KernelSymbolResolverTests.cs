using KernelTrace.Diagnostics;

namespace KernelTrace.Tests.Diagnostics;

public sealed class KernelSymbolResolverTests
{
    // ── Load ──────────────────────────────────────────────────────────────────

    [Test]
    public async Task Load_ParsesSymbolsFromFile()
    {
        string path = WriteTempKallsyms([
            "ffffffff81000000 T startup_64",
            "ffffffff81004000 T tcp_connect",
            "ffffffff81008000 t __alloc_skb",
        ]);

        var resolver = KernelSymbolResolver.Load(path);

        await Assert.That(resolver.Count).IsEqualTo(3);

        File.Delete(path);
    }

    [Test]
    public async Task Load_SkipsZeroAddressLines()
    {
        string path = WriteTempKallsyms([
            "0000000000000000 D some_hidden_sym",
            "ffffffff81004000 T tcp_connect",
        ]);

        var resolver = KernelSymbolResolver.Load(path);

        // Zero-address symbols are skipped.
        await Assert.That(resolver.Count).IsEqualTo(1);

        File.Delete(path);
    }

    // ── Resolve ───────────────────────────────────────────────────────────────

    [Test]
    public async Task Resolve_ExactAddress_ReturnsSymbolWithNoOffset()
    {
        string path = WriteTempKallsyms([
            "ffffffff81000000 T startup_64",
            "ffffffff81004000 T tcp_connect",
        ]);

        var resolver = KernelSymbolResolver.Load(path);
        string result = resolver.Resolve(0xffffffff81004000UL);

        await Assert.That(result).IsEqualTo("tcp_connect");

        File.Delete(path);
    }

    [Test]
    public async Task Resolve_AddressWithinSymbol_ReturnsSymbolPlusOffset()
    {
        string path = WriteTempKallsyms([
            "ffffffff81000000 T startup_64",
            "ffffffff81004000 T tcp_connect",
        ]);

        var resolver = KernelSymbolResolver.Load(path);
        string result = resolver.Resolve(0xffffffff81004042UL);

        await Assert.That(result).IsEqualTo("tcp_connect+0x42");

        File.Delete(path);
    }

    [Test]
    public async Task Resolve_AddressBeforeAllSymbols_ReturnsHex()
    {
        string path = WriteTempKallsyms([
            "ffffffff81004000 T tcp_connect",
        ]);

        var resolver = KernelSymbolResolver.Load(path);
        string result = resolver.Resolve(0x1000UL);

        await Assert.That(result).StartsWith("0x");

        File.Delete(path);
    }

    [Test]
    public async Task Resolve_EmptyResolver_ReturnsHex()
    {
        string path = WriteTempKallsyms([]);
        var resolver = KernelSymbolResolver.Load(path);

        string result = resolver.Resolve(0xdeadbeefUL);

        await Assert.That(result).StartsWith("0x");

        File.Delete(path);
    }

    [Test]
    public async Task Resolve_IgnoresModuleSuffix()
    {
        // kallsyms lines can include "[module_name]" after the symbol.
        string path = WriteTempKallsyms([
            "ffffffff81004000 T tcp_connect [tcp]",
        ]);

        var resolver = KernelSymbolResolver.Load(path);
        string result = resolver.Resolve(0xffffffff81004000UL);

        await Assert.That(result).IsEqualTo("tcp_connect");

        File.Delete(path);
    }

    // ── ResolveStack ──────────────────────────────────────────────────────────

    [Test]
    public async Task ResolveStack_MapsAllAddresses()
    {
        string path = WriteTempKallsyms([
            "ffffffff81000000 T func_a",
            "ffffffff81001000 T func_b",
        ]);

        var resolver = KernelSymbolResolver.Load(path);
        string[] names = resolver.ResolveStack(
        [
            0xffffffff81000000UL,
            0xffffffff81001000UL,
        ]);

        await Assert.That(names).Count().IsEqualTo(2);
        await Assert.That(names[0]).IsEqualTo("func_a");
        await Assert.That(names[1]).IsEqualTo("func_b");

        File.Delete(path);
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private static string WriteTempKallsyms(IEnumerable<string> lines)
    {
        string path = Path.GetTempFileName();
        File.WriteAllLines(path, lines);
        return path;
    }
}
