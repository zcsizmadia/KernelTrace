using System.CommandLine;
using System.CommandLine.Invocation;
using System.Runtime.InteropServices;
using KernelTrace.Diagnostics;
using KernelTrace.Probes;
using KernelTrace.Sessions;

// ─────────────────────────────────────────────────────────────────────────────
//  dotnet-kerneltrace
//
//  A .NET global tool that wraps KernelTrace and exposes common eBPF tracing
//  operations from the command line without writing any C#.
//
//  Commands:
//    btf-check                    — check whether the running kernel exposes BTF
//    trace <probe-type> [options] — attach a probe and stream events to stdout
//    map-dump <probe-obj> <map>   — attach a session and dump a BPF map
//    kallsyms-resolve <addr>      — resolve one or more kernel addresses
// ─────────────────────────────────────────────────────────────────────────────

var root = new RootCommand("dotnet-kerneltrace — real-time eBPF tracing from the .NET CLI");

// ── btf-check ─────────────────────────────────────────────────────────────────
var btfCmd = new Command("btf-check", "Check whether the running kernel exposes BTF (CO-RE support).");
btfCmd.SetHandler(() =>
{
    bool available = KernelTraceSession.IsBtfAvailable();
    Console.WriteLine(available
        ? "BTF is available — CO-RE relocations are supported."
        : "BTF is NOT available — CO-RE relocations will require a custom BTF file.");
    return Task.FromResult(available ? 0 : 1);
});
root.AddCommand(btfCmd);

// ── trace ─────────────────────────────────────────────────────────────────────
var traceCmd    = new Command("trace", "Attach a probe and stream raw events to stdout as hex+timestamp.");
var probeObjArg = new Argument<FileInfo>("probe-object", "Path to the compiled .bpf.o object file.");
var probeTypeOpt = new Option<string>(
    "--probe-type",
    description: "Probe type: tracepoint|kprobe|kretprobe|usdt",
    getDefaultValue: () => "tracepoint");
var categoryOpt = new Option<string>("--category", "Tracepoint category (e.g. syscalls). Required for tracepoint probes.");
var nameOpt     = new Option<string>("--name",     "Probe name (e.g. sys_enter_openat).")
    { IsRequired = true };
var pidOpt      = new Option<int>("--pid",    getDefaultValue: () => -1, description: "PID filter (-1 = all).");
var limitOpt    = new Option<int>("--limit",  getDefaultValue: () => 50, description: "Stop after N events (0 = unlimited).");
var btfPathOpt  = new Option<FileInfo?>("--btf-path", "Custom BTF file path for CO-RE.");
var debugOpt    = new Option<bool>("--debug",  "Enable verbose libbpf debug output.");
var binaryOpt   = new Option<string?>("--binary", "Binary path for USDT probes.");
var providerOpt = new Option<string?>("--provider", "USDT provider name.");

traceCmd.AddArgument(probeObjArg);
traceCmd.AddOption(probeTypeOpt);
traceCmd.AddOption(categoryOpt);
traceCmd.AddOption(nameOpt);
traceCmd.AddOption(pidOpt);
traceCmd.AddOption(limitOpt);
traceCmd.AddOption(btfPathOpt);
traceCmd.AddOption(debugOpt);
traceCmd.AddOption(binaryOpt);
traceCmd.AddOption(providerOpt);

traceCmd.SetHandler(async (InvocationContext ctx) =>
{
    var probeObj   = ctx.ParseResult.GetValueForArgument(probeObjArg);
    string ptype   = ctx.ParseResult.GetValueForOption(probeTypeOpt)!;
    string? cat    = ctx.ParseResult.GetValueForOption(categoryOpt);
    string probeName = ctx.ParseResult.GetValueForOption(nameOpt)!;
    int pid        = ctx.ParseResult.GetValueForOption(pidOpt);
    int limit      = ctx.ParseResult.GetValueForOption(limitOpt);
    string? btfPath = ctx.ParseResult.GetValueForOption(btfPathOpt)?.FullName;
    bool debug     = ctx.ParseResult.GetValueForOption(debugOpt);
    string? binary = ctx.ParseResult.GetValueForOption(binaryOpt);
    string? provider = ctx.ParseResult.GetValueForOption(providerOpt);

    if (!probeObj.Exists)
    {
        Console.Error.WriteLine($"Error: probe object not found: {probeObj.FullName}");
        ctx.ExitCode = 1;
        return;
    }

    ProbeSpec probe = ptype.ToLowerInvariant() switch
    {
        "kprobe"    => new KprobeSpec    { FunctionName = probeName, ReturnProbe = false },
        "kretprobe" => new KprobeSpec    { FunctionName = probeName, ReturnProbe = true  },
        "usdt"      => new UsdtSpec
        {
            BinaryPath = binary
                ?? throw new InvalidOperationException("--binary is required for USDT probes."),
            Provider   = provider
                ?? throw new InvalidOperationException("--provider is required for USDT probes."),
            Name       = probeName,
            Pid        = pid,
        },
        _ => new TracepointSpec
        {
            Category = cat ?? throw new InvalidOperationException("--category is required for tracepoint probes."),
            Name     = probeName,
        },
    };

    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

    await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
    {
        ProbePath       = probeObj.FullName,
        Probes          = [probe],
        BtfCustomPath   = btfPath,
        DebugOutput     = debug,
        PollTimeoutMs   = 100,
    });

    Console.Error.WriteLine($"Session started. Streaming raw events (limit={limit})...");
    Console.Error.WriteLine("Press Ctrl+C to stop.");
    Console.Error.WriteLine();

    int count = 0;
    try
    {
        await foreach (var ev in session.ReadRawAsync(cts.Token))
        {
            string hex = Convert.ToHexString(ev.Span);
            Console.WriteLine($"{DateTimeOffset.UtcNow:O} {hex}");
            count++;

            if (limit > 0 && count >= limit)
            {
                cts.Cancel();
            }
        }
    }
    catch (OperationCanceledException) { }

    Console.Error.WriteLine($"\n{count} events received.");
});
root.AddCommand(traceCmd);

// ── map-dump ──────────────────────────────────────────────────────────────────
var mapDumpCmd  = new Command("map-dump", "Load a session and dump all entries of a named BPF map as hex key→value pairs.");
var mdObjArg    = new Argument<FileInfo>("probe-object", "Path to the compiled .bpf.o object file.");
var mdMapNameArg = new Argument<string>("map-name", "Name of the BPF map to dump.");
var mdProbeNameOpt = new Option<string>("--probe-name", "Probe name to attach (required to load the object).")
    { IsRequired = true };
var mdCatOpt    = new Option<string?>("--category", "Tracepoint category.");

mapDumpCmd.AddArgument(mdObjArg);
mapDumpCmd.AddArgument(mdMapNameArg);
mapDumpCmd.AddOption(mdProbeNameOpt);
mapDumpCmd.AddOption(mdCatOpt);

mapDumpCmd.SetHandler(async (InvocationContext ctx) =>
{
    var probeObj  = ctx.ParseResult.GetValueForArgument(mdObjArg);
    string mapName = ctx.ParseResult.GetValueForArgument(mdMapNameArg);
    string pName  = ctx.ParseResult.GetValueForOption(mdProbeNameOpt)!;
    string? cat   = ctx.ParseResult.GetValueForOption(mdCatOpt);

    if (!probeObj.Exists)
    {
        Console.Error.WriteLine($"Error: probe object not found: {probeObj.FullName}");
        ctx.ExitCode = 1;
        return;
    }

    ProbeSpec probe = cat is not null
        ? new TracepointSpec { Category = cat, Name = pName }
        : new KprobeSpec { FunctionName = pName, ReturnProbe = false };

    await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
    {
        ProbePath       = probeObj.FullName,
        Probes          = [probe],
        PollTimeoutMs   = 50,
    });

    var map = session.GetMap<uint, ulong>(mapName);

    Console.WriteLine($"Map: {mapName}");
    Console.WriteLine(new string('─', 50));

    int rows = 0;
    await foreach (var kvp in map.IterateAsync(CancellationToken.None))
    {
        Console.WriteLine($"  {kvp.Key:X8} → {kvp.Value:X16}");
        rows++;
    }

    Console.WriteLine(new string('─', 50));
    Console.WriteLine($"{rows} entries.");
});
root.AddCommand(mapDumpCmd);

// ── kallsyms-resolve ──────────────────────────────────────────────────────────
var ksCmd = new Command("kallsyms-resolve", "Resolve kernel addresses to symbol names using /proc/kallsyms.");
var ksAddrArg = new Argument<string[]>("addresses", "One or more kernel addresses in hex (e.g. ffffffff81234567).")
    { Arity = ArgumentArity.OneOrMore };
ksCmd.AddArgument(ksAddrArg);

ksCmd.SetHandler((string[] addrs) =>
{
    KernelSymbolResolver resolver;
    try
    {
        resolver = KernelSymbolResolver.Load();
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error loading /proc/kallsyms: {ex.Message}");
        return Task.FromResult(1);
    }

    Console.WriteLine($"Loaded {resolver.Count:N0} kernel symbols.");
    Console.WriteLine();

    foreach (string addrStr in addrs)
    {
        string normalized = addrStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? addrStr[2..]
            : addrStr;

        if (!ulong.TryParse(normalized, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
        {
            Console.WriteLine($"  {addrStr,-20} [invalid address]");
            continue;
        }

        string sym = resolver.Resolve(addr);
        Console.WriteLine($"  0x{addr:x16}  {sym}");
    }

    return Task.FromResult(0);
}, ksAddrArg);
root.AddCommand(ksCmd);

// ── Entry point ───────────────────────────────────────────────────────────────
return await root.InvokeAsync(args);
