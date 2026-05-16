using System.Diagnostics;
using System.Reflection;
using KernelTrace.Probes;
using KernelTrace.Sessions;

// ──────────────────────────────────────────────────────────────────────────────
//  DotNetRuntime — Sample
//  Attaches uprobes to the .NET CLR to trace GC, exceptions, and JIT events.
//
//  How it works:
//    1. Locate the running CLR (libcoreclr.so or libclrjit.so).
//    2. Resolve symbol offsets with `nm` / `objdump`.
//    3. Attach a named BPF program section per event type.
//
//  Requirements:
//    - Linux with kernel >= 5.8
//    - CAP_BPF capability (or run as root)
//    - Compiled eBPF object: ../../native/probes/dotnet_runtime.bpf.o
// ──────────────────────────────────────────────────────────────────────────────

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║       KernelTrace — .NET Runtime Tracer      ║");
Console.WriteLine("║  Press Ctrl+C to stop                        ║");
Console.WriteLine("╚══════════════════════════════════════════════╝");
Console.WriteLine();

// ── Locate the CLR shared library ──────────────────────────────────────────

string? clrPath = FindClrLibrary();
if (clrPath is null)
{
    Console.Error.WriteLine("ERROR: Cannot find libcoreclr.so in the current process maps.");
    Console.Error.WriteLine("       This sample must run on a Linux .NET process.");
    return 1;
}

Console.WriteLine($"CLR library: {clrPath}");

// ── Resolve symbol offsets ─────────────────────────────────────────────────
//
//  These symbols differ between CLR versions.  We use `nm` at runtime to
//  resolve the current binary.  The offsets are .bss-relative (file offsets).
//
//  If a symbol is not found, the corresponding probe is skipped.

ulong gcOffset        = ResolveSymbol(clrPath, "GarbageCollect");
ulong exceptionOffset = ResolveSymbol(clrPath, "RealCOMPlusThrow");
ulong jitOffset       = ResolveSymbol(clrPath, "MethodCompiled");

Console.WriteLine($"  GarbageCollect     offset: 0x{gcOffset:x}");
Console.WriteLine($"  RealCOMPlusThrow   offset: 0x{exceptionOffset:x}");
Console.WriteLine($"  MethodCompiled     offset: 0x{jitOffset:x}");
Console.WriteLine();

// ── Build probe list from resolved offsets ────────────────────────────────

var probes = new List<ProbeSpec>();

if (gcOffset != 0)
{
    probes.Add(new UprobeSpec
    {
        BinaryPath     = clrPath,
        Offset         = gcOffset,
        ProgramSection = "uprobe/dotnet_gc_start",
    });
    probes.Add(new UprobeSpec
    {
        BinaryPath     = clrPath,
        Offset         = gcOffset,
        ReturnProbe    = true,
        ProgramSection = "uretprobe/dotnet_gc_end",
    });
}

if (exceptionOffset != 0)
{
    probes.Add(new UprobeSpec
    {
        BinaryPath     = clrPath,
        Offset         = exceptionOffset,
        ProgramSection = "uprobe/dotnet_exception_thrown",
    });
}

if (jitOffset != 0)
{
    probes.Add(new UprobeSpec
    {
        BinaryPath     = clrPath,
        Offset         = jitOffset,
        ProgramSection = "uprobe/dotnet_method_jitted",
    });
}

if (probes.Count == 0)
{
    Console.Error.WriteLine("ERROR: No CLR symbols resolved.  Ensure the CLR has debug symbols.");
    return 2;
}

// ── Start the session ─────────────────────────────────────────────────────

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath       = Path.Combine(AppContext.BaseDirectory, "dotnet_runtime.bpf.o"),
    Probes          = [..probes],
    ChannelCapacity = 16_384,
    PollTimeoutMs   = 50,
});

Console.WriteLine($"Attached {probes.Count} probes.  Tracing CLR events ...");
Console.WriteLine();
Console.WriteLine($"{"TIME",-12} {"PID",-8} {"COMM",-16} EVENT");
Console.WriteLine(new string('─', 80));

// gc_event layout:   ts(8) duration(8) pid(4) tgid(4) gen(4) is_end(1) comm(16)
// exc_event layout:  ts(8) exc_ptr(8) pid(4) tgid(4) comm(16)
// method layout:     ts(8) method(8) pid(4) tgid(4) comm(16)
const int GcMin  = 8 + 8 + 4 + 4 + 4 + 1 + 16;
const int RwMin  = 8 + 8 + 4 + 4 + 16; // exc / method share same layout

await foreach (var rawEvent in session.ReadRawAsync(cts.Token))
{
    string time = DateTime.Now.ToString("HH:mm:ss.fff");
    var s = rawEvent.Span;

    if (rawEvent.Length >= GcMin)
    {
        int off = 0;
        ulong ts  = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[off..]); off += 8;
        ulong dur = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[off..]); off += 8;
        uint  pid = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[off..]); off += 4;
        off += 4;
        uint  gen = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[off..]); off += 4;
        bool  end = s[off] != 0; off++;
        string comm = ReadComm(s[off..]);
        string evName = end ? $"GC gen{gen} END  ({dur / 1_000_000.0:F2} ms)" : $"GC gen{gen} START";
        Console.WriteLine($"{time,-12} {pid,-8} {comm,-16} {evName}");
    }
    else if (rawEvent.Length >= RwMin)
    {
        int off = 0;
        ulong ts  = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[off..]); off += 8;
        ulong ptr = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[off..]); off += 8;
        uint  pid = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[off..]); off += 4;
        off += 4;
        string comm = ReadComm(s[off..]);
        // Distinguish by rough payload size convention.
        Console.WriteLine($"{time,-12} {pid,-8} {comm,-16} CLR event @ 0x{ptr:x}");
    }
}

return 0;

// ── Helpers ───────────────────────────────────────────────────────────────

static string? FindClrLibrary()
{
    try
    {
        string maps = File.ReadAllText($"/proc/{Environment.ProcessId}/maps");
        foreach (string line in maps.Split('\n'))
        {
            if (line.Contains("libcoreclr.so"))
            {
                int idx = line.IndexOf('/');
                if (idx >= 0)
                {
                    string path = line[idx..].Trim();
                    if (File.Exists(path))
                    {
                        return path;
                    }
                }
            }
        }
    }
    catch { /* ignore */ }
    return null;
}

static ulong ResolveSymbol(string library, string symbol)
{
    try
    {
        // nm -D <library> | grep " T <symbol>"
        using var p = Process.Start(new ProcessStartInfo("nm")
        {
            Arguments              = $"-D \"{library}\"",
            RedirectStandardOutput = true,
            UseShellExecute        = false,
        });
        if (p is null)
        {
            return 0;
        }

        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();

        foreach (string line in output.Split('\n'))
        {
            if (!line.Contains($" {symbol}"))
            {
                continue;
            }
            string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 3 && ulong.TryParse(parts[0], System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
            {
                return addr;
            }
        }
    }
    catch { /* nm not available */ }
    return 0;
}

static string ReadComm(ReadOnlySpan<byte> s)
{
    int end = s[..16].IndexOf((byte)0);
    return System.Text.Encoding.UTF8.GetString(end < 0 ? s[..16] : s[..end]);
}
