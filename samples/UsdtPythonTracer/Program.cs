using System.Runtime.InteropServices;
using KernelTrace.Probes;
using KernelTrace.Sessions;

// ──────────────────────────────────────────────────────────────────────────────
//  UsdtPythonTracer — Sample
//  Attaches to the Python 3 `function__entry` USDT probe and prints every
//  Python function call in real time.
//
//  Shows:
//    - UsdtSpec — attaching to a user-space USDT probe point
//    - Filtering by PID (or -1 for all processes)
//    - Reading mixed C string fields from BPF ring-buffer events
//
//  Requirements:
//    - Linux with kernel >= 5.8 and BTF support
//    - CAP_BPF + CAP_PERFMON (or root)
//    - Python 3 compiled with USDT probes (python3-dbg on Debian/Ubuntu)
//    - Compiled eBPF object: usdt_python.bpf.o
//    - Optional: set env var PYTHON_PID=<pid> to trace a single process
// ──────────────────────────────────────────────────────────────────────────────

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// Optional: restrict to a specific Python PID.
int targetPid = -1;  // -1 = all processes
if (Environment.GetEnvironmentVariable("PYTHON_PID") is { } pidStr &&
    int.TryParse(pidStr, out int parsedPid))
{
    targetPid = parsedPid;
}

Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║     KernelTrace — USDT Python Tracer         ║");
Console.WriteLine("║  Traces Python function__entry USDT probes   ║");
Console.WriteLine("║  Press Ctrl+C to stop                        ║");
Console.WriteLine("╚══════════════════════════════════════════════╝");
Console.WriteLine();

if (targetPid > 0)
{
    Console.WriteLine($"Restricting trace to PID {targetPid}.");
}
else
{
    Console.WriteLine("Tracing all Python processes. " +
                      "Set PYTHON_PID=<pid> to restrict to one process.");
}
Console.WriteLine();

// Detect the Python 3 interpreter path (used for the USDT binary path).
string pythonBinary = FindPythonBinary();
Console.WriteLine($"Python binary: {pythonBinary}");

string probePath = Path.Combine(AppContext.BaseDirectory, "usdt_python.bpf.o");

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = probePath,
    Probes =
    [
        // Attach to the function__entry USDT probe in the Python interpreter.
        new UsdtSpec
        {
            BinaryPath     = pythonBinary,
            Provider       = "python",
            Name           = "function__entry",
            ProgramSection = "usdt/python:function__entry",
            Pid            = targetPid,
        },
    ],
    ValidateStructLayouts = false,
    PollTimeoutMs         = 100,
});

Console.WriteLine($"Session started. Waiting for Python function calls...");
Console.WriteLine();
Console.WriteLine($"{"TIME",-12} {"PID",-8} {"FILE",-40} {"FUNCTION",-30} LINE");
Console.WriteLine(new string('─', 95));

int eventCount = 0;

try
{
    await foreach (var ev in session.ReadAsync<PythonCallEvent>(cts.Token))
    {
        eventCount++;

        string time     = DateTime.Now.ToString("HH:mm:ss.fff");
        string filename = ReadCString(ev.Filename, 64);
        string funcname = ReadCString(ev.Funcname, 64);

        // Shorten long filenames for display.
        if (filename.Length > 39)
        {
            filename = "..." + filename[^36..];
        }

        Console.WriteLine($"{time,-12} {ev.Pid,-8} {filename,-40} {funcname,-30} {ev.Lineno}");
    }
}
catch (OperationCanceledException) { }

Console.WriteLine();
Console.WriteLine($"Total events received: {eventCount}");
Console.WriteLine($"Session metrics: {session.Metrics.TotalReceived} received, " +
                  $"{session.Metrics.TotalDropped} dropped.");

// ── Helpers ───────────────────────────────────────────────────────────────────

static string FindPythonBinary()
{
    // Look for python3 in PATH.
    foreach (string dir in (Environment.GetEnvironmentVariable("PATH") ?? "")
                           .Split(':', StringSplitOptions.RemoveEmptyEntries))
    {
        string candidate = Path.Combine(dir, "python3");
        if (File.Exists(candidate))
        {
            return candidate;
        }
    }

    return "/usr/bin/python3";
}

static unsafe string ReadCString(ReadOnlySpan<byte> span, int maxLen)
{
    int len = 0;
    while (len < span.Length && len < maxLen && span[len] != 0)
    {
        len++;
    }

    return System.Text.Encoding.UTF8.GetString(span[..len]);
}

// ── Event struct ──────────────────────────────────────────────────────────────
// Must match struct python_call_event in usdt_python.bpf.c exactly.

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct PythonCallEvent
{
    public ulong    TimestampNs;
    public uint     Pid;
    public uint     Tgid;
    public fixed byte _filename[64];
    public fixed byte _funcname[64];
    public int      Lineno;
    public uint     _pad;

    public ReadOnlySpan<byte> Filename =>
        MemoryMarshal.CreateReadOnlySpan(ref _filename[0], 64);

    public ReadOnlySpan<byte> Funcname =>
        MemoryMarshal.CreateReadOnlySpan(ref _funcname[0], 64);
}
