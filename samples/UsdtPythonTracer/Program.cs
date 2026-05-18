using System.Diagnostics;
using System.Runtime.InteropServices;
using KernelTrace.Probes;
using KernelTrace.Sessions;

// ──────────────────────────────────────────────────────────────────────────────
//  UsdtPythonTracer — Sample
//  Attaches to the Python 3 `gc__start` and `gc__done` USDT probes and prints
//  every Python garbage-collection cycle in real time.
//
//  These probes are present in every standard CPython 3.x binary that was
//  built with USDT support (all Debian/Ubuntu packages include them).
//  The function__entry / function__return probes require python3-dbg and are
//  NOT used here.
//
//  Shows:
//    - UsdtSpec — attaching to multiple user-space USDT probe points
//    - Filtering by PID (or -1 for all processes)
//    - A self-driven Python GC subprocess so events are always visible
//
//  Requirements:
//    - Linux with kernel >= 5.8 and BTF support
//    - CAP_BPF + CAP_PERFMON (or root)
//    - Python 3 with USDT probes compiled in (standard packages work)
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
Console.WriteLine("║  Traces Python gc__start / gc__done probes   ║");
Console.WriteLine("║  Press Ctrl+C to stop                        ║");
Console.WriteLine("╚══════════════════════════════════════════════╝");
Console.WriteLine();

if (targetPid > 0)
    Console.WriteLine($"Restricting trace to PID {targetPid}.");
else
    Console.WriteLine("Tracing all Python processes. Set PYTHON_PID=<pid> to restrict to one process.");

Console.WriteLine();

string pythonBinary = FindPythonBinary();
Console.WriteLine($"Python binary: {pythonBinary}");

string probePath = Path.Combine(AppContext.BaseDirectory, "usdt_python.bpf.o");

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = probePath,
    Probes =
    [
        // gc__start fires when a GC cycle begins; arg0 = generation (0/1/2).
        new UsdtSpec
        {
            BinaryPath     = pythonBinary,
            Provider       = "python",
            Name           = "gc__start",
            ProgramSection = "usdt/python:gc__start",
            Pid            = targetPid,
        },
        // gc__done fires when a GC cycle ends; arg0 = number of objects collected.
        new UsdtSpec
        {
            BinaryPath     = pythonBinary,
            Provider       = "python",
            Name           = "gc__done",
            ProgramSection = "usdt/python:gc__done",
            Pid            = targetPid,
        },
    ],
    ValidateStructLayouts = false,
    PollTimeoutMs         = 100,
});

// Spawn a Python subprocess that generates GC events so there is always
// something to observe in the trace output.
using var gcDriver = SpawnGcDriver(pythonBinary, cts.Token);

Console.WriteLine("Session started. Waiting for Python GC events...");
Console.WriteLine();
Console.WriteLine($"{"TIME",-12} {"PID",-8} {"EVENT",-12} {"GEN / COLLECTED",-20}");
Console.WriteLine(new string('─', 55));

int eventCount = 0;

try
{
    await foreach (var ev in session.ReadAsync<PythonGcEvent>(cts.Token))
    {
        eventCount++;

        string time  = DateTime.Now.ToString("HH:mm:ss.fff");
        string kind  = ev.IsEnd == 0 ? "GC START" : "GC DONE";
        string label = ev.IsEnd == 0 ? $"gen {ev.Value}" : $"{ev.Value} collected";

        Console.WriteLine($"{time,-12} {ev.Pid,-8} {kind,-12} {label,-20}");
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
    foreach (string dir in (Environment.GetEnvironmentVariable("PATH") ?? "")
                           .Split(':', StringSplitOptions.RemoveEmptyEntries))
    {
        string candidate = Path.Combine(dir, "python3");
        if (File.Exists(candidate))
            return candidate;
    }
    return "/usr/bin/python3";
}

// Starts a background Python process that repeatedly triggers GC so events
// are always visible in the trace output.
static Process? SpawnGcDriver(string pythonBinary, CancellationToken ct)
{
    const string script =
        "import gc, time\n" +
        "while True:\n" +
        "    gc.collect(0)\n" +
        "    gc.collect(1)\n" +
        "    gc.collect(2)\n" +
        "    time.sleep(0.5)\n";

    var psi = new ProcessStartInfo(pythonBinary, ["-c", script])
    {
        RedirectStandardOutput = true,
        RedirectStandardError  = true,
        UseShellExecute        = false,
    };

    try
    {
        var proc = Process.Start(psi);
        if (proc is not null)
            ct.Register(() => { try { proc.Kill(); } catch { } });
        return proc;
    }
    catch
    {
        return null;   // Python not available — events from other processes may still arrive.
    }
}

// ── Event struct ──────────────────────────────────────────────────────────────
// Must match struct python_gc_event in usdt_python.bpf.c exactly.

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct PythonGcEvent
{
    public ulong TimestampNs;   // offset  0, size 8
    public uint  Pid;           // offset  8, size 4
    public uint  Tgid;          // offset 12, size 4
    public long  Value;         // offset 16, size 8  (generation or collected count)
    public byte  IsEnd;         // offset 24, size 1  (0 = gc__start, 1 = gc__done)
    private fixed byte _pad[7]; // offset 25, size 7  (pad to 32 bytes)
}
