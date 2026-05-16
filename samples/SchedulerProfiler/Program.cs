using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using KernelTrace.Events;
using KernelTrace.Probes;
using KernelTrace.Sessions;

// ──────────────────────────────────────────────────────────────────────────────
//  SchedulerProfiler — Sample
//  Listens to sched_switch events and builds a live table of per-process
//  off-CPU time. Refreshes the console every second.
//
//  This demonstrates:
//    - ProcessAsync<T> zero-copy API
//    - Aggregating kernel events in-process
//    - Real-time console reporting with TimeProvider
// ──────────────────────────────────────────────────────────────────────────────

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// Per-PID stats: accumulated off-CPU nanoseconds.
var offCpuNs = new ConcurrentDictionary<uint, long>();
// Track when each PID was last descheduled.
var descheduledAt = new ConcurrentDictionary<uint, ulong>();

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = Path.Combine(AppContext.BaseDirectory, "scheduler_profiler.bpf.o"),
    Probes    = [new TracepointSpec { Category = "sched", Name = "sched_switch" }],
    ChannelCapacity = 131_072,   // 128K — scheduler is very chatty
    PollTimeoutMs   = 10,
    PollingThreadPriority = System.Threading.ThreadPriority.Highest,
});

// Background: print report every second.
var reportTimer = new Timer(_ => PrintReport(offCpuNs), null,
    TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));

// Foreground: consume events zero-copy via ProcessAsync.
await session.ProcessAsync<SchedSwitchEvent>(
    handler: (in SchedSwitchEvent ev, CancellationToken ct) =>
    {
        ulong now = ev.Timestamp;

        // PID being scheduled OUT → record when it was put to sleep.
        descheduledAt[ev.PrevPid] = now;

        // PID being scheduled IN → accumulate its off-CPU time.
        if (descheduledAt.TryRemove(ev.NextPid, out ulong sleptAt))
        {
            ulong elapsed = now > sleptAt ? now - sleptAt : 0UL;
            offCpuNs.AddOrUpdate(ev.NextPid,
                addValue: (long)elapsed,
                updateValueFactory: (_, existing) => existing + (long)elapsed);
        }

        return ValueTask.CompletedTask;
    },
    cancellationToken: cts.Token);

await reportTimer.DisposeAsync();

// ── Reporting ─────────────────────────────────────────────────────────────────

static void PrintReport(ConcurrentDictionary<uint, long> stats)
{
    Console.Clear();
    Console.WriteLine("╔══════════════════════════════════════════════════╗");
    Console.WriteLine("║   KernelTrace — Off-CPU Profiler (sched_switch)  ║");
    Console.WriteLine($"║   {DateTime.Now:HH:mm:ss}  |  Press Ctrl+C to stop           ║");
    Console.WriteLine("╚══════════════════════════════════════════════════╝");
    Console.WriteLine();
    Console.WriteLine($"{"PID",-10} {"Off-CPU Time (ms)",-20}");
    Console.WriteLine(new string('─', 32));

    foreach (var (pid, ns) in stats.OrderByDescending(x => x.Value).Take(20))
    {
        double ms = ns / 1_000_000.0;
        Console.WriteLine($"{pid,-10} {ms,18:F3}");
    }
}

// ── Event struct ──────────────────────────────────────────────────────────────

/// <summary>
/// Emitted by the kernel on every context switch (<c>sched_switch</c> tracepoint).
/// </summary>
[KernelEvent("sched_switch_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public partial struct SchedSwitchEvent
{
    /// <summary>Kernel monotonic timestamp (nanoseconds).</summary>
    public ulong Timestamp;

    /// <summary>PID of the process being switched out.</summary>
    public uint PrevPid;

    /// <summary>PID of the process being switched in.</summary>
    public uint NextPid;

    /// <summary>CPU core this switch occurred on.</summary>
    public uint CpuId;
}
