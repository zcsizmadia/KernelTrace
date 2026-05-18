using KernelTrace.Probes;
using KernelTrace.Sessions;

// ──────────────────────────────────────────────────────────────────────────────
//  BlockIoAnalyzer — Sample
//  Correlates block request issue and completion to measure per-device latency.
//  Shows: latency histogram per device, separate read/write breakdown.
//
//  Requirements:
//    - Linux with kernel >= 5.8
//    - CAP_BPF capability (or run as root)
//    - Compiled eBPF object: ../../native/probes/block_io.bpf.o
// ──────────────────────────────────────────────────────────────────────────────

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// Per-device stats: major<<8|minor → (read count, read sum ns, write count, write sum ns)
var stats = new Dictionary<uint, (long RC, long RS, long WC, long WS)>();

Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║       KernelTrace — Block I/O Analyzer       ║");
Console.WriteLine("║  Press Ctrl+C to stop                        ║");
Console.WriteLine("╚══════════════════════════════════════════════╝");
Console.WriteLine();

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = Path.Combine(AppContext.BaseDirectory, "block_io.bpf.o"),
    Probes =
    [
        new TracepointSpec { Category = "block", Name = "block_rq_issue"    },
        new TracepointSpec { Category = "block", Name = "block_rq_complete" },
    ],
    ChannelCapacity = 32_768,
    PollTimeoutMs   = 50,
});

Console.WriteLine("Capturing block I/O events ...");
Console.WriteLine();

using var reportTimer = new PeriodicTimer(TimeSpan.FromSeconds(2));
var reportTask = Task.Run(async () =>
{
    while (await reportTimer.WaitForNextTickAsync(cts.Token).ConfigureAwait(false))
    {
        Console.Clear();
        Console.WriteLine($"  {"DEVICE",-10} {"READS",8} {"AVG READ µs",14} {"WRITES",8} {"AVG WRITE µs",14}");
        Console.WriteLine("  " + new string('─', 58));

        foreach (var (dev, (rc, rs, wc, ws)) in stats.OrderBy(kv => kv.Key))
        {
            uint major = dev >> 8, minor = dev & 0xFF;
            string devName = $"{major}:{minor}";
            double avgRead  = rc > 0 ? rs / 1000.0 / rc : 0;
            double avgWrite = wc > 0 ? ws / 1000.0 / wc : 0;
            Console.WriteLine($"  {devName,-10} {rc,8} {avgRead,14:F1} {wc,8} {avgWrite,14:F1}");
        }
    }
}, cts.Token);

// block_rq_event layout (matches block_io.bpf.c):
//   ts(8) latency(8) sector(8) dev(4) nr_sector(4) bytes(4) pid(4) rwbs(8) comm(16) is_write(1)
const int EventSize = 8 + 8 + 8 + 4 + 4 + 4 + 4 + 8 + 16 + 1;

try
{
await foreach (var rawEvent in session.ReadRawAsync(cts.Token))
{
    if (rawEvent.Length < EventSize)
    {
        continue;
    }
    var s = rawEvent.Span;
    int off = 0;
    off += 8; // skip timestamp
    ulong latency = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[off..]); off += 8;
    off += 8; // skip sector
    uint  dev     = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[off..]); off += 4;
    off += 4 + 4 + 4 + 8 + 16; // nr_sector, bytes, pid, rwbs, comm
    bool  isWrite = s[off] != 0;

    stats.TryGetValue(dev, out var cur);
    stats[dev] = isWrite
        ? (cur.RC, cur.RS, cur.WC + 1, cur.WS + (long)latency)
        : (cur.RC + 1, cur.RS + (long)latency, cur.WC, cur.WS);
}
}
catch (OperationCanceledException) { }

try { await reportTask.ConfigureAwait(false); }
catch (OperationCanceledException) { }
