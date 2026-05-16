using KernelTrace.Probes;
using KernelTrace.Sessions;

// ──────────────────────────────────────────────────────────────────────────────
//  KernelInternals — Sample
//  Live dashboard for IRQ latency, kernel lock contention, and CPU P/C-states.
//
//  Shows: per-IRQ latency stats, lock hot-spots, CPU frequency and idle events.
//
//  Requirements:
//    - Linux >= 5.14 for lock tracepoints; >= 5.8 for others
//    - CAP_BPF capability (or run as root)
//    - Compiled eBPF object: ../../native/probes/kernel_internals.bpf.o
// ──────────────────────────────────────────────────────────────────────────────

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// ── Event layouts (matching kernel_internals.bpf.c) ────────────────────────
//  irq_event:   ts(8) latency(8) irq(4) pid(4) event_type(1) softirq(1)
//  lock_event:  ts(8) latency(8) lock_addr(8) pid(4) flags(4) is_end(1)
//  power_event: ts(8) cpu_id(4) state(4) is_idle(1)

const int IrqSize   = 8 + 8 + 4 + 4 + 1 + 1;
const int LockSize  = 8 + 8 + 8 + 4 + 4 + 1;
const int PowerSize = 8 + 4 + 4 + 1;

// Per-IRQ latency accumulators (irq_nr → (count, sum_ns, max_ns))
var irqStats  = new Dictionary<uint, (long C, long Sum, long Max)>();
// Per-lock-addr contention accumulators (lock_addr → (count, sum_ns))
var lockStats = new Dictionary<ulong, (long C, long Sum)>();
// Last seen CPU frequency per cpu_id
var cpuFreq   = new Dictionary<uint, uint>();

Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║       KernelTrace — Kernel Internals         ║");
Console.WriteLine("║  Press Ctrl+C to stop                        ║");
Console.WriteLine("╚══════════════════════════════════════════════╝");
Console.WriteLine();

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = Path.Combine(AppContext.BaseDirectory, "kernel_internals.bpf.o"),
    Probes =
    [
        new TracepointSpec { Category = "irq",   Name = "irq_handler_entry"  },
        new TracepointSpec { Category = "irq",   Name = "irq_handler_exit"   },
        new TracepointSpec { Category = "irq",   Name = "softirq_entry"      },
        new TracepointSpec { Category = "irq",   Name = "softirq_exit"       },
        new TracepointSpec { Category = "lock",  Name = "contention_begin"   },
        new TracepointSpec { Category = "lock",  Name = "contention_end"     },
        new TracepointSpec { Category = "power", Name = "cpu_frequency"      },
        new TracepointSpec { Category = "power", Name = "cpu_idle"           },
    ],
    ChannelCapacity = 32_768,
    PollTimeoutMs   = 50,
});

Console.WriteLine("Capturing kernel internals events ...");

// Refresh dashboard every 2 seconds.
using var reportTimer = new PeriodicTimer(TimeSpan.FromSeconds(2));
var reportTask = Task.Run(async () =>
{
    while (await reportTimer.WaitForNextTickAsync(cts.Token).ConfigureAwait(false))
    {
        Console.Clear();
        Console.WriteLine("── IRQ Latency (top 10 by average) ─────────────────────────────");
        Console.WriteLine($"  {"IRQ",-8} {"COUNT",8} {"AVG µs",10} {"MAX µs",10}");
        foreach (var (irq, (c, sum, max)) in irqStats
                     .OrderByDescending(kv => kv.Value.Sum / Math.Max(kv.Value.C, 1))
                     .Take(10))
        {
            double avgUs = c > 0 ? sum / 1000.0 / c : 0;
            double maxUs = max / 1000.0;
            Console.WriteLine($"  {irq,-8} {c,8} {avgUs,10:F2} {maxUs,10:F2}");
        }

        Console.WriteLine();
        Console.WriteLine("── Lock Contention (top 10 by total wait) ───────────────────────");
        Console.WriteLine($"  {"LOCK ADDR",-20} {"COUNT",8} {"TOTAL µs",12} {"AVG µs",10}");
        foreach (var (addr, (c, sum)) in lockStats
                     .OrderByDescending(kv => kv.Value.Sum)
                     .Take(10))
        {
            double totalUs = sum / 1000.0;
            double avgUs   = c > 0 ? totalUs / c : 0;
            Console.WriteLine($"  0x{addr,-18:x} {c,8} {totalUs,12:F0} {avgUs,10:F2}");
        }

        Console.WriteLine();
        Console.WriteLine("── CPU Frequency ────────────────────────────────────────────────");
        foreach (var (cpu, khz) in cpuFreq.OrderBy(kv => kv.Key))
        {
            Console.WriteLine($"  CPU {cpu}: {khz / 1000.0:F0} MHz");
        }
    }
}, cts.Token);

await foreach (var rawEvent in session.ReadRawAsync(cts.Token))
{
    var s = rawEvent.Span;

    if (rawEvent.Length >= LockSize && s[LockSize - 1] != 255 /* is_end present */)
    {
        // Distinguish by size: lock > irq > power
        if (rawEvent.Length >= LockSize + 1 && rawEvent.Length > IrqSize + 1)
        {
            // lock_event
            ulong latency  = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[8..]);
            ulong lockAddr = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[16..]);
            bool  isEnd    = s[LockSize - 1] != 0;

            if (isEnd && latency > 0)
            {
                lockStats.TryGetValue(lockAddr, out var ls);
                lockStats[lockAddr] = (ls.C + 1, ls.Sum + (long)latency);
            }
            continue;
        }
    }

    if (rawEvent.Length >= IrqSize)
    {
        ulong latency  = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[8..]);
        uint  irqNr    = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[16..]);
        byte  evType   = s[20]; // event_type

        // Only accumulate on exit events (odd types: 1=IRQ_EXIT, 3=SOFTIRQ_EXIT).
        if ((evType & 1) == 1 && latency > 0)
        {
            irqStats.TryGetValue(irqNr, out var ist);
            long newMax = latency > (ulong)ist.Max ? (long)latency : ist.Max;
            irqStats[irqNr] = (ist.C + 1, ist.Sum + (long)latency, newMax);
        }
        continue;
    }

    if (rawEvent.Length >= PowerSize)
    {
        // power_event
        uint cpuId  = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[8..]);
        uint state  = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[12..]);
        bool isIdle = s[16] != 0;

        if (!isIdle)
        {
            cpuFreq[cpuId] = state; // kHz
        }
    }
}

await reportTask.ConfigureAwait(false);
