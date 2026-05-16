using KernelTrace.Probes;
using KernelTrace.Sessions;

// ──────────────────────────────────────────────────────────────────────────────
//  MemoryProfiler — Sample
//  Tracks kernel slab (kmalloc/kfree) and page allocator events live.
//  Shows: allocation accounting per call site, net-bytes tracking.
//
//  Requirements:
//    - Linux with kernel >= 5.8
//    - CAP_BPF capability (or run as root)
//    - Compiled eBPF object: ../../native/probes/memory_profiler.bpf.o
// ──────────────────────────────────────────────────────────────────────────────

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// Per call-site: net allocated bytes (positive = outstanding alloc).
var callSites = new Dictionary<ulong, long>();
long totalAlloc = 0, totalFree = 0, pageFaults = 0;

Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║       KernelTrace — Memory Profiler          ║");
Console.WriteLine("║  Press Ctrl+C to stop                        ║");
Console.WriteLine("╚══════════════════════════════════════════════╝");
Console.WriteLine();

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = Path.Combine(AppContext.BaseDirectory, "memory_profiler.bpf.o"),
    Probes =
    [
        new TracepointSpec { Category = "kmem", Name = "kmalloc"       },
        new TracepointSpec { Category = "kmem", Name = "kfree"         },
        new TracepointSpec { Category = "kmem", Name = "mm_page_alloc" },
        new TracepointSpec { Category = "kmem", Name = "mm_page_free"  },
        new KprobeSpec     { FunctionName = "handle_mm_fault"          },
    ],
    ChannelCapacity = 32_768,
    PollTimeoutMs   = 50,
});

Console.WriteLine($"Session started.");
Console.WriteLine();

// Report top call-sites by outstanding bytes every 3 s.
using var reportTimer = new PeriodicTimer(TimeSpan.FromSeconds(3));
var reportTask = Task.Run(async () =>
{
    while (await reportTimer.WaitForNextTickAsync(cts.Token).ConfigureAwait(false))
    {
        Console.Clear();
        Console.WriteLine($"  Total allocated: {totalAlloc / 1024,10} KiB");
        Console.WriteLine($"  Total freed:     {totalFree  / 1024,10} KiB");
        Console.WriteLine($"  Net outstanding: {(totalAlloc - totalFree) / 1024,10} KiB");
        Console.WriteLine($"  Page faults:     {pageFaults,10}");
        Console.WriteLine();
        Console.WriteLine($"  {"CALL SITE (hex)",-20} {"NET BYTES",14}");
        Console.WriteLine("  " + new string('─', 36));

        foreach (var (site, net) in callSites
                     .OrderByDescending(kv => kv.Value)
                     .Take(20))
        {
            Console.WriteLine($"  0x{site:x16}  {net,14:N0}");
        }
    }
}, cts.Token);

// kmalloc_event layout: ts(8) call_site(8) ptr(8) req(8) alloc(8) gfp(4) pid(4) comm(16) is_free(1)
const int KmallocMinSize = 8 + 8 + 8 + 8 + 8 + 4 + 4 + 16 + 1;
// page_alloc_event layout: ts(8) pfn(8) order(4) gfp(4) pid(4) is_free(1)
const int PageAllocSize  = 8 + 8 + 4 + 4 + 4 + 1;

await foreach (var rawEvent in session.ReadRawAsync(cts.Token))
{
    if (rawEvent.Length < PageAllocSize)
    {
        continue;
    }
    var s = rawEvent.Span;

    // Heuristic: kmalloc events carry a call_site pointer (8 bytes starting at offset 8).
    // Page alloc events are smaller and have pfn at offset 8.
    // We distinguish by size — kmalloc events are larger.
    if (rawEvent.Length >= KmallocMinSize)
    {
        // kmalloc_event
        ulong callSite  = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[8..]);
        ulong bytesReq  = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[24..]);
        bool  isFree    = s[KmallocMinSize - 1] != 0;

        if (isFree)
        {
            totalFree += (long)bytesReq;
            if (callSites.TryGetValue(callSite, out long prev))
            {
                callSites[callSite] = prev - (long)bytesReq;
            }
        }
        else
        {
            totalAlloc += (long)bytesReq;
            callSites.TryGetValue(callSite, out long prev);
            callSites[callSite] = prev + (long)bytesReq;
        }
    }
    else if (rawEvent.Length >= PageAllocSize)
    {
        // page_alloc_event or page_fault_event
        bool isFree = s[PageAllocSize - 1] != 0;
        if (!isFree)
        {
            uint order = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[16..]);
            long pageBytes = 4096L * (1L << (int)order);
            totalAlloc += pageBytes;
        }
        else
        {
            // Treat as page fault if the raw length equals the fault struct
            pageFaults++;
        }
    }
}

await reportTask.ConfigureAwait(false);
