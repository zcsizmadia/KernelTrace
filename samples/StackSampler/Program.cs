using System.Runtime.InteropServices;
using KernelTrace.Diagnostics;
using KernelTrace.Probes;
using KernelTrace.Sessions;

// ──────────────────────────────────────────────────────────────────────────────
//  StackSampler — Sample
//  Captures kernel + user-space stack traces on every openat() syscall and
//  symbolizes kernel frames using /proc/kallsyms.
//
//  Shows:
//    - BPF_MAP_TYPE_STACK_TRACE via KernelTraceSession.GetStackTraceMap()
//    - KernelSymbolResolver for /proc/kallsyms lookups
//    - Custom event struct with stack IDs
//
//  Requirements:
//    - Linux with kernel >= 5.8 and BTF support
//    - CAP_BPF + CAP_PERFMON (or root)
//    - Compiled eBPF object: stack_sampler.bpf.o
// ──────────────────────────────────────────────────────────────────────────────

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║      KernelTrace — Stack Sampler             ║");
Console.WriteLine("║  Traces openat() syscalls with stack frames  ║");
Console.WriteLine("║  Press Ctrl+C to stop                        ║");
Console.WriteLine("╚══════════════════════════════════════════════╝");
Console.WriteLine();

// Load /proc/kallsyms for kernel symbol resolution.
Console.Write("Loading kernel symbols from /proc/kallsyms ... ");
KernelSymbolResolver? resolver = null;
try
{
    resolver = KernelSymbolResolver.Load();
    Console.WriteLine($"{resolver.Count:N0} symbols loaded.");
}
catch (Exception ex)
{
    Console.WriteLine($"[warning] {ex.Message} — kernel frames will show raw addresses.");
}
Console.WriteLine();

string probePath = Path.Combine(AppContext.BaseDirectory, "stack_sampler.bpf.o");

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = probePath,
    Probes =
    [
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_openat" },
    ],
    ValidateStructLayouts = false,
    PollTimeoutMs         = 100,
});

// Grab the stack-trace map after the session is loaded.
var stackMap = session.GetStackTraceMap("stacks");

Console.WriteLine($"Stack depth supported: {stackMap.MaxDepth} frames");
Console.WriteLine();

int eventCount = 0;

try
{
    await foreach (var ev in session.ReadAsync<StackSampleEvent>(cts.Token))
    {
        eventCount++;

        string comm = ReadComm(ev);
        Console.WriteLine(
            $"[{ev.TimestampNs / 1_000_000:N0} ms] PID={ev.Pid,-6} COMM={comm,-16} " +
            $"kstack={ev.KernelStackId} ustack={ev.UserStackId}");

        // Symbolize the kernel stack.
        ulong[] kFrames = stackMap.Lookup(ev.KernelStackId);
        if (kFrames.Length > 0 && resolver is not null)
        {
            Console.WriteLine("  Kernel stack:");
            foreach (string sym in resolver.ResolveStack(kFrames))
            {
                Console.WriteLine($"    {sym}");
            }
        }

        Console.WriteLine();

        if (eventCount >= 20)
        {
            Console.WriteLine("Reached 20 events — stopping.");
            cts.Cancel();
        }
    }
}
catch (OperationCanceledException) { }

Console.WriteLine($"\nTotal events received: {eventCount}");
Console.WriteLine($"Session metrics: {session.Metrics.TotalReceived} received, " +
                  $"{session.Metrics.TotalDropped} dropped.");

// ── Helpers ───────────────────────────────────────────────────────────────────

static unsafe string ReadComm(in StackSampleEvent ev)
{
    fixed (byte* p = ev.Comm)
    {
        int len = 0;
        while (len < 16 && p[len] != 0)
        {
            len++;
        }

        return System.Text.Encoding.ASCII.GetString(p, len);
    }
}

// ── Event struct ──────────────────────────────────────────────────────────────
// Must match struct stack_sample_event in stack_sampler.bpf.c exactly.

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct StackSampleEvent
{
    public ulong    TimestampNs;
    public uint     Pid;
    public uint     Tgid;
    public int      KernelStackId;
    public int      UserStackId;
    public fixed byte Comm[16];
}
