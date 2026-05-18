using KernelTrace.Probes;
using KernelTrace.Sessions;
using System.Net;
using System.Runtime.InteropServices;

// ──────────────────────────────────────────────────────────────────────────────
//  CoreRelocations — Sample
//  Demonstrates CO-RE (Compile Once – Run Everywhere) support in KernelTrace:
//    - IsBtfAvailable()    — check at runtime whether the kernel exposes BTF
//    - SessionOptions.BtfCustomPath — supply an alternative BTF archive
//    - SessionOptions.DebugOutput  — enable verbose libbpf loader logging
//
//  The sample runs the same network_monitor.bpf.o probe that is used by the
//  NetworkMonitor sample.  The important difference is in the SessionOptions:
//  we check for BTF availability first and, if present, let CO-RE relocation
//  proceed normally.  If the kernel BTF is missing (common on older distros or
//  container images), we fall back to a BTF snapshot supplied as a file.
//
//  Requirements:
//    - Linux with kernel >= 5.8
//    - CAP_BPF capability (or run as root)
//    - Compiled eBPF object: network_monitor.bpf.o
//    - Optional: set env var BTF_PATH=/path/to/custom.btf to use a custom BTF
// ──────────────────────────────────────────────────────────────────────────────

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║    KernelTrace — CO-RE Relocations Sample    ║");
Console.WriteLine("║  Press Ctrl+C to stop                        ║");
Console.WriteLine("╚══════════════════════════════════════════════╝");
Console.WriteLine();

// ── CO-RE / BTF availability check ───────────────────────────────────────────

bool btfAvailable = KernelTraceSession.IsBtfAvailable();

Console.WriteLine($"Kernel BTF available : {btfAvailable}");

// Allow overriding with a custom BTF snapshot (e.g. from kernel-devel or btfhub).
string? customBtfPath = Environment.GetEnvironmentVariable("BTF_PATH");

if (!btfAvailable && customBtfPath is null)
{
    Console.WriteLine();
    Console.WriteLine("[warning] Kernel BTF not found and BTF_PATH is not set.");
    Console.WriteLine("          CO-RE relocations may fail for BTF-dependent programs.");
    Console.WriteLine("          Set BTF_PATH=/path/to/vmlinux.btf to supply a BTF archive.");
    Console.WriteLine("          Download snapshots from: https://github.com/aquasecurity/btfhub");
    Console.WriteLine();
}
else if (customBtfPath is not null)
{
    Console.WriteLine($"Custom BTF path      : {customBtfPath}");
}

// ── Session creation with CO-RE options ──────────────────────────────────────

string probePath = Path.Combine(AppContext.BaseDirectory, "network_monitor.bpf.o");

bool debugOutput = Environment.GetEnvironmentVariable("KT_DEBUG") == "1";

Console.WriteLine($"Debug output         : {debugOutput}");
Console.WriteLine($"eBPF object          : {probePath}");
Console.WriteLine();

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath     = probePath,
    Probes        =
    [
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" },
        new TracepointSpec { Category = "syscalls", Name = "sys_exit_connect" },
    ],
    // CO-RE options — the key new features demonstrated here.
    BtfCustomPath = customBtfPath,
    DebugOutput   = debugOutput,

    ChannelCapacity = 8_192,
    PollTimeoutMs   = 100,
});

Console.WriteLine("Session started successfully with CO-RE relocations applied.");
Console.WriteLine();
Console.WriteLine($"{"TIME",-12} {"PID",-8} {"COMM",-16} {"DST IP",-18} {"PORT",-8}");
Console.WriteLine(new string('─', 65));

int eventCount = 0;

try
{
    await foreach (var ev in session.ReadAsync<SocketConnectEvent>(cts.Token))
    {
        eventCount++;

        string time  = DateTime.Now.ToString("HH:mm:ss.fff");
        string dstIp = new IPAddress(BitConverter.GetBytes(ev.DstIp)).ToString();
        string comm  = ReadComm(ev);

        Console.WriteLine($"{time,-12} {ev.Pid,-8} {comm,-16} {dstIp,-18} {ev.DstPort,-8}");
    }
}
catch (OperationCanceledException) { }

Console.WriteLine();
Console.WriteLine($"Total events received: {eventCount}");
Console.WriteLine($"Session metrics: {session.Metrics.TotalReceived} received, " +
                  $"{session.Metrics.TotalDropped} dropped.");

// ── Helpers ───────────────────────────────────────────────────────────────────

static unsafe string ReadComm(in SocketConnectEvent ev)
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

// ── Event struct ────────────────────────────────────────────────
// Must match struct sock_connect_event in network_monitor.bpf.c exactly.

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct SocketConnectEvent
{
    public uint   Pid;
    public uint   SrcIp;
    public uint   DstIp;
    public ushort SrcPort;
    public ushort DstPort;
    public fixed byte Comm[16];
}
