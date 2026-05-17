using System.Runtime.InteropServices;
using KernelTrace.Events;
using KernelTrace.Probes;
using KernelTrace.Sessions;

// ──────────────────────────────────────────────────────────────────────────────
//  SecurityGuard — Sample
//  Hooks execve syscall entries to detect execution of suspicious binaries.
//  Demonstrates kprobe attachment and security-relevant event correlation.
//
//  Requirements:
//    - Linux with kernel >= 5.8
//    - CAP_BPF or root
//    - Compiled eBPF object: security_guard.bpf.o
// ──────────────────────────────────────────────────────────────────────────────

// ── Suspicious executable patterns to flag. ───────────────────────────────────
string[] suspiciousPatterns =
[
    "/bin/nc", "/usr/bin/nc",          // netcat
    "/bin/ncat", "/usr/bin/ncat",
    "/usr/bin/wget", "/usr/bin/curl",
    "perl -e", "python -c",           // one-liners
    "/tmp/",                          // execution from /tmp is suspicious
    "/dev/shm/",                      // execution from tmpfs
];

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

Console.WriteLine("╔═════════════════════════════════════════╗");
Console.WriteLine("║   KernelTrace — Security Guard          ║");
Console.WriteLine("║   Monitoring execve calls...            ║");
Console.WriteLine("║   Press Ctrl+C to stop                  ║");
Console.WriteLine("╚═════════════════════════════════════════╝");
Console.WriteLine();

int alertCount = 0;

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = Path.Combine(AppContext.BaseDirectory, "security_guard.bpf.o"),
    Probes =
    [
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_execve" },
    ],
    ChannelCapacity = 32_768,
    PollTimeoutMs   = 10,
});

try
{
await foreach (var ev in session.ReadAsync<ExecveEvent>(cts.Token))
{
    unsafe
    {
        string filename = ReadString(ev.Filename, 256);
        string comm     = ReadString(ev.Comm,     16);
        string time     = DateTime.Now.ToString("HH:mm:ss.fff");

        bool suspicious = suspiciousPatterns.Any(p =>
            filename.Contains(p, StringComparison.OrdinalIgnoreCase));

        if (suspicious)
        {
            Interlocked.Increment(ref alertCount);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"🚨 ALERT #{alertCount}  [{time}]  PID={ev.Pid}  PPID={ev.Ppid}  COMM={comm}");
            Console.WriteLine($"   EXEC: {filename}");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"   [{time}]  PID={ev.Pid}  COMM={comm}  EXEC={filename}");
            Console.ResetColor();
        }
    }
}
}
catch (OperationCanceledException) { }

Console.WriteLine($"\nMonitoring stopped. Total alerts: {alertCount}");

// ── Helpers ───────────────────────────────────────────────────────────────────

static unsafe string ReadString(byte* ptr, int maxLen)
{
    int len = 0;
    while (len < maxLen && ptr[len] != 0)
    {
        len++;
    }
    return System.Text.Encoding.UTF8.GetString(ptr, len);
}

// ── Event struct ──────────────────────────────────────────────────────────────

/// <summary>
/// Emitted by <c>sys_enter_execve</c> / <c>do_execve</c> kprobe.
/// Carries the calling process identity and the filename being executed.
/// </summary>
[KernelEvent("execve_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe partial struct ExecveEvent
{
    /// <summary>Kernel monotonic timestamp (ns).</summary>
    public ulong Timestamp;

    /// <summary>Process ID of the caller.</summary>
    public uint Pid;

    /// <summary>Parent process ID.</summary>
    public uint Ppid;

    /// <summary>User ID of the calling process.</summary>
    public uint Uid;

    /// <summary>Group ID of the calling process.</summary>
    public uint Gid;

    /// <summary>Return value (only valid on kretprobe variant).</summary>
    public int ReturnCode;

    /// <summary>Command name of the calling process (not the exec'd binary).</summary>
    public fixed byte Comm[16];

    /// <summary>Path of the binary being executed.</summary>
    public fixed byte Filename[256];
}
