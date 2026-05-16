using KernelTrace.Probes;
using KernelTrace.Sessions;

// ──────────────────────────────────────────────────────────────────────────────
//  ContainerMonitor — Sample
//  Attributes kernel events to containers using cgroup v2 IDs.
//  Resolves cgroup IDs to container names by reading /sys/fs/cgroup.
//
//  Shows: cgroup-based container attribution, execve/connect/fork/exit tracking.
//
//  Requirements:
//    - Linux with kernel >= 5.8 and cgroup v2 enabled
//    - CAP_BPF capability (or run as root)
//    - Compiled eBPF object: ../../native/probes/container_monitor.bpf.o
// ──────────────────────────────────────────────────────────────────────────────

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// Build cgroup-id → container-name cache from /sys/fs/cgroup.
var cgroupNames = BuildCgroupCache();

Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║       KernelTrace — Container Monitor        ║");
Console.WriteLine("║  Press Ctrl+C to stop                        ║");
Console.WriteLine("╚══════════════════════════════════════════════╝");
Console.WriteLine();
Console.WriteLine($"  Resolved {cgroupNames.Count} cgroup entries.");
Console.WriteLine();

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = Path.Combine(AppContext.BaseDirectory, "container_monitor.bpf.o"),
    Probes =
    [
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_execve"   },
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect"  },
        new TracepointSpec { Category = "sched",    Name = "sched_process_fork" },
        new TracepointSpec { Category = "sched",    Name = "sched_process_exit" },
    ],
    ChannelCapacity = 32_768,
    PollTimeoutMs   = 50,
});

Console.WriteLine($"{"TIME",-12} {"CGROUP / CONTAINER",-32} {"PID",-8} {"COMM",-16} {"EVENT",-8} DETAIL");
Console.WriteLine(new string('─', 110));

// container_event layout:
//   ts(8) cgroup_id(8) pid(4) tgid(4) ppid(4) uid(4) event_type(1) comm(16) filename(256)
const int HeaderSize = 8 + 8 + 4 + 4 + 4 + 4 + 1 + 16;
const int EventSize  = HeaderSize + 256;

string[] typeNames = ["EXECVE", "CONNECT", "FORK", "EXIT"];

await foreach (var rawEvent in session.ReadRawAsync(cts.Token))
{
    if (rawEvent.Length < HeaderSize)
    {
        continue;
    }
    var s = rawEvent.Span;

    int off = 0;
    ulong ts      = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[off..]); off += 8;
    ulong cgId    = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[off..]); off += 8;
    uint  pid     = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[off..]); off += 4;
    off += 4; // tgid
    off += 4; // ppid
    off += 4; // uid
    byte  evType  = s[off]; off++;
    string comm   = ReadStr(s[off..], 16); off += 16;

    string evName = evType < typeNames.Length ? typeNames[evType] : $"?{evType}";
    string detail = "";
    if (evType == 0 && rawEvent.Length >= EventSize) // EXECVE
        detail = ReadStr(s[off..], 256);

    string containerName = cgroupNames.TryGetValue(cgId, out string? n) ? n : $"cg:{cgId}";
    string time = DateTime.Now.ToString("HH:mm:ss.fff");

    Console.WriteLine($"{time,-12} {containerName,-32} {pid,-8} {comm,-16} {evName,-8} {detail}");
}

// ── Helpers ───────────────────────────────────────────────────────────────

static Dictionary<ulong, string> BuildCgroupCache()
{
    var result = new Dictionary<ulong, string>();
    try
    {
        // Walk /sys/fs/cgroup looking for cgroup.controllers files.
        // The directory name is used as the container label.
        foreach (string dir in Directory.EnumerateDirectories("/sys/fs/cgroup", "*", SearchOption.AllDirectories))
        {
            string idFile = Path.Combine(dir, "cgroup.id");
            if (!File.Exists(idFile))
            {
                continue;
            }

            if (ulong.TryParse(File.ReadAllText(idFile).Trim(), out ulong id))
            {
                result[id] = Path.GetFileName(dir);
            }
        }
    }
    catch { /* cgroup v2 may not be mounted */ }
    return result;
}

static string ReadStr(ReadOnlySpan<byte> s, int max)
{
    int len = Math.Min(max, s.Length);
    int end = s[..len].IndexOf((byte)0);
    return System.Text.Encoding.UTF8.GetString(end < 0 ? s[..len] : s[..end]);
}
