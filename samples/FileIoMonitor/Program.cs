using KernelTrace.Events;
using KernelTrace.Probes;
using KernelTrace.Sessions;

// ──────────────────────────────────────────────────────────────────────────────
//  FileIoMonitor — Sample
//  Streams file open/read/write events with per-call latency.
//  Shows: syscall latency measurement, filename capture, hot-file ranking.
//
//  Requirements:
//    - Linux with kernel >= 5.8
//    - CAP_BPF capability (or run as root)
//    - Compiled eBPF object: ../../native/probes/fs_io.bpf.o
// ──────────────────────────────────────────────────────────────────────────────

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║       KernelTrace — File I/O Monitor         ║");
Console.WriteLine("║  Press Ctrl+C to stop                        ║");
Console.WriteLine("╚══════════════════════════════════════════════╝");
Console.WriteLine();

// Top-N slowest open calls: filename → max latency in µs.
var slowestOpens = new SortedDictionary<ulong, string>(Comparer<ulong>.Create((a, b) => b.CompareTo(a)));
var openCount = 0;

await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
{
    ProbePath = Path.Combine(AppContext.BaseDirectory, "fs_io.bpf.o"),
    Probes =
    [
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_openat" },
        new TracepointSpec { Category = "syscalls", Name = "sys_exit_openat"  },
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_read"   },
        new TracepointSpec { Category = "syscalls", Name = "sys_exit_read"    },
        new TracepointSpec { Category = "syscalls", Name = "sys_enter_write"  },
        new TracepointSpec { Category = "syscalls", Name = "sys_exit_write"   },
    ],
    ChannelCapacity = 32_768,
    PollTimeoutMs   = 50,
});

Console.WriteLine($"{"TIME",-12} {"PID",-8} {"COMM",-16} {"TYPE",-6} {"LATENCY µs",-12} {"FD/BYTES",-10} FILENAME/FLAGS");
Console.WriteLine(new string('─', 100));

// Periodic top-20 slow opens report every 5 seconds.
using var reportTimer = new PeriodicTimer(TimeSpan.FromSeconds(5));
var reportTask = Task.Run(async () =>
{
    while (await reportTimer.WaitForNextTickAsync(cts.Token).ConfigureAwait(false))
    {
        if (slowestOpens.Count == 0)
        {
            continue;
        }
        Console.WriteLine();
        Console.WriteLine("  ── Top slowest openat calls ──────────────────────────────");
        int rank = 1;
        foreach (var (latUs, file) in slowestOpens)
        {
            Console.WriteLine($"  {rank,2}. {latUs,10} µs  {file}");
            if (++rank > 20)
            {
                break;
            }
        }
        Console.WriteLine();
    }
}, cts.Token);

await foreach (var rawEvent in session.ReadRawAsync(cts.Token))
{
    // The source generator emits [KernelEvent] structs from the eBPF C structs.
    // For this sample we read tagged union by inspecting payload size.
    // A real app would define [KernelEvent] records and call ReadAsync<T>().

    string time = DateTime.Now.ToString("HH:mm:ss.fff");

    // fs_open_event is the larger struct (has filename[]).
    if (rawEvent.Length >= FsOpenEvent.MinSize)
    {
        var ev = FsOpenEvent.FromBytes(rawEvent);
        string comm = ReadNullTerminated(ev.Comm.Span, 16);
        string filename = ReadNullTerminated(ev.Filename.Span, 256);
        ulong latUs = ev.LatencyNs / 1_000;

        Console.WriteLine($"{time,-12} {ev.Pid,-8} {comm,-16} {"OPEN",-6} {latUs,-12} {ev.RetFd,-10} {filename}");
        openCount++;
        // Keep track of the top-100 slowest opens (no duplicates per latency).
        if (!slowestOpens.ContainsKey(ev.LatencyNs))
        {
            slowestOpens[ev.LatencyNs] = filename;
        }
        if (slowestOpens.Count > 100)
        {
            // Remove the fastest (smallest key) to cap map size.
            var it = slowestOpens.GetEnumerator();
            if (it.MoveNext())
            {
                slowestOpens.Remove(it.Current.Key);
            }
        }
    }
    else if (rawEvent.Length >= FsRwEvent.Size)
    {
        var ev = FsRwEvent.FromBytes(rawEvent);
        string comm = ReadNullTerminated(ev.Comm.Span, 16);
        string type = ev.IsWrite != 0 ? "WRITE" : "READ";
        ulong latUs = ev.LatencyNs / 1_000;
        Console.WriteLine($"{time,-12} {ev.Pid,-8} {comm,-16} {type,-6} {latUs,-12} {ev.Bytes,-10} fd={ev.Fd}");
    }
}

await reportTask.ConfigureAwait(false);

// ── Lightweight struct overlays (until source-generator is wired up) ─────────

static string ReadNullTerminated(ReadOnlySpan<byte> span, int maxLen)
{
    int end = span[..maxLen].IndexOf((byte)0);
    return System.Text.Encoding.UTF8.GetString(end < 0 ? span[..maxLen] : span[..end]);
}

/// <summary>Mirrors fs_open_event from fs_io.bpf.c.</summary>
readonly struct FsOpenEvent
{
    public const int MinSize = 8 + 8 + 4 + 4 + 4 + 4 + 4 + 16; // without filename

    public readonly ulong TimestampNs;
    public readonly ulong LatencyNs;
    public readonly uint  Pid;
    public readonly uint  Tgid;
    public readonly uint  Uid;
    public readonly uint  Flags;
    public readonly int   RetFd;
    public readonly ReadOnlyMemory<byte> Comm;
    public readonly ReadOnlyMemory<byte> Filename;

    public static FsOpenEvent FromBytes(ReadOnlyMemory<byte> data)
    {
        var s = data.Span;
        int off = 0;
        ulong ts  = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[off..]); off += 8;
        ulong lat = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[off..]); off += 8;
        uint  pid = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[off..]); off += 4;
        uint  tgid= System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[off..]); off += 4;
        uint  uid = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[off..]); off += 4;
        uint  flags=System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[off..]); off += 4;
        int   fd  = System.Runtime.InteropServices.MemoryMarshal.Read<int>(s[off..]); off += 4;
        return new FsOpenEvent(ts, lat, pid, tgid, uid, flags, fd,
            data.Slice(off, 16), data.Slice(off + 16, 256));
    }

    private FsOpenEvent(ulong ts, ulong lat, uint pid, uint tgid, uint uid,
                        uint flags, int fd, ReadOnlyMemory<byte> comm, ReadOnlyMemory<byte> filename)
    {
        TimestampNs = ts; LatencyNs = lat; Pid = pid; Tgid = tgid;
        Uid = uid; Flags = flags; RetFd = fd; Comm = comm; Filename = filename;
    }
}

/// <summary>Mirrors fs_rw_event from fs_io.bpf.c.</summary>
readonly struct FsRwEvent
{
    public const int Size = 8 + 8 + 4 + 4 + 4 + 8 + 1 + 16;

    public readonly ulong TimestampNs;
    public readonly ulong LatencyNs;
    public readonly uint  Pid;
    public readonly uint  Tgid;
    public readonly int   Fd;
    public readonly long  Bytes;
    public readonly byte  IsWrite;
    public readonly ReadOnlyMemory<byte> Comm;

    public static FsRwEvent FromBytes(ReadOnlyMemory<byte> data)
    {
        var s = data.Span;
        int off = 0;
        ulong ts  = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[off..]); off += 8;
        ulong lat = System.Runtime.InteropServices.MemoryMarshal.Read<ulong>(s[off..]); off += 8;
        uint  pid = System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[off..]); off += 4;
        uint  tgid= System.Runtime.InteropServices.MemoryMarshal.Read<uint>(s[off..]); off += 4;
        int   fd  = System.Runtime.InteropServices.MemoryMarshal.Read<int>(s[off..]); off += 4;
        long  b   = System.Runtime.InteropServices.MemoryMarshal.Read<long>(s[off..]); off += 8;
        byte  w   = s[off]; off++;
        return new FsRwEvent(ts, lat, pid, tgid, fd, b, w, data.Slice(off, 16));
    }

    private FsRwEvent(ulong ts, ulong lat, uint pid, uint tgid, int fd,
                      long bytes, byte isWrite, ReadOnlyMemory<byte> comm)
    {
        TimestampNs = ts; LatencyNs = lat; Pid = pid; Tgid = tgid;
        Fd = fd; Bytes = bytes; IsWrite = isWrite; Comm = comm;
    }
}
