using KernelTrace.Interop;

namespace KernelTrace.Tests.Fakes;

/// <summary>
/// In-memory implementation of <see cref="INativeInterop"/> for unit tests.
/// No native library or Linux kernel required.
/// </summary>
internal sealed class FakeNativeInterop : INativeInterop
{
    // ── State ────────────────────────────────────────────────────────────────

    /// <summary>Records each attach call for assertion in tests.</summary>
    public List<string> AttachedProbes { get; } = [];

    /// <summary>Tracks how many times Poll was called.</summary>
    public int PollCallCount { get; private set; }

    /// <summary>
    /// Controls whether Poll returns data (1) or timeout (0) on the next call.
    /// </summary>
    public Queue<int> PollResults { get; } = new();

    /// <summary>The ring buffer used by this fake.</summary>
    public FakeRingBuffer RingBuffer { get; } = new();

    /// <summary>Throws the given exception on the next LoadSession call.</summary>
    public Exception? LoadException { get; set; }

    /// <summary>Simulated BTF struct sizes (struct name → byte size).</summary>
    public Dictionary<string, int> BtfSizes { get; } = new(StringComparer.Ordinal);

    /// <summary>Records the TGID set by SetTgidFilter, or null if never called.</summary>
    public uint? TgidFilter { get; private set; }

    /// <summary>Fake BTF availability (default: true).</summary>
    public bool BtfAvailableResult { get; set; } = true;

    /// <summary>Map name → fake fd mapping (default fd = 100 + index).</summary>
    public Dictionary<string, int> MapFds { get; } = new(StringComparer.Ordinal);

    /// <summary>Map fd → fake map info (default: hash map, 4-byte key, 8-byte value).</summary>
    public Dictionary<int, NativeMapInfo> MapInfos { get; } = new();

    /// <summary>
    /// In-memory map data: fd → (key bytes → value bytes).
    /// Keys and values are compared by their byte representations.
    /// </summary>
    public Dictionary<int, Dictionary<byte[], byte[]>> MapData { get; } =
        new(new FdComparer());

    private int _nextFd = 100;

    // ── INativeInterop ───────────────────────────────────────────────────────

    public KernelProbeHandle LoadSession(string objPath,
        string? btfCustomPath = null, bool debugOutput = false)
    {
        if (LoadException is not null)
        {
            throw LoadException;
        }
        // Return a fake non-zero handle.
        return new FakeKernelProbeHandle(1);
    }

    public AttachmentHandle AttachTracepoint(KernelProbeHandle session, string category, string name)
    {
        AttachedProbes.Add($"tracepoint/{category}/{name}");
        return new FakeAttachmentHandle(AttachedProbes.Count);
    }

    public AttachmentHandle AttachKprobe(KernelProbeHandle session, string functionName, bool returnProbe = false)
    {
        AttachedProbes.Add($"{(returnProbe ? "kretprobe" : "kprobe")}/{functionName}");
        return new FakeAttachmentHandle(AttachedProbes.Count);
    }

    public AttachmentHandle AttachUprobe(KernelProbeHandle session, string binaryPath, ulong offset, bool returnProbe = false, string? programSection = null)
    {
        AttachedProbes.Add($"{(returnProbe ? "uretprobe" : "uprobe")}:{binaryPath}+0x{offset:x}");
        return new FakeAttachmentHandle(AttachedProbes.Count);
    }

    public void Detach(AttachmentHandle attachment)
    {
        // No-op in fake.
    }

    public int GetRingBufFd(KernelProbeHandle session, string mapName) => 42; // fake fd

    public MappedRingBuffer MapRingBuffer(int fd) => RingBuffer.CreateMapping();

    public int CreateEpoll(int ringBufFd) => 99; // fake epoll fd

    public int Poll(int epollFd, int timeoutMs)
    {
        PollCallCount++;
        return PollResults.Count > 0 ? PollResults.Dequeue() : 0;
    }

    public void CloseFd(int fd) { /* no-op */ }

    public int GetBtfStructSize(KernelProbeHandle session, string structName) =>
        BtfSizes.TryGetValue(structName, out int size) ? size : -1;

    public bool IsBtfAvailable() => BtfAvailableResult;

    public void SetTgidFilter(KernelProbeHandle session, uint tgid) =>
        TgidFilter = tgid;

    // ── USDT probes ───────────────────────────────────────────────────────────

    public AttachmentHandle AttachUsdt(KernelProbeHandle session, int pid,
        string binaryPath, string provider, string name, string? programSection = null)
    {
        AttachedProbes.Add($"usdt:{provider}:{name}");
        return new FakeAttachmentHandle(1);
    }

    // ── BPF map operations ────────────────────────────────────────────────────

    public int MapGetFd(KernelProbeHandle session, string mapName)
    {
        if (MapFds.TryGetValue(mapName, out int fd))
        {
            return fd;
        }

        // Auto-allocate an fd for any unregistered map name.
        fd = _nextFd++;
        MapFds[mapName] = fd;
        return fd;
    }

    public NativeMapInfo MapGetInfo(int mapFd)
    {
        if (MapInfos.TryGetValue(mapFd, out var info))
        {
            return info;
        }

        return new NativeMapInfo { Type = 1, KeySize = 4, ValueSize = 8, MaxEntries = 1024 };
    }

    public unsafe int MapLookup(int mapFd, nint keyPtr, nint valuePtr)
    {
        if (!MapData.TryGetValue(mapFd, out var store))
        {
            return -2; // ENOENT
        }

        var keyBytes = ReadBytes(keyPtr, GetKeySize(mapFd));
        if (!store.TryGetValue(keyBytes, out var valueBytes))
        {
            return -2;
        }

        WriteBytes(valuePtr, valueBytes);
        return 0;
    }

    public unsafe int MapUpdate(int mapFd, nint keyPtr, nint valuePtr, ulong flags)
    {
        if (!MapData.TryGetValue(mapFd, out var store))
        {
            store = new Dictionary<byte[], byte[]>(ByteArrayComparer.Instance);
            MapData[mapFd] = store;
        }

        var keyBytes   = ReadBytes(keyPtr, GetKeySize(mapFd));
        var valueBytes = ReadBytes(valuePtr, GetValueSize(mapFd));

        if (flags == 1 && store.ContainsKey(keyBytes))
        {
            return -17; // EEXIST
        }

        if (flags == 2 && !store.ContainsKey(keyBytes))
        {
            return -2;  // ENOENT
        }

        store[keyBytes] = valueBytes;
        return 0;
    }

    public unsafe int MapDelete(int mapFd, nint keyPtr)
    {
        if (!MapData.TryGetValue(mapFd, out var store))
        {
            return -2;
        }

        var keyBytes = ReadBytes(keyPtr, GetKeySize(mapFd));
        return store.Remove(keyBytes) ? 0 : -2;
    }

    public unsafe int MapGetNextKey(int mapFd, nint currentKeyPtr, nint nextKeyPtr)
    {
        if (!MapData.TryGetValue(mapFd, out var store) || store.Count == 0)
        {
            return -2;
        }

        var keys = store.Keys.ToList();
        if (currentKeyPtr == nint.Zero)
        {
            WriteBytes(nextKeyPtr, keys[0]);
            return 0;
        }

        var currentKey = ReadBytes(currentKeyPtr, GetKeySize(mapFd));
        int idx = keys.FindIndex(k => ByteArrayComparer.Instance.Equals(k, currentKey));
        if (idx < 0 || idx + 1 >= keys.Count)
        {
            return -2; // end of iteration
        }

        WriteBytes(nextKeyPtr, keys[idx + 1]);
        return 0;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private int GetKeySize(int mapFd) =>
        (int)(MapGetInfo(mapFd).KeySize > 0 ? MapGetInfo(mapFd).KeySize : 4);

    private int GetValueSize(int mapFd) =>
        (int)(MapGetInfo(mapFd).ValueSize > 0 ? MapGetInfo(mapFd).ValueSize : 8);

    private static unsafe byte[] ReadBytes(nint ptr, int count)
    {
        var buf = new byte[count];
        fixed (byte* dst = buf)
        {
            Buffer.MemoryCopy((void*)ptr, dst, count, count);
        }

        return buf;
    }

    private static unsafe void WriteBytes(nint ptr, byte[] src)
    {
        fixed (byte* s = src)
        {
            Buffer.MemoryCopy(s, (void*)ptr, src.Length, src.Length);
        }
    }

    private sealed class FdComparer : IEqualityComparer<int>
    {
        public bool Equals(int x, int y) => x == y;
        public int GetHashCode(int obj) => obj;
    }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();
        public bool Equals(byte[]? x, byte[]? y) => x.AsSpan().SequenceEqual(y.AsSpan());
        public int GetHashCode(byte[] obj)
        {
            var hc = new HashCode();
            foreach (var b in obj)
            {
                hc.Add(b);
            }

            return hc.ToHashCode();
        }
    }
}

// ── Fake SafeHandle implementations ─────────────────────────────────────────

internal sealed class FakeKernelProbeHandle : KernelProbeHandle
{
    public FakeKernelProbeHandle(nint value) : base(value) { }

    protected override bool ReleaseHandle() => true; // no-op
}

internal sealed class FakeAttachmentHandle : AttachmentHandle
{
    public FakeAttachmentHandle(nint value) : base(value) { }

    protected override bool ReleaseHandle() => true; // no-op
}
