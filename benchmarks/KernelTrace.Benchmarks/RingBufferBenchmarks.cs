using System.Buffers;
using System.Runtime.InteropServices;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using KernelTrace.RingBuffer;

namespace KernelTrace.Benchmarks;

/// <summary>
/// Benchmarks the hot path: reading records from the mmap'd ring buffer and
/// draining them into the consumer channel.
/// </summary>
[Config(typeof(Config))]
[MemoryDiagnoser]
[HideColumns(Column.RatioSD, Column.StdDev)]
public class RingBufferBenchmarks
{
    private sealed class Config : ManualConfig
    {
        public Config() => AddJob(
            Job.Default
               .WithWarmupCount(3)
               .WithIterationCount(10));
    }

    // ── Parameters ────────────────────────────────────────────────────────────

    [Params(1, 8, 64, 256)]
    public int RecordCount { get; set; }

    [Params(8, 64, 512)]
    public int RecordSizeBytes { get; set; }

    // ── State ─────────────────────────────────────────────────────────────────

    private FakeBenchmarkRingBuffer _fakeBuffer = null!;
    private RingBufferReader         _reader     = null!;

    // ── Setup / Cleanup ───────────────────────────────────────────────────────

    [GlobalSetup]
    public void Setup()
    {
        _fakeBuffer = new FakeBenchmarkRingBuffer();
        var mapping = _fakeBuffer.CreateMapping();
        _reader = new RingBufferReader(mapping, FakeBenchmarkRingBuffer.PageSize);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _reader.Dispose();
        _fakeBuffer.Dispose();
    }

    [IterationSetup]
    public void IterationSetup()
    {
        _fakeBuffer.Reset();
        var payload = new byte[RecordSizeBytes];
        for (int i = 0; i < RecordCount; i++)
        {
            _fakeBuffer.Enqueue(payload);
        }
    }

    // ── Benchmarks ────────────────────────────────────────────────────────────

    /// <summary>Drain N records from the ring buffer via TryReadRecord.</summary>
    [Benchmark(Baseline = true)]
    public int TryReadRecord_Drain()
    {
        int count = 0;
        while (_reader.TryReadRecord(out var rec))
        {
            count++;
            rec.Dispose();
        }
        return count;
    }

    /// <summary>Drain N records into an unbounded channel.</summary>
    [Benchmark]
    public int DrainInto_UnboundedChannel()
    {
        var channel = System.Threading.Channels.Channel.CreateUnbounded<RingBufferRecord>();
        int n = _reader.DrainInto(channel.Writer);

        // Consume and dispose.
        while (channel.Reader.TryRead(out var rec))
        {
            rec.Dispose();
        }
        return n;
    }

    /// <summary>ReadAs&lt;T&gt; projection overhead (vs raw byte access).</summary>
    [Benchmark]
    public ulong TryReadRecord_ReadAs()
    {
        _fakeBuffer.Reset();
        var ev = new BenchEvent { Ts = 0xDEAD_BEEF_CAFE_BABEuL, Pid = 42 };
        _fakeBuffer.Enqueue(System.Runtime.InteropServices.MemoryMarshal.AsBytes(
            System.Runtime.InteropServices.MemoryMarshal.CreateReadOnlySpan(ref ev, 1)));

        if (_reader.TryReadRecord(out var rec))
        {
            using (rec)
                return rec.ReadAs<BenchEvent>().Ts;
        }
        return 0;
    }
}

// ── Event struct for ReadAs benchmark ────────────────────────────────────────

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct BenchEvent
{
    public ulong Ts;
    public uint  Pid;
    public uint  _pad;
}

// ── Minimal pinned ring-buffer for benchmarks ────────────────────────────────

internal sealed unsafe class FakeBenchmarkRingBuffer : IDisposable
{
    public const ulong PageSize = 4096;

    private static readonly ulong DataSize  = PageSize * 16;  // 64 KB data pages
    private static readonly ulong TotalSize = PageSize * 2 + DataSize * 2;

    private readonly byte[]   _memory;
    private readonly GCHandle _pin;
    private          byte*    _base;

    private ulong* ConsumerPage => (ulong*)_base;
    private ulong* ProducerPage => (ulong*)(_base + PageSize);
    private byte*  DataPage     => _base + PageSize * 2;

    public FakeBenchmarkRingBuffer()
    {
        _memory = GC.AllocateArray<byte>((int)TotalSize, pinned: true);
        _pin    = GCHandle.Alloc(_memory, GCHandleType.Pinned);
        _base   = (byte*)_pin.AddrOfPinnedObject();
    }

    public void Reset()
    {
        *ConsumerPage = 0;
        *ProducerPage = 0;
        new Span<byte>(DataPage, (int)DataSize).Clear();
    }

    public void Enqueue(ReadOnlySpan<byte> payload)
    {
        ulong pos = *ProducerPage;
        ulong mask = DataSize - 1;

        // Write header (8 bytes: length | flags, page_offset).
        uint len = (uint)payload.Length;
        byte* slot = DataPage + (pos & mask);
        *(uint*)slot       = len;          // no flags = ready to read
        *(uint*)(slot + 4) = 0;

        // Write data.
        payload.CopyTo(new Span<byte>(slot + 8, payload.Length));

        ulong advance = 8 + (ulong)AlignUp((uint)payload.Length, 8);
        System.Threading.Volatile.Write(ref *ProducerPage, pos + advance);
    }

    public KernelTrace.Interop.MappedRingBuffer CreateMapping()
    {
        // Mirror data pages (ring buffer layout: consumer page, producer page, data × 2).
        return new KernelTrace.Interop.MappedRingBuffer(
            ptr:       _base,
            totalSize: (nuint)TotalSize,
            dataSize:  (nuint)DataSize);
    }

    private static uint AlignUp(uint val, uint align) =>
        (val + align - 1) & ~(align - 1);

    public void Dispose()
    {
        if (_pin.IsAllocated)
        {
            _pin.Free();
        }
    }
}
