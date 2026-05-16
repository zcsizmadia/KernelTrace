using System.Runtime.InteropServices;
using System.Threading.Channels;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using KernelTrace.RingBuffer;

namespace KernelTrace.Benchmarks;

/// <summary>
/// Benchmarks the event-processing pipeline — channel throughput, IAsyncEnumerable
/// overhead, and struct projection costs.
/// </summary>
[Config(typeof(Config))]
[MemoryDiagnoser]
[HideColumns(Column.RatioSD, Column.StdDev)]
public class EventProcessingBenchmarks
{
    private sealed class Config : ManualConfig
    {
        public Config() => AddJob(
            Job.Default
               .WithWarmupCount(3)
               .WithIterationCount(10));
    }

    // ── Parameters ────────────────────────────────────────────────────────────

    [Params(100, 1_000, 10_000)]
    public int EventCount { get; set; }

    // ── Benchmark: Channel throughput ─────────────────────────────────────────

    /// <summary>Measures raw bounded-channel write + read throughput.</summary>
    [Benchmark(Baseline = true)]
    public async Task<int> BoundedChannel_WriteRead()
    {
        var channel = Channel.CreateBounded<int>(
            new BoundedChannelOptions(EventCount)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
            });

        for (int i = 0; i < EventCount; i++)
        {
            channel.Writer.TryWrite(i);
        }
        channel.Writer.Complete();

        int consumed = 0;
        await foreach (var _ in channel.Reader.ReadAllAsync())
        {
            consumed++;
        }

        return consumed;
    }

    // ── Benchmark: RingBufferRecord struct read + dispose ─────────────────────

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct SmallEvent { public ulong Ts; public uint Pid; public uint Pad; }

    /// <summary>
    /// Rents a pooled buffer, wraps it in <see cref="RingBufferRecord"/>,
    /// projects to <see cref="SmallEvent"/>, then returns the buffer.
    /// </summary>
    [Benchmark]
    public ulong RecordReadAs_SmallStruct()
    {
        ulong sum = 0;
        for (int i = 0; i < EventCount; i++)
        {
            byte[] rented = System.Buffers.ArrayPool<byte>.Shared.Rent(16);
            MemoryMarshal.Write(rented, new SmallEvent { Ts = (ulong)i, Pid = 42 });

            using var record = new RingBufferRecord(rented, 16);
            sum += record.ReadAs<SmallEvent>().Ts;
        }
        return sum;
    }

    // ── Benchmark: IAsyncEnumerable overhead ─────────────────────────────────

    /// <summary>
    /// Writes <see cref="EventCount"/> records to a channel, then drains via
    /// <c>ReadAllAsync()</c>, measuring the async-enumerable overhead.
    /// </summary>
    [Benchmark]
    public async Task<long> Channel_IAsyncEnumerable_Drain()
    {
        var channel = Channel.CreateBounded<RingBufferRecord>(
            new BoundedChannelOptions(EventCount)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
            });

        for (int i = 0; i < EventCount; i++)
        {
            byte[] rented = System.Buffers.ArrayPool<byte>.Shared.Rent(16);
            MemoryMarshal.Write(rented, new SmallEvent { Ts = (ulong)i, Pid = 1 });
            channel.Writer.TryWrite(new RingBufferRecord(rented, 16));
        }
        channel.Writer.Complete();

        long sum = 0;
        await foreach (var rec in channel.Reader.ReadAllAsync())
        {
            using (rec)
            {
                sum += (long)rec.ReadAs<SmallEvent>().Ts;
            }
        }
        return sum;
    }
}
