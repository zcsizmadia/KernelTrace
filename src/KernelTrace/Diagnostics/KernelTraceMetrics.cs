using System.Diagnostics.Metrics;

namespace KernelTrace.Diagnostics;

/// <summary>
/// Live metrics for a <see cref="Sessions.KernelTraceSession"/>.
/// All counters are wired into the <c>System.Diagnostics.Metrics</c>
/// infrastructure (meter name: <c>"KernelTrace"</c>), making them
/// compatible with OpenTelemetry and <c>dotnet-counters</c> for live inspection.
/// </summary>
public sealed class KernelTraceMetrics : IDisposable
{
    // ── Meter ────────────────────────────────────────────────────────────────
    internal const string MeterName = "KernelTrace";

    private readonly Meter _meter;

    // ── Instruments ──────────────────────────────────────────────────────────
    private readonly Counter<long> _eventsReceived;
    private readonly Counter<long> _eventsDropped;
    private readonly Counter<long> _pollIterations;
    private readonly Histogram<double> _drainLatency;

    // ── Snapshot fields (for ObservableGauge) ────────────────────────────────
    private long _receivedSnapshot;
    private long _droppedSnapshot;
    private long _pollsSnapshot;

    /// <summary>Total events successfully enqueued from the ring buffer.</summary>
    public long TotalReceived => Volatile.Read(ref _receivedSnapshot);

    /// <summary>Total events dropped because the bounded channel was full.</summary>
    public long TotalDropped => Volatile.Read(ref _droppedSnapshot);

    /// <summary>Total epoll_wait iterations performed by the polling thread.</summary>
    public long TotalPolls => Volatile.Read(ref _pollsSnapshot);

    /// <inheritdoc cref="KernelTraceMetrics"/>
    public KernelTraceMetrics()
    {
        _meter = new Meter(MeterName);

        _eventsReceived = _meter.CreateCounter<long>(
            "kerneltrace.events.received.total",
            unit: "{events}",
            description: "Total number of kernel events successfully read from the ring buffer.");

        _eventsDropped = _meter.CreateCounter<long>(
            "kerneltrace.events.dropped.total",
            unit: "{events}",
            description: "Total events dropped because the consumer channel was full.");

        _pollIterations = _meter.CreateCounter<long>(
            "kerneltrace.ring_buffer.polls.total",
            unit: "{iterations}",
            description: "Total number of epoll_wait iterations performed by the polling thread.");

        _drainLatency = _meter.CreateHistogram<double>(
            "kerneltrace.ring_buffer.drain.duration",
            unit: "ms",
            description: "Time taken to drain all available records from the ring buffer in one pass.");

        _meter.CreateObservableGauge(
            "kerneltrace.events.received.snapshot",
            () => TotalReceived,
            unit: "{events}",
            description: "Snapshot of total received events (observable gauge for Prometheus).");

        _meter.CreateObservableGauge(
            "kerneltrace.events.dropped.snapshot",
            () => TotalDropped,
            unit: "{events}",
            description: "Snapshot of total dropped events (observable gauge for Prometheus).");
    }

    // ── Internal mutation API (called by the polling thread) ─────────────────

    internal void AddReceived(int count)
    {
        if (count <= 0)
        {
            return;
        }

        Interlocked.Add(ref _receivedSnapshot, count);
        _eventsReceived.Add(count);
    }

    internal void AddDropped(int count)
    {
        if (count <= 0)
        {
            return;
        }

        Interlocked.Add(ref _droppedSnapshot, count);
        _eventsDropped.Add(count);
    }

    internal void IncrementPolls()
    {
        Interlocked.Increment(ref _pollsSnapshot);
        _pollIterations.Add(1);
    }

    internal void RecordDrainLatency(double milliseconds) =>
        _drainLatency.Record(milliseconds);

    // ── IDisposable ───────────────────────────────────────────────────────────

    /// <inheritdoc/>
    public void Dispose() => _meter.Dispose();
}
