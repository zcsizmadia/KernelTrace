using KernelTrace.Diagnostics;

namespace KernelTrace.Tests.Diagnostics;

public sealed class KernelTraceMetricsTests : IDisposable
{
    private readonly KernelTraceMetrics _metrics = new();

    // ── Initial state ─────────────────────────────────────────────────────────

    [Test]
    public async Task InitialCounters_AreAllZero()
    {
        await Assert.That(_metrics.TotalReceived).IsEqualTo(0);
        await Assert.That(_metrics.TotalDropped).IsEqualTo(0);
        await Assert.That(_metrics.TotalPolls).IsEqualTo(0);
    }

    // ── AddReceived ───────────────────────────────────────────────────────────

    [Test]
    [Arguments(1)]
    [Arguments(10)]
    [Arguments(1000)]
    public async Task AddReceived_IncrementsCounterByAmount(int amount)
    {
        var m = new KernelTraceMetrics();
        m.AddReceived(amount);
        await Assert.That(m.TotalReceived).IsEqualTo(amount);
        m.Dispose();
    }

    [Test]
    public async Task AddReceived_WithZero_DoesNotChange()
    {
        _metrics.AddReceived(5);
        _metrics.AddReceived(0);
        await Assert.That(_metrics.TotalReceived).IsEqualTo(5);
    }

    // ── AddDropped ────────────────────────────────────────────────────────────

    [Test]
    public async Task AddDropped_IncrementsDropCounter()
    {
        _metrics.AddDropped(3);
        await Assert.That(_metrics.TotalDropped).IsEqualTo(3);
    }

    // ── IncrementPolls ────────────────────────────────────────────────────────

    [Test]
    public async Task IncrementPolls_IncreasesPollCountByOne()
    {
        _metrics.IncrementPolls();
        _metrics.IncrementPolls();
        await Assert.That(_metrics.TotalPolls).IsEqualTo(2);
    }

    // ── Thread safety — concurrent increments ─────────────────────────────────

    [Test]
    public async Task AddReceived_ConcurrentCalls_CountsAllEvents()
    {
        var m = new KernelTraceMetrics();
        int threads = 8;
        int perThread = 1000;

        var tasks = Enumerable.Range(0, threads)
            .Select(_ => Task.Run(() =>
            {
                for (int i = 0; i < perThread; i++)
                {
                    m.AddReceived(1);
                }
            }))
            .ToArray();

        await Task.WhenAll(tasks);

        await Assert.That(m.TotalReceived).IsEqualTo(threads * perThread);
        m.Dispose();
    }

    public void Dispose() => _metrics.Dispose();
}
