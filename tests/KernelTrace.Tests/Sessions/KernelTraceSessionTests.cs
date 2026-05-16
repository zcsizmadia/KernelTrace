using KernelTrace.Events;

namespace KernelTrace.Tests.Sessions;

public sealed class KernelTraceSessionTests
{
    // ── CreateAsync — platform guard ──────────────────────────────────────────

    [Test]
    public async Task CreateAsync_OnNonLinux_WithRealInterop_ThrowsPlatformNotSupportedException()
    {
        if (OperatingSystem.IsLinux())
        {
            // Skip this test on Linux — it would try to load real native lib.
            return;
        }

        var options = new SessionOptions { ProbePath = "./fake.bpf.o" };

        await Assert.That(async () =>
            await KernelTraceSession.CreateAsync(options))
            .Throws<PlatformNotSupportedException>();
    }

    // ── CreateAsync — file not found ──────────────────────────────────────────

    [Test]
    public async Task CreateAsync_WithMissingFile_ThrowsFileNotFoundException()
    {
        var fake = new FakeNativeInterop();
        var options = new SessionOptions
        {
            ProbePath = "/nonexistent/path/probe.bpf.o",
        };

        await Assert.That(async () =>
            await KernelTraceSession.CreateAsync(options, fake))
            .Throws<FileNotFoundException>();
    }

    // ── CreateAsync — probe attachment ────────────────────────────────────────

    [Test]
    public async Task CreateAsync_AttachesAllSpecifiedProbes()
    {
        var fake = new FakeNativeInterop();
        using var tmpFile = new TempProbeFile();

        var options = new SessionOptions
        {
            ProbePath        = tmpFile.Path,
            ValidateStructLayouts = false,
            Probes = [
                new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" },
                new KprobeSpec     { FunctionName = "tcp_connect" },
            ],
        };

        await using var session = await KernelTraceSession.CreateAsync(options, fake);

        await Assert.That(fake.AttachedProbes).Contains("tracepoint/syscalls/sys_enter_connect");
        await Assert.That(fake.AttachedProbes).Contains("kprobe/tcp_connect");
        await Assert.That(fake.AttachedProbes.Count).IsEqualTo(2);
    }

    // ── ReadAsync<T> — streams events ─────────────────────────────────────────

    [Test]
    public async Task ReadAsync_WhenEventsEnqueued_YieldsCorrectValues()
    {
        var fake = new FakeNativeInterop();
        using var tmpFile = new TempProbeFile();

        var options = new SessionOptions
        {
            ProbePath             = tmpFile.Path,
            ValidateStructLayouts = false,
            PollTimeoutMs         = 10,
        };

        // Pre-populate the fake ring buffer with 3 events.
        var expected = new[]
        {
            new TestNetEvent { Pid = 100, DstPort = 80 },
            new TestNetEvent { Pid = 200, DstPort = 443 },
            new TestNetEvent { Pid = 300, DstPort = 8080 },
        };
        foreach (var ev in expected)
        {
            fake.RingBuffer.Enqueue(ev);
        }

        // Signal Poll to return data on first call, then cancel.
        fake.PollResults.Enqueue(1); // first drain
        fake.PollResults.Enqueue(0); // idle

        await using var session = await KernelTraceSession.CreateAsync(options, fake);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var received = new List<TestNetEvent>();

        try
        {
            await foreach (var ev in session.ReadAsync<TestNetEvent>(cts.Token))
            {
                received.Add(ev);

                if (received.Count >= expected.Length)
                {
                    cts.Cancel();
                }
            }
        }
        catch (OperationCanceledException) { /* expected */ }

        await Assert.That(received.Count).IsGreaterThanOrEqualTo(expected.Length);
        await Assert.That(received[0].Pid).IsEqualTo(100u);
        await Assert.That(received[1].Pid).IsEqualTo(200u);
        await Assert.That(received[2].Pid).IsEqualTo(300u);
    }

    // ── Metrics ───────────────────────────────────────────────────────────────

    [Test]
    public async Task Metrics_AfterReadingEvents_ReflectsCorrectCounts()
    {
        var fake = new FakeNativeInterop();
        using var tmpFile = new TempProbeFile();

        var options = new SessionOptions
        {
            ProbePath             = tmpFile.Path,
            ValidateStructLayouts = false,
        };

        int eventCount = 5;
        for (int i = 0; i < eventCount; i++)
        {
            fake.RingBuffer.Enqueue(new TestNetEvent { Pid = (uint)i, DstPort = 80 });
        }
        fake.PollResults.Enqueue(1);

        await using var session = await KernelTraceSession.CreateAsync(options, fake);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        int received = 0;
        try
        {
            await foreach (var _ in session.ReadAsync<TestNetEvent>(cts.Token))
            {
                received++;

                if (received >= eventCount)
                {
                    cts.Cancel();
                }
            }
        }
        catch (OperationCanceledException) { }

        await Assert.That(session.Metrics.TotalReceived).IsGreaterThanOrEqualTo(eventCount);
        await Assert.That(session.Metrics.TotalDropped).IsEqualTo(0);
    }

    // ── BTF validation ────────────────────────────────────────────────────────

    [Test]
    public async Task ReadAsync_WhenBtfSizeMismatch_ThrowsKernelStructMismatchException()
    {
        var fake = new FakeNativeInterop();
        fake.BtfSizes["test_net_event"] = 999; // deliberately wrong

        using var tmpFile = new TempProbeFile();
        var options = new SessionOptions
        {
            ProbePath             = tmpFile.Path,
            ValidateStructLayouts = true,
        };

        await using var session = await KernelTraceSession.CreateAsync(options, fake);

        await Assert.That(async () =>
        {
            await foreach (var _ in session.ReadAsync<AnnotatedEvent>())
            {
            }
        })
        .Throws<KernelStructMismatchException>();
    }

    // ── DisposeAsync — idempotent ─────────────────────────────────────────────

    [Test]
    public async Task DisposeAsync_CalledTwice_DoesNotThrow()
    {
        var fake = new FakeNativeInterop();
        using var tmpFile = new TempProbeFile();
        var options = new SessionOptions { ProbePath = tmpFile.Path, ValidateStructLayouts = false };

        var session = await KernelTraceSession.CreateAsync(options, fake);

        await Assert.That(async () =>
        {
            await session.DisposeAsync();
            await session.DisposeAsync();
        }).ThrowsNothing();
    }

    // ── Hot-attach ────────────────────────────────────────────────────────────

    [Test]
    public async Task AttachAsync_AddsNewProbeToRunningSession()
    {
        var fake = new FakeNativeInterop();
        using var tmpFile = new TempProbeFile();
        var options = new SessionOptions { ProbePath = tmpFile.Path, ValidateStructLayouts = false };

        await using var session = await KernelTraceSession.CreateAsync(options, fake);

        int countBefore = fake.AttachedProbes.Count;
        var token = await session.AttachAsync(new KprobeSpec { FunctionName = "tcp_retransmit_skb" });

        await Assert.That(fake.AttachedProbes.Count).IsEqualTo(countBefore + 1);
        await Assert.That(fake.AttachedProbes).Contains("kprobe/tcp_retransmit_skb");
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct TestNetEvent
{
    public uint   Pid;
    public ushort DstPort;
    public ushort _pad;
}

[KernelEventAttribute("test_net_event")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct AnnotatedEvent
{
    public uint Pid;
    public uint Value;
}

/// <summary>Creates a temp file to satisfy the <see cref="SessionOptions.ProbePath"/> existence check.</summary>
internal sealed class TempProbeFile : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(
        System.IO.Path.GetTempPath(),
        $"kt_test_{Guid.NewGuid():N}.bpf.o");

    public TempProbeFile() => File.WriteAllBytes(Path, []);

    public void Dispose()
    {
        try { File.Delete(Path); } catch { /* best-effort */ }
    }
}
