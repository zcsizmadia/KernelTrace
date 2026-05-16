using KernelTrace.RingBuffer;

namespace KernelTrace.Tests.RingBuffer;

[ClassDataSource<FakeRingBufferFixture>]
public sealed class RingBufferReaderTests(FakeRingBufferFixture fixture)
{
    // ── Empty buffer ──────────────────────────────────────────────────────────

    [Test]
    public async Task TryReadRecord_WhenBufferEmpty_ReturnsFalse()
    {
        fixture.Reset();
        bool got = fixture.Reader.TryReadRecord(out var record);

        await Assert.That(got).IsFalse();
        await Assert.That(record.Length).IsEqualTo(0);
    }

    // ── Single record ─────────────────────────────────────────────────────────

    [Test]
    public async Task TryReadRecord_WithOneRecord_ReturnsCorrectPayload()
    {
        fixture.Reset();
        byte[] expected = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        fixture.FakeBuffer.Enqueue(expected);

        bool got = fixture.Reader.TryReadRecord(out var record);

        using (record)
        {
            await Assert.That(got).IsTrue();
            await Assert.That(record.Length).IsEqualTo(expected.Length);
            await Assert.That(record.AsSpan().ToArray()).IsEquivalentTo(expected);
        }
    }

    // ── Struct projection ─────────────────────────────────────────────────────

    [Test]
    public async Task TryReadRecord_WhenStructEnqueued_ProjectsCorrectly()
    {
        fixture.Reset();
        var expected = new TestEvent { Pid = 42, Value = 0xDEAD_BEEF };
        fixture.FakeBuffer.Enqueue(expected);

        bool got = fixture.Reader.TryReadRecord(out var record);

        using (record)
        {
            await Assert.That(got).IsTrue();
            var actual = record.ReadAs<TestEvent>();
            await Assert.That(actual.Pid).IsEqualTo(42u);
            await Assert.That(actual.Value).IsEqualTo(0xDEAD_BEEFu);
        }
    }

    // ── Multiple records ──────────────────────────────────────────────────────

    [Test]
    public async Task TryReadRecord_WithMultipleRecords_DrainedInOrder()
    {
        fixture.Reset();
        var events = new TestEvent[]
        {
            new() { Pid = 1, Value = 100 },
            new() { Pid = 2, Value = 200 },
            new() { Pid = 3, Value = 300 },
        };

        foreach (var ev in events)
        {
            fixture.FakeBuffer.Enqueue(ev);
        }

        for (int i = 0; i < events.Length; i++)
        {
            bool got = fixture.Reader.TryReadRecord(out var record);
            using (record)
            {
                await Assert.That(got).IsTrue();
                var actual = record.ReadAs<TestEvent>();
                await Assert.That(actual.Pid).IsEqualTo(events[i].Pid);
                await Assert.That(actual.Value).IsEqualTo(events[i].Value);
            }
        }

        // Buffer should now be empty.
        bool afterDrain = fixture.Reader.TryReadRecord(out _);
        await Assert.That(afterDrain).IsFalse();
    }

    // ── DrainInto ─────────────────────────────────────────────────────────────

    [Test]
    public async Task DrainInto_WritesAllRecordsToChannel()
    {
        fixture.Reset();
        int count = 10;
        for (int i = 0; i < count; i++)
        {
            fixture.FakeBuffer.Enqueue(new TestEvent { Pid = (uint)i, Value = (uint)i * 100 });
        }

        var channel = Channel.CreateUnbounded<RingBufferRecord>();
        int drained = fixture.Reader.DrainInto(channel.Writer);

        await Assert.That(drained).IsEqualTo(count);

        // Verify all records are in the channel.
        int channelCount = 0;
        while (channel.Reader.TryRead(out var record))
        {
            record.Dispose();
            channelCount++;
        }
        await Assert.That(channelCount).IsEqualTo(count);
    }

    // ── RingBufferRecord.ReadAs<T> size guard ────────────────────────────────

    [Test]
    public async Task ReadAs_WhenRecordTooShort_ThrowsInvalidOperationException()
    {
        fixture.Reset();
        fixture.FakeBuffer.Enqueue(new byte[] { 0x01, 0x02 }); // 2 bytes, TestEvent needs 8

        bool got = fixture.Reader.TryReadRecord(out var record);
        await Assert.That(got).IsTrue();

        using (record)
        {
            await Assert.That(() => record.ReadAs<TestEvent>())
                .Throws<InvalidOperationException>();
        }
    }
}

// ── Test fixture ─────────────────────────────────────────────────────────────

public sealed class FakeRingBufferFixture : IDisposable
{
    internal FakeRingBuffer FakeBuffer { get; } = new();
    internal RingBufferReader Reader   { get; }

    public FakeRingBufferFixture()
    {
        var mapping = FakeBuffer.CreateMapping();
        Reader = new RingBufferReader(mapping, FakeRingBuffer.TestPageSize);
    }

    public void Reset() => FakeBuffer.Reset();

    public void Dispose()
    {
        Reader.Dispose();
        FakeBuffer.Dispose();
    }
}

// ── Test event struct ─────────────────────────────────────────────────────────

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct TestEvent
{
    public uint Pid;
    public uint Value;
}
