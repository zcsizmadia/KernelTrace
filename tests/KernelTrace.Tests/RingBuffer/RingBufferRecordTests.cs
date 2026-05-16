namespace KernelTrace.Tests.RingBuffer;

public sealed class RingBufferRecordTests
{
    // ── AsSpan ────────────────────────────────────────────────────────────────

    [Test]
    public async Task AsSpan_ReturnsCorrectBytes()
    {
        byte[] payload = [1, 2, 3, 4, 5];
        byte[] rented = ArrayPool<byte>.Shared.Rent(payload.Length);
        payload.CopyTo(rented, 0);

        using var record = new RingBufferRecord(rented, payload.Length);

        await Assert.That(record.AsSpan().ToArray()).IsEquivalentTo(payload);
    }

    // ── AsMemory ──────────────────────────────────────────────────────────────

    [Test]
    public async Task AsMemory_ReturnsCorrectLength()
    {
        byte[] payload = new byte[16];
        byte[] rented = ArrayPool<byte>.Shared.Rent(16);
        payload.CopyTo(rented, 0);

        using var record = new RingBufferRecord(rented, 16);

        await Assert.That(record.AsMemory().Length).IsEqualTo(16);
    }

    // ── ReadAs<T> ─────────────────────────────────────────────────────────────

    [Test]
    public async Task ReadAs_DecodesUInt32Correctly()
    {
        uint expected = 0xCAFE_BABE;
        byte[] rented = ArrayPool<byte>.Shared.Rent(4);
        BitConverter.TryWriteBytes(rented, expected);

        using var record = new RingBufferRecord(rented, 4);
        uint actual = record.ReadAs<uint>();

        await Assert.That(actual).IsEqualTo(expected);
    }

    [Test]
    public async Task ReadAs_WhenTooShort_ThrowsInvalidOperationException()
    {
        byte[] rented = ArrayPool<byte>.Shared.Rent(2);

        using var record = new RingBufferRecord(rented, 2);

        await Assert.That(() => record.ReadAs<uint>())
            .Throws<InvalidOperationException>();
    }

    // ── Length ────────────────────────────────────────────────────────────────

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(100)]
    [Arguments(4096)]
    public async Task Length_MatchesConstructorArgument(int length)
    {
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(length, 1));

        using var record = new RingBufferRecord(rented, length);

        await Assert.That(record.Length).IsEqualTo(length);
    }

    // ── Dispose returns to pool ────────────────────────────────────────────────
    // (Hard to assert directly without custom pool, but we verify no throw.)

    [Test]
    public async Task Dispose_DoesNotThrow()
    {
        byte[] rented = ArrayPool<byte>.Shared.Rent(8);
        var record = new RingBufferRecord(rented, 8);

        await Assert.That(() => record.Dispose()).ThrowsNothing();
    }
}
