using KernelTrace.Interop;

namespace KernelTrace.RingBuffer;

/// <summary>
/// Lock-free, zero-copy reader for the Linux eBPF ring buffer
/// (<c>BPF_MAP_TYPE_RINGBUF</c>).
/// </summary>
/// <remarks>
/// <para>
/// The ring buffer memory layout (from the Linux kernel) is:
/// <code>
/// [0 .. PAGE_SIZE)           consumer page  — uint64 consumer_pos at offset 0
/// [PAGE_SIZE .. 2*PAGE_SIZE) producer page  — uint64 producer_pos at offset 0
/// [2*PAGE_SIZE .. end)       data pages     — mirrored once for wrap-around
/// </code>
/// </para>
/// <para>
/// Each record is prefixed by an 8-byte header:
/// <code>
/// bit 31      : BUSY    (record still being written)
/// bit 30      : DISCARD (record was discarded by the eBPF program)
/// bits [29:0] : data length in bytes
/// </code>
/// The header plus data are padded to an 8-byte boundary.
/// </para>
/// <para>
/// <see cref="TryReadRecord"/> is intended to be called from a single dedicated
/// reader thread.  The consumer position is advanced with a
/// <see cref="Volatile.Write(ref ulong, ulong)"/> memory barrier that makes the
/// update visible to the kernel producer.
/// </para>
/// </remarks>
internal sealed unsafe class RingBufferReader : IDisposable
{
    // ── Ring buffer header bit masks ─────────────────────────────────────────
    private const uint BusyBit    = 1u << 31;
    private const uint DiscardBit = 1u << 30;
    private const uint LenMask    = ~(BusyBit | DiscardBit);
    private const uint HdrSize    = 8u;       // bytes (two uint32 fields)

    // ── Memory layout ────────────────────────────────────────────────────────
    private readonly byte* _consumerPage;  // pointer to consumer_pos (uint64)
    private readonly byte* _producerPage;  // pointer to producer_pos (uint64)
    private readonly byte* _data;          // start of data pages
    private readonly ulong _dataMask;      // data_size - 1  (power-of-two mask)

    private readonly MappedRingBuffer _mapping;
    private bool _disposed;

    internal RingBufferReader(MappedRingBuffer mapping, ulong pageSize)
    {
        _mapping = mapping;
        var basePtr = (byte*)mapping.BasePointer;

        _consumerPage = basePtr;
        _producerPage = basePtr + pageSize;
        _data          = basePtr + (2 * pageSize);
        _dataMask      = (ulong)mapping.DataSize - 1UL;
    }

    // ── Consumer / producer position accessors ───────────────────────────────

    private ref ulong ConsumerPos =>
        ref Unsafe.AsRef<ulong>(_consumerPage);

    private ref readonly ulong ProducerPos =>
        ref Unsafe.AsRef<ulong>(_producerPage);

    // ── Public API ───────────────────────────────────────────────────────────

    /// <summary>
    /// Attempts to dequeue one record from the ring buffer.
    /// </summary>
    /// <param name="record">
    /// On success, a <see cref="RingBufferRecord"/> backed by a pooled
    /// <see cref="ArrayPool{T}"/> buffer.  The caller is responsible for
    /// disposing the record after use.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if a non-discarded record was returned;
    /// <see langword="false"/> if the ring buffer is empty, the next record is
    /// still being written (BUSY), or the record was marked DISCARD.
    /// </returns>
    public bool TryReadRecord(out RingBufferRecord record)
    {
        ulong consPos = Volatile.Read(ref ConsumerPos);
        ulong prodPos = Volatile.Read(ref Unsafe.AsRef<ulong>(_producerPage));

        if (consPos == prodPos)
        {
            record = default;
            return false;
        }

        // Pointer into the (mirrored) data area at the current consumer offset.
        uint* hdrPtr = (uint*)(_data + (consPos & _dataMask));

        // Read the raw header — length + flags in the first uint32.
        uint lenAndFlags = Volatile.Read(ref *hdrPtr);

        if ((lenAndFlags & BusyBit) != 0)
        {
            // Record is still being produced.  Signal the caller to retry.
            record = default;
            return false;
        }

        uint dataLen  = lenAndFlags & LenMask;
        bool discard  = (lenAndFlags & DiscardBit) != 0;

        // Advance past the 8-byte header to the actual event payload.
        byte* payloadPtr = (byte*)hdrPtr + HdrSize;

        if (!discard && dataLen > 0)
        {
            // Copy payload into a pooled buffer before advancing the consumer
            // pointer (advancing makes the kernel free to overwrite this slot).
            byte[] rented = ArrayPool<byte>.Shared.Rent((int)dataLen);
            new ReadOnlySpan<byte>(payloadPtr, (int)dataLen).CopyTo(rented);
            record = new RingBufferRecord(rented, (int)dataLen);
        }
        else
        {
            record = default;
        }

        // Advance consumer position (8-byte aligned record size).
        ulong recordSize = AlignUp((ulong)dataLen + HdrSize, 8UL);
        Volatile.Write(ref ConsumerPos, consPos + recordSize);

        return !discard && dataLen > 0;
    }

    /// <summary>
    /// Drains all currently available records into <paramref name="target"/>.
    /// </summary>
    /// <returns>The number of records written.</returns>
    public int DrainInto(ChannelWriter<RingBufferRecord> target)
    {
        int count = 0;

        while (TryReadRecord(out var record))
        {
            if (!target.TryWrite(record))
            {
                // Channel is full — return the buffer to the pool to avoid a leak.
                record.Dispose();
            }
            else
            {
                count++;
            }
        }

        return count;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong AlignUp(ulong value, ulong alignment) =>
        (value + alignment - 1) & ~(alignment - 1);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _mapping.Dispose();
    }
}
