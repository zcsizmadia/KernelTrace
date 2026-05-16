namespace KernelTrace.RingBuffer;

/// <summary>
/// A pooled, reference-counted byte slice that wraps one record read from the
/// eBPF ring buffer.  The underlying <c>byte[]</c> is rented from
/// <see cref="ArrayPool{T}.Shared"/> and returned on <see cref="Dispose"/>.
/// </summary>
/// <remarks>
/// <para>
/// Consumers <b>must</b> call <see cref="Dispose"/> (or use the record inside a
/// <c>using</c> block) after they have finished with the data.  Failing to do so
/// leaks pooled memory.
/// </para>
/// <para>
/// Records are value types — copy semantics apply.  Only one copy should call
/// <see cref="Dispose"/>.
/// </para>
/// </remarks>
public readonly struct RingBufferRecord : IDisposable
{
    private readonly byte[] _buffer;

    internal RingBufferRecord(byte[] pooledBuffer, int length)
    {
        _buffer = pooledBuffer;
        Length = length;
    }

    /// <summary>Length of the event payload in bytes.</summary>
    public int Length { get; }

    /// <summary>
    /// Returns a <see cref="ReadOnlySpan{T}"/> view of the event payload.
    /// The span is only valid while the record has not been disposed.
    /// </summary>
    public ReadOnlySpan<byte> AsSpan() => _buffer.AsSpan(0, Length);

    /// <summary>
    /// Returns a <see cref="ReadOnlyMemory{T}"/> view of the event payload.
    /// The memory is only valid while the record has not been disposed.
    /// </summary>
    public ReadOnlyMemory<byte> AsMemory() => _buffer.AsMemory(0, Length);

    /// <summary>
    /// Projects the payload bytes into a <typeparamref name="T"/> struct using
    /// <see cref="MemoryMarshal.Read{T}"/>.  This performs exactly one struct-copy
    /// and does not allocate.
    /// </summary>
    /// <typeparam name="T">
    /// An <c>unmanaged</c> struct whose size must be ≤ <see cref="Length"/>.
    /// </typeparam>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the record is too short to hold a <typeparamref name="T"/>.
    /// </exception>
    public T ReadAs<T>() where T : unmanaged
    {
        int size = Unsafe.SizeOf<T>();
        if (Length < size)
        {
            ThrowTooShort(typeof(T).Name, size, Length);
        }

        return MemoryMarshal.Read<T>(AsSpan());
    }

    /// <summary>Returns the rented array to <see cref="ArrayPool{T}.Shared"/>.</summary>
    public void Dispose() => ArrayPool<byte>.Shared.Return(_buffer);

    [DoesNotReturn]
    private static void ThrowTooShort(string typeName, int needed, int actual) =>
        throw new InvalidOperationException(
            $"Cannot project record into '{typeName}': need {needed} bytes, record has {actual} bytes.");
}
