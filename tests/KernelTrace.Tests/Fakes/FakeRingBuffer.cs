using System.Runtime.InteropServices;
using KernelTrace.Interop;

namespace KernelTrace.Tests.Fakes;

/// <summary>
/// An in-memory ring buffer for unit tests.
/// Simulates the kernel ring buffer memory layout without any native calls.
/// </summary>
internal sealed unsafe class FakeRingBuffer : IDisposable
{
    // Page size used in tests (fixed for determinism).
    internal const int TestPageSize = 4096;

    // Data section: 64 KB (must be power of two).
    internal const int DataSize = 65_536;

    // Total allocation: consumer + producer + 2x data (mirrored).
    private const int TotalSize = TestPageSize + TestPageSize + (2 * DataSize);

    private readonly byte[] _memory;
    private GCHandle _pin;
    private byte* _basePtr;
    private ulong _producerPos;
    private bool _disposed;

    public FakeRingBuffer()
    {
        _memory = GC.AllocateArray<byte>(TotalSize, pinned: true);
        _pin = GCHandle.Alloc(_memory, GCHandleType.Pinned);
        _basePtr = (byte*)_pin.AddrOfPinnedObject();
        _producerPos = 0;
    }

    // ── Pointers into the memory layout ──────────────────────────────────────

    private ulong* ConsumerPos => (ulong*)_basePtr;
    private ulong* ProducerPos => (ulong*)(_basePtr + TestPageSize);
    private byte*  Data        => _basePtr + (2 * TestPageSize);

    // ── Internal API used by FakeNativeInterop ────────────────────────────────

    /// <summary>
    /// Creates a <see cref="MappedRingBuffer"/> that points to this fake memory.
    /// </summary>
    internal MappedRingBuffer CreateMapping() =>
        new(_basePtr, (nuint)TotalSize, (nuint)DataSize);

    /// <summary>
    /// Enqueues a record into the fake ring buffer (simulates the kernel side).
    /// </summary>
    /// <param name="payload">The event payload bytes.</param>
    public void Enqueue(ReadOnlySpan<byte> payload)
    {
        uint len = (uint)payload.Length;
        ulong recordSize = AlignUp(len + 8UL, 8UL);
        ulong mask = DataSize - 1UL;

        byte* slot = Data + (_producerPos & mask);

        // Write header: len (lower 30 bits), no busy/discard flags.
        *(uint*)slot = len;         // first uint32: len
        *((uint*)slot + 1) = 0;    // second uint32: pg_off (unused by reader)

        // Write payload after 8-byte header.
        payload.CopyTo(new Span<byte>(slot + 8, (int)len));

        _producerPos += recordSize;

        // Update the producer position with a memory barrier.
        Volatile.Write(ref *ProducerPos, _producerPos);
    }

    /// <summary>Enqueues a struct value as its raw bytes.</summary>
    public void Enqueue<T>(T value) where T : unmanaged
    {
        var bytes = MemoryMarshal.AsBytes(new ReadOnlySpan<T>(ref value));
        Enqueue(bytes);
    }

    /// <summary>Resets consumer and producer positions.</summary>
    public void Reset()
    {
        Volatile.Write(ref *ConsumerPos, 0UL);
        Volatile.Write(ref *ProducerPos, 0UL);
        _producerPos = 0;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_pin.IsAllocated)
        {
            _pin.Free();
        }
    }

    private static ulong AlignUp(ulong value, ulong alignment) =>
        (value + alignment - 1) & ~(alignment - 1);
}
