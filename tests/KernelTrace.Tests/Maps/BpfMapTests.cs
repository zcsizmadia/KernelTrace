using KernelTrace.Maps;
using KernelTrace.Tests.Fakes;

namespace KernelTrace.Tests.Maps;

public sealed class BpfMapTests
{
    // ── Lookup ────────────────────────────────────────────────────────────────

    [Test]
    public async Task Lookup_ExistingKey_ReturnsValue()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);

        // Seed the map data via FakeNativeInterop's raw dict.
        var key   = ToBytes(10u);
        var value = ToBytes(999UL);
        fake.MapData[42][key] = value;

        var map = new BpfMap<uint, ulong>(fake, 42, "test");
        ulong? result = map.Lookup(10u);

        await Assert.That(result).IsEqualTo(999UL);
    }

    [Test]
    public async Task Lookup_MissingKey_ReturnsNull()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        var map  = new BpfMap<uint, ulong>(fake, 42, "test");

        ulong? result = map.Lookup(10u);

        await Assert.That(result).IsNull();
    }

    [Test]
    public async Task TryLookup_ExistingKey_ReturnsTrueAndValue()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        fake.MapData[42][ToBytes(5u)] = ToBytes(77UL);

        var map  = new BpfMap<uint, ulong>(fake, 42, "test");
        bool ok  = map.TryLookup(5u, out ulong v);

        await Assert.That(ok).IsTrue();
        await Assert.That(v).IsEqualTo(77UL);
    }

    [Test]
    public async Task TryLookup_MissingKey_ReturnsFalse()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        var map  = new BpfMap<uint, ulong>(fake, 42, "test");
        bool ok  = map.TryLookup(999u, out _);

        await Assert.That(ok).IsFalse();
    }

    // ── Update ────────────────────────────────────────────────────────────────

    [Test]
    public async Task Update_InsertsNewEntry()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        var map  = new BpfMap<uint, ulong>(fake, 42, "test");

        map.Update(1u, 100UL);

        await Assert.That(map.TryLookup(1u, out ulong v)).IsTrue();
        await Assert.That(v).IsEqualTo(100UL);
    }

    [Test]
    public async Task Update_OverwritesExistingEntry()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        fake.MapData[42][ToBytes(1u)] = ToBytes(50UL);

        var map = new BpfMap<uint, ulong>(fake, 42, "test");
        map.Update(1u, 200UL);

        map.TryLookup(1u, out ulong v);
        await Assert.That(v).IsEqualTo(200UL);
    }

    [Test]
    public async Task Update_NoExist_ThrowsWhenKeyExists()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        fake.MapData[42][ToBytes(1u)] = ToBytes(1UL);

        var map = new BpfMap<uint, ulong>(fake, 42, "test");

        await Assert.That(() => map.Update(1u, 99UL, BpfMapUpdateFlags.NoExist))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Update_Exist_ThrowsWhenKeyAbsent()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        var map  = new BpfMap<uint, ulong>(fake, 42, "test");

        await Assert.That(() => map.Update(99u, 1UL, BpfMapUpdateFlags.Exist))
            .Throws<InvalidOperationException>();
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    [Test]
    public async Task Delete_ExistingKey_ReturnsTrueAndRemovesEntry()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        fake.MapData[42][ToBytes(7u)] = ToBytes(0UL);

        var map  = new BpfMap<uint, ulong>(fake, 42, "test");
        bool ok  = map.Delete(7u);

        await Assert.That(ok).IsTrue();
        await Assert.That(map.TryLookup(7u, out _)).IsFalse();
    }

    [Test]
    public async Task Delete_MissingKey_ReturnsFalse()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        var map  = new BpfMap<uint, ulong>(fake, 42, "test");

        await Assert.That(map.Delete(7u)).IsFalse();
    }

    // ── Iterate ───────────────────────────────────────────────────────────────

    [Test]
    public async Task Iterate_ReturnsAllEntries()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        fake.MapData[42][ToBytes(1u)] = ToBytes(10UL);
        fake.MapData[42][ToBytes(2u)] = ToBytes(20UL);
        fake.MapData[42][ToBytes(3u)] = ToBytes(30UL);

        var map    = new BpfMap<uint, ulong>(fake, 42, "test");
        var result = map.Iterate().ToList();

        await Assert.That(result.Count).IsEqualTo(3);
    }

    [Test]
    public async Task Iterate_EmptyMap_ReturnsEmpty()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        var map  = new BpfMap<uint, ulong>(fake, 42, "test");

        await Assert.That(map.Iterate().ToList()).IsEmpty();
    }

    [Test]
    public async Task IterateAsync_ReturnsAllEntries()
    {
        var fake = MakeFakeWithMap(mapFd: 42, keySize: 4, valueSize: 8);
        fake.MapData[42][ToBytes(10u)] = ToBytes(100UL);
        fake.MapData[42][ToBytes(20u)] = ToBytes(200UL);

        var map  = new BpfMap<uint, ulong>(fake, 42, "test");
        var list = new List<KeyValuePair<uint, ulong>>();
        await foreach (var kv in map.IterateAsync())
        {
            list.Add(kv);
        }

        await Assert.That(list.Count).IsEqualTo(2);
    }

    // ── GetInfo ───────────────────────────────────────────────────────────────

    [Test]
    public async Task GetInfo_ReturnsExpectedMetadata()
    {
        var fake = new FakeNativeInterop();
        fake.MapInfos[42] = new KernelTrace.Interop.NativeMapInfo
        {
            Type = 1, KeySize = 4, ValueSize = 8, MaxEntries = 256,
        };

        var map  = new BpfMap<uint, ulong>(fake, 42, "test");
        var info = map.GetInfo();

        await Assert.That(info.Type).IsEqualTo(1u);
        await Assert.That(info.KeySize).IsEqualTo(4u);
        await Assert.That(info.ValueSize).IsEqualTo(8u);
        await Assert.That(info.MaxEntries).IsEqualTo(256u);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static FakeNativeInterop MakeFakeWithMap(int mapFd, uint keySize, uint valueSize)
    {
        var fake = new FakeNativeInterop();
        fake.MapInfos[mapFd] = new KernelTrace.Interop.NativeMapInfo
        {
            Type = 1, KeySize = keySize, ValueSize = valueSize, MaxEntries = 1024,
        };
        fake.MapData[mapFd] = new Dictionary<byte[], byte[]>(ByteArrayComparer.Instance);
        return fake;
    }

    private static unsafe byte[] ToBytes<T>(T value) where T : unmanaged
    {
        var buf = new byte[System.Runtime.CompilerServices.Unsafe.SizeOf<T>()];
        fixed (byte* dst = buf)
        {
            *(T*)dst = value;
        }

        return buf;
    }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();
        public bool Equals(byte[]? x, byte[]? y) => x.AsSpan().SequenceEqual(y.AsSpan());
        public int GetHashCode(byte[] obj)
        {
            var hc = new HashCode();
            foreach (var b in obj)
            {
                hc.Add(b);
            }

            return hc.ToHashCode();
        }
    }
}
