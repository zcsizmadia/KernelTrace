using KernelTrace.Maps;
using KernelTrace.Tests.Fakes;

namespace KernelTrace.Tests.Maps;

public sealed class StackTraceMapTests
{
    [Test]
    public async Task Lookup_NegativeStackId_ReturnsEmpty()
    {
        var fake = new FakeNativeInterop();
        var map  = new StackTraceMap(fake, 42, 127);

        var result = map.Lookup(-1);

        await Assert.That(result).IsEmpty();
    }

    [Test]
    public async Task Lookup_MissingStackId_ReturnsEmpty()
    {
        var fake = new FakeNativeInterop();
        fake.MapInfos[42] = new KernelTrace.Interop.NativeMapInfo
        {
            Type = 27, KeySize = 4, ValueSize = 1016, MaxEntries = 8192,
        };
        // No data seeded → should return empty gracefully.
        var map = new StackTraceMap(fake, 42, 127);

        var result = map.Lookup(5);

        await Assert.That(result).IsEmpty();
    }

    [Test]
    public async Task MaxDepth_ReflectsConstructorArgument()
    {
        var fake = new FakeNativeInterop();
        var map  = new StackTraceMap(fake, 42, 64);

        await Assert.That(map.MaxDepth).IsEqualTo(64);
    }
}
