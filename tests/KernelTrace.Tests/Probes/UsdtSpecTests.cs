namespace KernelTrace.Tests.Probes;

public sealed class UsdtSpecTests
{
    [Test]
    public async Task Describe_ReturnsProviderAndName()
    {
        var spec = new UsdtSpec
        {
            BinaryPath = "/usr/bin/python3",
            Provider   = "python",
            Name       = "function__entry",
        };

        await Assert.That(spec.Describe()).IsEqualTo("usdt:python3:python:function__entry");
    }

    [Test]
    public async Task Describe_WithLabel_ReturnsLabel()
    {
        var spec = new UsdtSpec
        {
            BinaryPath = "/usr/bin/python3",
            Provider   = "python",
            Name       = "function__entry",
            Label      = "py-entry",
        };

        await Assert.That(spec.Describe()).IsEqualTo("py-entry");
    }

    [Test]
    public async Task DefaultPid_IsMinusOne()
    {
        var spec = new UsdtSpec
        {
            BinaryPath = "/usr/bin/python3",
            Provider   = "python",
            Name       = "function__entry",
        };

        await Assert.That(spec.Pid).IsEqualTo(-1);
    }

    [Test]
    public async Task ProgramSection_DefaultsToNull()
    {
        var spec = new UsdtSpec
        {
            BinaryPath = "/usr/bin/python3",
            Provider   = "python",
            Name       = "function__entry",
        };

        await Assert.That(spec.ProgramSection).IsNull();
    }
}
