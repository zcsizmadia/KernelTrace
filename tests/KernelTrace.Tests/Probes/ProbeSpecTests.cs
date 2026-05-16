namespace KernelTrace.Tests.Probes;

public sealed class ProbeSpecTests
{
    // ── TracepointSpec ─────────────────────────────────────────────────────────

    [Test]
    public async Task TracepointSpec_Describe_ReturnsCorrectFormat()
    {
        var spec = new TracepointSpec { Category = "sched", Name = "sched_switch" };
        await Assert.That(spec.Describe()).IsEqualTo("tracepoint/sched/sched_switch");
    }

    [Test]
    public async Task TracepointSpec_Describe_WithLabel_ReturnsLabel()
    {
        var spec = new TracepointSpec { Category = "sched", Name = "sched_switch", Label = "my-label" };
        await Assert.That(spec.Describe()).IsEqualTo("my-label");
    }

    // ── KprobeSpec ────────────────────────────────────────────────────────────

    [Test]
    [Arguments("tcp_connect", false, "kprobe/tcp_connect")]
    [Arguments("tcp_connect", true,  "kretprobe/tcp_connect")]
    public async Task KprobeSpec_Describe_ReturnsCorrectFormat(
        string funcName, bool retProbe, string expected)
    {
        var spec = new KprobeSpec { FunctionName = funcName, ReturnProbe = retProbe };
        await Assert.That(spec.Describe()).IsEqualTo(expected);
    }

    // ── UprobeSpec ────────────────────────────────────────────────────────────

    [Test]
    public async Task UprobeSpec_Describe_IncludesFilenameAndOffset()
    {
        var spec = new UprobeSpec
        {
            BinaryPath = "/usr/lib/x86_64-linux-gnu/libc.so.6",
            Offset = 0x1234,
        };
        string desc = spec.Describe();

        await Assert.That(desc).Contains("libc.so.6");
        await Assert.That(desc).Contains("0x1234");
    }

    [Test]
    public async Task UprobeSpec_ReturnProbe_DescribeContainsUretprobe()
    {
        var spec = new UprobeSpec
        {
            BinaryPath  = "/usr/lib/libfoo.so",
            Offset      = 0xABC,
            ReturnProbe = true,
        };
        await Assert.That(spec.Describe()).Contains("uretprobe");
    }
}
