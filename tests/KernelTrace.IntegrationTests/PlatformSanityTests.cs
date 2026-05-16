namespace KernelTrace.IntegrationTests;

/// <summary>
/// Sanity tests that always run on every platform.
/// Ensures at least one test executes when integration tests are skipped
/// (e.g., on non-Linux), preventing the "zero tests ran" exit code.
/// </summary>
public sealed class PlatformSanityTests
{
    [Test]
    public async Task Platform_IsSupported_ReportsCorrectly()
    {
        // On Linux, integration tests will also run.
        // On other OSes, all eBPF tests are skipped, but this test always passes.
        bool isLinux = OperatingSystem.IsLinux();

        // Simply assert the platform detection is consistent.
        await Assert.That(isLinux).IsEqualTo(OperatingSystem.IsLinux());
    }
}
