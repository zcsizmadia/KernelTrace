namespace KernelTrace.IntegrationTests;

/// <summary>
/// TUnit skip condition: skips a test when NOT running on Linux.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
internal sealed class LinuxOnlyAttribute : SkipAttribute
{
    public LinuxOnlyAttribute()
        : base("Requires Linux — skipped on this platform.")
    {
    }

    public override Task<bool> ShouldSkip(TestRegisteredContext context)
    {
        return Task.FromResult(!OperatingSystem.IsLinux());
    }
}

/// <summary>
/// TUnit skip condition: skips a test when CAP_BPF is not available or a
/// required probe file is missing.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
internal sealed class RequiresBpfAttribute : SkipAttribute
{
    private readonly string _probeName;

    public RequiresBpfAttribute(string probeName)
        : base("Requires CAP_BPF capability and compiled eBPF probe files.")
    {
        _probeName = probeName;
    }

    public override Task<bool> ShouldSkip(TestRegisteredContext context)
    {
        if (!OperatingSystem.IsLinux())
        {
            return Task.FromResult(true);
        }

        if (!IntegrationTestHelpers.HasBpfCapability())
        {
            return Task.FromResult(true);
        }

        bool probeFound = IntegrationTestHelpers.FindProbeFile(_probeName) is not null;
        return Task.FromResult(!probeFound);
    }
}
