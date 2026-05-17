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

    public override async Task<bool> ShouldSkip(TestRegisteredContext context)
    {
        if (!OperatingSystem.IsLinux()) return true;
        if (!IntegrationTestHelpers.HasBpfCapability()) return true;

        string? probePath = IntegrationTestHelpers.FindProbeFile(_probeName);
        if (probePath is null) return true;

        // Attempt a trial load to catch kernel-incompatible probes before the
        // test body runs.  Only skip for known "this kernel can't run this probe"
        // error codes so that real bugs (struct mismatches, ENOMEM, etc.) still
        // surface as failures.
        //
        //  -13  EACCES  kernel LSM / security policy blocks this probe type
        //               (e.g. block_io on some Azure x64 kernels)
        //  -22  EINVAL  BPF program invalid for this architecture or kernel
        //               version (e.g. memory_profiler / uprobe on arm64)
        try
        {
            var opts = new SessionOptions { ProbePath = probePath, ValidateStructLayouts = false };
            await using var session = await KernelTraceSession.CreateAsync(opts);
            return false; // probe loaded — let the test run
        }
        catch (NativeInteropException ex) when (ex.NativeErrorCode is -13 or -22)
        {
            // Print the exact error so it is visible in CI logs even though the
            // test itself is marked skipped rather than failed.
            Console.WriteLine(
                $"[RequiresBpf] Skipping '{_probeName}' probe — kernel incompatibility: {ex.Message}");
            return true;
        }
        // Any other NativeInteropException (ENOMEM, unexpected verifier error,
        // …) is NOT caught here and will propagate, causing the test to fail
        // visibly rather than silently disappear as a skip.
    }
}

/// <summary>
/// TUnit skip condition: skips a test when running inside a CI environment
/// (i.e. the <c>CI</c> environment variable is set to <c>true</c>).
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
internal sealed class SkipInCiAttribute : SkipAttribute
{
    public SkipInCiAttribute(string reason)
        : base(reason)
    {
    }

    public override Task<bool> ShouldSkip(TestRegisteredContext context)
    {
        bool inCi = string.Equals(
            Environment.GetEnvironmentVariable("CI"),
            "true",
            StringComparison.OrdinalIgnoreCase);
        return Task.FromResult(inCi);
    }
}
