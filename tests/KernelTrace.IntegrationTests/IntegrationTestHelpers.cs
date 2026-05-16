namespace KernelTrace.IntegrationTests;

/// <summary>
/// Helpers shared across integration tests.
/// </summary>
internal static class IntegrationTestHelpers
{
    // ── Probe file resolution ─────────────────────────────────────────────────

    /// <summary>
    /// Locates a compiled eBPF object file by searching the conventional
    /// output locations produced by <c>native/scripts/build-and-install.sh</c>.
    /// </summary>
    /// <param name="probeName">File stem, e.g. <c>"network_monitor"</c>.</param>
    /// <returns>Absolute path, or <c>null</c> if not found.</returns>
    internal static string? FindProbeFile(string probeName)
    {
        string fileName = $"{probeName}.bpf.o";

        // Search order: RID-specific runtimes folder → CWD siblings.
        string rid = RuntimeInformation.RuntimeIdentifier; // e.g. linux-x64
        string repoRoot = FindRepoRoot(AppContext.BaseDirectory) ?? ".";

        string[] candidates =
        [
            Path.Combine(repoRoot, "runtimes", rid, "native", fileName),
            Path.Combine(repoRoot, "native", "build", fileName),
            Path.Combine(AppContext.BaseDirectory, fileName),
            Path.Combine("/usr/local/share/kerneltrace", fileName),
        ];

        foreach (string candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    /// <summary>
    /// Returns whether the current process has the privileges needed to load
    /// eBPF programs (<c>CAP_BPF</c> + <c>CAP_PERFMON</c>, or <c>root</c>).
    /// </summary>
    internal static bool HasBpfCapability()
    {
        if (!OperatingSystem.IsLinux())
        {
            return false;
        }

        // A quick heuristic: try reading /proc/self/status and look for
        // CapEff (effective capabilities).  A full capability check would
        // require P/Invoke into libcap; this is sufficient for CI.
        try
        {
            string status = File.ReadAllText("/proc/self/status");
            foreach (string line in status.Split('\n'))
            {
                if (!line.StartsWith("CapEff:", StringComparison.Ordinal))
                {
                    continue;
                }

                // CapEff is a hex bitmask.  CAP_BPF=39 (bit 39), CAP_PERFMON=38.
                string hex = line["CapEff:".Length..].Trim();
                if (!ulong.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out ulong caps))
                {
                    return false;
                }

                // Bit 39 = CAP_BPF, bit 38 = CAP_PERFMON.
                const ulong capBpf     = 1UL << 39;
                const ulong capPerfmon = 1UL << 38;
                return (caps & capBpf) != 0 && (caps & capPerfmon) != 0;
            }
        }
        catch
        {
            // Fall through — assume no capability.
        }

        return false;
    }

    /// <summary>
    /// Walks up the directory tree to find the repo root
    /// (identified by the presence of <c>KernelTrace.sln</c>).
    /// </summary>
    private static string? FindRepoRoot(string startDir)
    {
        DirectoryInfo? dir = new(startDir);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "KernelTrace.slnx")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        return null;
    }
}
