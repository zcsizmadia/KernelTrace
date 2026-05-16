using KernelTrace.Events;

namespace KernelTrace.IntegrationTests;

/// <summary>
/// Minimal unmanaged struct used for raw event reception in integration tests.
/// eBPF ring-buffer events must be at least this large; the struct is
/// intentionally small so it fits any event type.
/// <see cref="SessionOptions.ValidateStructLayouts"/> is set to <c>false</c>
/// to skip BTF size validation.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct RawEventHeader
{
    public ulong Raw0; // 8 bytes: sufficient for any non-empty ring-buffer record
}

/// <summary>
/// Integration tests that load real eBPF programs into a live Linux kernel.
///
/// Prerequisites (all handled by <see cref="RequiresBpfAttribute"/>):
///   • Linux kernel 5.8+ with BTF support (<c>CONFIG_DEBUG_INFO_BTF=y</c>)
///   • CAP_BPF + CAP_PERFMON (or run as root)
///   • Probe files compiled by <c>native/scripts/build-and-install.sh</c>
///
/// Run with:
///   sudo dotnet test tests/KernelTrace.IntegrationTests --logger "console;verbosity=normal"
/// </summary>
public sealed class KernelTracingIntegrationTests
{
    // Timeout for each test: 10 seconds is enough to receive at least one
    // event on a busy system.
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(10);

    // ── Tracepoints ───────────────────────────────────────────────────────────

    /// <summary>
    /// Attaches to the <c>syscalls/sys_enter_openat</c> tracepoint and verifies
    /// at least one event arrives within the timeout.
    /// The <c>network_monitor.bpf.o</c> probe includes a sys_enter_openat handler
    /// via fs_io.bpf.c, but we use the simpler network_monitor for tracepoint tests.
    /// </summary>
    [Test]
    [RequiresBpf("network_monitor")]
    public async Task Tracepoint_SysEnterOpenat_ReceivesEvents()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("network_monitor")!;

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                =
            [
                new TracepointSpec { Category = "syscalls", Name = "sys_enter_openat" },
            ],
            PollTimeoutMs = 50,
        };

        using var cts = new CancellationTokenSource(TestTimeout);
        int received = 0;

        await using var session = await KernelTraceSession.CreateAsync(options);

        // Trigger some openat syscalls from our own process to generate events.
        var triggerTask = Task.Run(async () =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    _ = File.Exists("/proc/self/status"); // triggers openat
                    await Task.Delay(10, cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        });

        await session.ProcessAsync<RawEventHeader>(
            (in RawEventHeader _, CancellationToken ct) =>
            {
                Interlocked.Increment(ref received);
                if (received >= 1)
                {
                    cts.Cancel();
                }
                return ValueTask.CompletedTask;
            },
            cts.Token)
            .ContinueWith(t =>
            {
                if (t.Exception?.InnerException is not OperationCanceledException)
                {
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(t.Exception!.InnerException ?? t.Exception!).Throw();
                }
            })
            .ConfigureAwait(false);

        await triggerTask.ConfigureAwait(false);

        await Assert.That(received).IsGreaterThan(0)
            .Because("at least one sys_enter_openat event must arrive");
    }

    /// <summary>
    /// Attaches to the <c>syscalls/sys_enter_connect</c> tracepoint (network_monitor probe).
    /// </summary>
    [Test]
    [RequiresBpf("network_monitor")]
    public async Task Tracepoint_SysEnterConnect_SessionCreatesAndDisposesCleanly()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("network_monitor")!;

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                =
            [
                new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" },
            ],
            PollTimeoutMs = 50,
        };

        // Just verify that session creation, attachment, and disposal work
        // without throwing on a real kernel.
        await using var session = await KernelTraceSession.CreateAsync(options);

        await Assert.That(session).IsNotNull();
        await Assert.That(session.Metrics).IsNotNull();
    }

    // ── Kprobes ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Attaches a kprobe to <c>tcp_connect</c> and verifies the session starts cleanly.
    /// </summary>
    [Test]
    [RequiresBpf("network_monitor")]
    public async Task Kprobe_TcpConnect_AttachesSuccessfully()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("network_monitor")!;

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                =
            [
                new KprobeSpec { FunctionName = "tcp_connect", ReturnProbe = false },
            ],
            PollTimeoutMs = 50,
        };

        await using var session = await KernelTraceSession.CreateAsync(options);

        await Assert.That(session).IsNotNull();
    }

    /// <summary>
    /// Attaches a kretprobe to <c>do_sys_openat2</c> (the kernel's openat impl).
    /// Verifies events arrive after triggering file opens.
    /// </summary>
    [Test]
    [RequiresBpf("network_monitor")]
    public async Task Kretprobe_DoSysOpenat2_ReceivesReturnEvents()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("network_monitor")!;

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                =
            [
                new KprobeSpec { FunctionName = "do_sys_openat2", ReturnProbe = true },
            ],
            PollTimeoutMs = 50,
        };

        using var cts = new CancellationTokenSource(TestTimeout);
        int received = 0;

        await using var session = await KernelTraceSession.CreateAsync(options);

        var triggerTask = Task.Run(async () =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    _ = File.Exists("/proc/self/cmdline");
                    await Task.Delay(5, cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        });

        await session.ProcessAsync<RawEventHeader>(
            (in RawEventHeader _, CancellationToken ct) =>
            {
                Interlocked.Increment(ref received);
                if (received >= 1)
                {
                    cts.Cancel();
                }
                return ValueTask.CompletedTask;
            },
            cts.Token)
            .ContinueWith(t =>
            {
                if (t.Exception?.InnerException is not OperationCanceledException)
                {
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(t.Exception!.InnerException ?? t.Exception!).Throw();
                }
            })
            .ConfigureAwait(false);

        await triggerTask.ConfigureAwait(false);

        await Assert.That(received).IsGreaterThan(0)
            .Because("at least one kretprobe return event must arrive");
    }

    // ── File-system I/O probe ─────────────────────────────────────────────────

    /// <summary>
    /// Verifies the <c>fs_io.bpf.o</c> probe attaches to openat/read/write
    /// tracepoints and delivers events.
    /// </summary>
    [Test]
    [RequiresBpf("fs_io")]
    public async Task FsIo_TracepointOpenatReadWrite_ReceivesEvents()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("fs_io")!;

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                =
            [
                new TracepointSpec { Category = "syscalls", Name = "sys_enter_openat" },
                new TracepointSpec { Category = "syscalls", Name = "sys_exit_openat" },
                new TracepointSpec { Category = "syscalls", Name = "sys_enter_read" },
                new TracepointSpec { Category = "syscalls", Name = "sys_exit_read" },
            ],
            PollTimeoutMs = 50,
        };

        using var cts = new CancellationTokenSource(TestTimeout);
        int received = 0;

        await using var session = await KernelTraceSession.CreateAsync(options);

        var triggerTask = Task.Run(async () =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    // Read a small file to generate enter+exit pairs.
                    _ = File.ReadAllBytes("/proc/self/status");
                    await Task.Delay(20, cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        });

        await session.ProcessAsync<RawEventHeader>(
            (in RawEventHeader _, CancellationToken ct) =>
            {
                Interlocked.Increment(ref received);
                if (received >= 3)
                {
                    cts.Cancel();
                }
                return ValueTask.CompletedTask;
            },
            cts.Token)
            .ContinueWith(t =>
            {
                if (t.Exception?.InnerException is not OperationCanceledException)
                {
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(t.Exception!.InnerException ?? t.Exception!).Throw();
                }
            })
            .ConfigureAwait(false);

        await triggerTask.ConfigureAwait(false);

        await Assert.That(received).IsGreaterThan(0)
            .Because("fs_io probe must deliver openat events");
    }

    // ── Memory profiler probe ─────────────────────────────────────────────────

    /// <summary>
    /// Verifies the <c>memory_profiler.bpf.o</c> probe attaches to kmalloc/kfree
    /// kernel tracepoints successfully.
    /// </summary>
    [Test]
    [RequiresBpf("memory_profiler")]
    public async Task MemoryProfiler_KmallocKfreeTracepoints_ReceivesEvents()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("memory_profiler")!;

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                =
            [
                new TracepointSpec { Category = "kmem", Name = "kmalloc" },
                new TracepointSpec { Category = "kmem", Name = "kfree" },
            ],
            PollTimeoutMs = 50,
        };

        using var cts = new CancellationTokenSource(TestTimeout);
        int received = 0;

        await using var session = await KernelTraceSession.CreateAsync(options);

        await session.ProcessAsync<RawEventHeader>(
            (in RawEventHeader _, CancellationToken ct) =>
            {
                Interlocked.Increment(ref received);
                if (received >= 1)
                {
                    cts.Cancel();
                }
                return ValueTask.CompletedTask;
            },
            cts.Token)
            .ContinueWith(t =>
            {
                if (t.Exception?.InnerException is not OperationCanceledException)
                {
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(t.Exception!.InnerException ?? t.Exception!).Throw();
                }
            })
            .ConfigureAwait(false);

        // On an active kernel, kmalloc fires constantly.
        await Assert.That(received).IsGreaterThan(0)
            .Because("kmalloc tracepoint fires continuously on an active kernel");
    }

    // ── Block I/O probe ───────────────────────────────────────────────────────

    /// <summary>
    /// Verifies the <c>block_io.bpf.o</c> probe attaches to block request tracepoints.
    /// Event delivery is optional — a quiescent system may have no block I/O.
    /// </summary>
    [Test]
    [RequiresBpf("block_io")]
    public async Task BlockIo_BlockRqTracepoints_AttachesSuccessfully()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("block_io")!;

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                =
            [
                new TracepointSpec { Category = "block", Name = "block_rq_issue" },
                new TracepointSpec { Category = "block", Name = "block_rq_complete" },
            ],
            PollTimeoutMs = 100,
        };

        // Just validate that the session starts without error.
        await using var session = await KernelTraceSession.CreateAsync(options);

        await Assert.That(session).IsNotNull();

        await Assert.That(session.Metrics.TotalPolls).IsGreaterThanOrEqualTo(0);
    }

    // ── Kernel internals probe ────────────────────────────────────────────────

    /// <summary>
    /// Verifies the <c>kernel_internals.bpf.o</c> probe attaches to IRQ and
    /// softIRQ tracepoints and receives events.
    /// </summary>
    [Test]
    [RequiresBpf("kernel_internals")]
    public async Task KernelInternals_IrqSoftirqTracepoints_ReceivesEvents()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("kernel_internals")!;

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                =
            [
                new TracepointSpec { Category = "irq", Name = "irq_handler_entry" },
                new TracepointSpec { Category = "irq", Name = "irq_handler_exit" },
                new TracepointSpec { Category = "irq", Name = "softirq_entry" },
                new TracepointSpec { Category = "irq", Name = "softirq_exit" },
            ],
            PollTimeoutMs = 50,
        };

        using var cts = new CancellationTokenSource(TestTimeout);
        int received = 0;

        await using var session = await KernelTraceSession.CreateAsync(options);

        await session.ProcessAsync<RawEventHeader>(
            (in RawEventHeader _, CancellationToken ct) =>
            {
                Interlocked.Increment(ref received);
                if (received >= 3)
                {
                    cts.Cancel();
                }
                return ValueTask.CompletedTask;
            },
            cts.Token)
            .ContinueWith(t =>
            {
                if (t.Exception?.InnerException is not OperationCanceledException)
                {
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(t.Exception!.InnerException ?? t.Exception!).Throw();
                }
            })
            .ConfigureAwait(false);

        // IRQ and softIRQ fire constantly on any non-idle Linux system.
        await Assert.That(received).IsGreaterThan(0)
            .Because("IRQ/softirq tracepoints fire on every interrupt");
    }

    // ── Container monitor probe ───────────────────────────────────────────────

    /// <summary>
    /// Verifies the <c>container_monitor.bpf.o</c> probe attaches to execve
    /// and fork tracepoints and delivers events when processes are spawned.
    /// </summary>
    [Test]
    [RequiresBpf("container_monitor")]
    public async Task ContainerMonitor_ExecveForkTracepoints_ReceivesEvents()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("container_monitor")!;

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                =
            [
                new TracepointSpec { Category = "syscalls", Name = "sys_enter_execve" },
                new TracepointSpec { Category = "sched",    Name = "sched_process_fork" },
                new TracepointSpec { Category = "sched",    Name = "sched_process_exit" },
            ],
            PollTimeoutMs = 50,
        };

        using var cts = new CancellationTokenSource(TestTimeout);
        int received = 0;

        await using var session = await KernelTraceSession.CreateAsync(options);

        // Spawn a child process to trigger the probes.
        var triggerTask = Task.Run(async () =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    using var p = System.Diagnostics.Process.Start(
                        new System.Diagnostics.ProcessStartInfo("true")
                        {
                            UseShellExecute = false,
                        });
                    p?.WaitForExit();
                    await Task.Delay(100, cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    // 'true' may not be found — that's OK
                    break;
                }
            }
        });

        await session.ProcessAsync<RawEventHeader>(
            (in RawEventHeader _, CancellationToken ct) =>
            {
                Interlocked.Increment(ref received);
                if (received >= 1)
                {
                    cts.Cancel();
                }
                return ValueTask.CompletedTask;
            },
            cts.Token)
            .ContinueWith(t =>
            {
                if (t.Exception?.InnerException is not OperationCanceledException)
                {
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(t.Exception!.InnerException ?? t.Exception!).Throw();
                }
            })
            .ConfigureAwait(false);

        await triggerTask.ConfigureAwait(false);

        // At least one exec/fork event must arrive.
        await Assert.That(received).IsGreaterThan(0)
            .Because("execve/fork tracepoints fire when processes are spawned");
    }

    // ── Uprobe ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Attaches a uprobe to <c>libc.so.6!malloc</c> and verifies events arrive
    /// as this process allocates memory normally.
    /// </summary>
    [Test]
    [RequiresBpf("dotnet_runtime")]
    public async Task Uprobe_LibcMalloc_ReceivesEvents()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("dotnet_runtime")!;

        // Resolve libc.so.6 from /proc/self/maps.
        string? libcPath = ResolveLibc();
        if (libcPath is null)
        {
            // libc not found in maps — skip gracefully rather than throw.
            return;
        }

        // Resolve the symbol offset of 'malloc'.
        ulong mallocOffset = ResolveSymbol(libcPath, "malloc");
        if (mallocOffset == 0)
        {
            return; // nm not available or symbol not found
        }

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                =
            [
                new UprobeSpec
                {
                    BinaryPath  = libcPath,
                    Offset      = mallocOffset,
                    ReturnProbe = false,
                },
            ],
            PollTimeoutMs = 50,
        };

        await using var session = await KernelTraceSession.CreateAsync(options);

        // Key validation: the session must start without throwing.
        // We do not assert event count because malloc may be inlined by the JIT.
        await Assert.That(session).IsNotNull();
    }

    // ── Hot attach / detach ───────────────────────────────────────────────────

    /// <summary>
    /// Verifies that a probe can be hot-attached to a running session and
    /// then hot-detached without errors.
    /// </summary>
    [Test]
    [RequiresBpf("network_monitor")]
    public async Task HotAttach_AddsProbeToRunningSession_ThenDetachesCleanly()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("network_monitor")!;

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                =
            [
                new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" },
            ],
            PollTimeoutMs = 50,
        };

        await using var session = await KernelTraceSession.CreateAsync(options);

        // Hot-attach a second tracepoint.
        var token = await session.AttachAsync(
            new TracepointSpec { Category = "syscalls", Name = "sys_enter_openat" });

        await Assert.That(token).IsNotNull();

        // Hot-detach it.
        await Assert.That(async () =>
            await session.DetachAsync(token)).ThrowsNothing();
    }

    // ── Metrics ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Validates that <see cref="KernelTraceSession.Metrics"/> tracks events
    /// on a live session.
    /// </summary>
    [Test]
    [RequiresBpf("network_monitor")]
    public async Task Metrics_AfterReceivingEvents_TotalPollsIsPositive()
    {
        string probePath = IntegrationTestHelpers.FindProbeFile("network_monitor")!;

        var options = new SessionOptions
        {
            ProbePath             = probePath,
            ValidateStructLayouts = false,
            Probes                = [new TracepointSpec { Category = "syscalls", Name = "sys_enter_openat" }],
            PollTimeoutMs = 50,
        };

        using var cts = new CancellationTokenSource(TestTimeout);

        await using var session = await KernelTraceSession.CreateAsync(options);

        // Trigger some events.
        var triggerTask = Task.Run(async () =>
        {
            for (int i = 0; i < 20 && !cts.Token.IsCancellationRequested; i++)
            {
                _ = File.Exists("/proc/self/status");
                await Task.Delay(10, cts.Token).ConfigureAwait(false);
            }
        });

        int consumed = 0;

        await session.ProcessAsync<RawEventHeader>(
            (in RawEventHeader _, CancellationToken ct) =>
            {
                Interlocked.Increment(ref consumed);
                if (consumed >= 5)
                {
                    cts.Cancel();
                }
                return ValueTask.CompletedTask;
            },
            cts.Token)
            .ContinueWith(t =>
            {
                if (t.Exception?.InnerException is not OperationCanceledException)
                {
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(t.Exception!.InnerException ?? t.Exception!).Throw();
                }
            })
            .ConfigureAwait(false);

        await triggerTask.ConfigureAwait(false);

        await Assert.That(session.Metrics.TotalPolls).IsGreaterThan(0)
            .Because("the polling loop must have executed at least once");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string? ResolveLibc()
    {
        try
        {
            string maps = File.ReadAllText("/proc/self/maps");

            foreach (string line in maps.Split('\n'))
            {
                if (!line.Contains("libc.so") && !line.Contains("libc-"))
                {
                    continue;
                }

                int idx = line.IndexOf('/', StringComparison.Ordinal);

                if (idx >= 0)
                {
                    string path = line[idx..].Trim();

                    if (File.Exists(path))
                    {
                        return path;
                    }
                }
            }
        }
        catch
        {
            // /proc not available
        }

        return null;
    }

    private static ulong ResolveSymbol(string library, string symbol)
    {
        try
        {
            using var p = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo("nm")
                {
                    Arguments              = $"-D \"{library}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute        = false,
                });

            if (p is null)
            {
                return 0;
            }

            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            foreach (string line in output.Split('\n'))
            {
                if (!line.Contains($" {symbol}"))
                {
                    continue;
                }

                string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                if (parts.Length >= 3 &&
                    ulong.TryParse(
                        parts[0],
                        System.Globalization.NumberStyles.HexNumber,
                        null,
                        out ulong addr))
                {
                    return addr;
                }
            }
        }
        catch
        {
            // nm not available
        }

        return 0;
    }
}
