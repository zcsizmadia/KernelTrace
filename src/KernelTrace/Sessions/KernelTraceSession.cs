using KernelTrace.Diagnostics;
using KernelTrace.Exceptions;
using KernelTrace.Interop;
using KernelTrace.Probes;
using KernelTrace.RingBuffer;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace KernelTrace.Sessions;

/// <summary>
/// The primary entry point for KernelTrace.  A session owns a loaded eBPF
/// object, one or more probe attachments, and a dedicated ring buffer polling
/// thread that streams kernel events into a bounded
/// <see cref="Channel{T}"/>.
/// </summary>
/// <remarks>
/// <para>
/// Create sessions via the async factory <see cref="CreateAsync(SessionOptions, ILogger{KernelTraceSession}?, CancellationToken)"/> rather than
/// the constructor — the factory validates options, loads the native object,
/// attaches probes, and starts the polling thread atomically.
/// </para>
/// <para>
/// The session is designed to be consumed by a <b>single reader</b>.  Multiple
/// concurrent calls to <see cref="ReadAsync{T}"/> on the same session will
/// compete for records; use separate sessions if you need fan-out.
/// </para>
/// <para>
/// This class is <c>sealed</c> and should be disposed via
/// <c>await using</c> to guarantee the polling thread exits cleanly.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// await using var session = await KernelTraceSession.CreateAsync(new SessionOptions
/// {
///     ProbePath = "./probes/network_monitor.bpf.o",
///     Probes    = [new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" }],
/// });
///
/// await foreach (var ev in session.ReadAsync&lt;SocketConnectEvent&gt;())
/// {
///     Console.WriteLine($"PID {ev.Pid} → port {ev.DstPort}");
/// }
/// </code>
/// </example>
public sealed class KernelTraceSession : IAsyncDisposable
{
    private readonly INativeInterop _interop;
    private readonly SessionOptions _options;
    private readonly ILogger<KernelTraceSession> _logger;
    private readonly KernelProbeHandle _sessionHandle;
    private readonly List<AttachmentHandle> _attachments;
    private readonly RingBufferReader _ringBuffer;
    private readonly Channel<RingBufferRecord> _channel;
    private readonly CancellationTokenSource _cts;
    private readonly Thread _pollingThread;
    private readonly TaskCompletionSource _pollingThreadExited;
    private int _disposed;

    // Set of struct names that have been BTF-validated in this session.
#if NET9_0_OR_GREATER
    private readonly Lock _validatedStructsLock = new();
#else
    private readonly object _validatedStructsLock = new();
#endif
    private readonly HashSet<Type> _validatedStructs = [];

    // ── Metrics ──────────────────────────────────────────────────────────────

    /// <summary>Live metrics for this session (received, dropped, latency).</summary>
    public KernelTraceMetrics Metrics { get; }

    // ── Constructor (private — use CreateAsync) ───────────────────────────────

    private KernelTraceSession(
        INativeInterop interop,
        SessionOptions options,
        KernelProbeHandle sessionHandle,
        List<AttachmentHandle> attachments,
        RingBufferReader ringBuffer,
        ILogger<KernelTraceSession> logger)
    {
        _interop        = interop;
        _options        = options;
        _logger         = logger;
        _sessionHandle  = sessionHandle;
        _attachments    = attachments;
        _ringBuffer     = ringBuffer;
        _cts            = new CancellationTokenSource();
        _pollingThreadExited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Metrics         = new KernelTraceMetrics();

        _channel = Channel.CreateBounded<RingBufferRecord>(new BoundedChannelOptions(options.ChannelCapacity)
        {
            FullMode            = BoundedChannelFullMode.DropOldest,
            SingleWriter        = true,   // only the polling thread writes
            SingleReader        = false,  // ReadAsync<T> callers may pipeline
            AllowSynchronousContinuations = false,
        });

        _pollingThread = new Thread(PollingLoop)
        {
            Name       = $"KernelTrace.Poll[{Path.GetFileNameWithoutExtension(options.ProbePath)}]",
            IsBackground = false,  // keep alive until DisposeAsync completes
            Priority   = options.PollingThreadPriority,
        };
    }

    // ── Factory ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Creates, validates, and starts a new <see cref="KernelTraceSession"/>.
    /// </summary>
    /// <param name="options">Session configuration.</param>
    /// <param name="logger">Optional logger; defaults to a no-op logger.</param>
    /// <param name="cancellationToken">Token to cancel the async setup.</param>
    /// <exception cref="PlatformNotSupportedException">
    /// Thrown on non-Linux operating systems.
    /// </exception>
    /// <exception cref="FileNotFoundException">
    /// Thrown when <see cref="SessionOptions.ProbePath"/> does not exist.
    /// </exception>
    /// <exception cref="NativeInteropException">
    /// Thrown when the eBPF object cannot be loaded (bad bytecode, missing
    /// <c>CAP_BPF</c>, or unsupported kernel version).
    /// </exception>
    [SupportedOSPlatform("linux")]
    public static Task<KernelTraceSession> CreateAsync(
        SessionOptions options,
        ILogger<KernelTraceSession>? logger = null,
        CancellationToken cancellationToken = default) =>
        CreateAsync(options, LibBpfInterop.Instance, logger, cancellationToken);

    /// <summary>
    /// Testability overload — accepts a custom <see cref="INativeInterop"/>.
    /// </summary>
    [SupportedOSPlatform("linux")]
    internal static async Task<KernelTraceSession> CreateAsync(
        SessionOptions options,
        INativeInterop interop,
        ILogger<KernelTraceSession>? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!OperatingSystem.IsLinux() && interop is LibBpfInterop)
        {
            throw new PlatformNotSupportedException(
                "KernelTrace requires Linux. Use a mock INativeInterop for testing on other platforms.");
        }

        if (!File.Exists(options.ProbePath))
        {
            throw new FileNotFoundException(
                $"eBPF object not found: {options.ProbePath}", options.ProbePath);
        }

        logger ??= NullLogger<KernelTraceSession>.Instance;

        logger.LogInformation(
            "Loading eBPF object {ProbePath} with {ProbeCount} probe(s)",
            options.ProbePath, options.Probes.Count);

        // All native calls are off the async state machine to avoid blocking
        // the thread pool for extended periods.
        var session = await Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            // 1. Load the eBPF object into the kernel.
            var sessionHandle = interop.LoadSession(options.ProbePath);

            // 2. Attach probes.
            var attachments = new List<AttachmentHandle>(options.Probes.Count);
            try
            {
                foreach (var probe in options.Probes)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var attachment = probe switch
                    {
                        TracepointSpec tp => interop.AttachTracepoint(sessionHandle, tp.Category, tp.Name),
                        KprobeSpec kp    => interop.AttachKprobe(sessionHandle, kp.FunctionName, kp.ReturnProbe),
                        UprobeSpec up    => interop.AttachUprobe(sessionHandle, up.BinaryPath, up.Offset, up.ReturnProbe, up.ProgramSection),
                        _ => throw new NotSupportedException($"Unsupported probe type: {probe.GetType().Name}"),
                    };

                    attachments.Add(attachment);
                    logger.LogDebug("Attached {Probe}", probe.Describe());
                }
            }
            catch
            {
                // Clean up already-attached probes on partial failure.
                foreach (var a in attachments)
                {
                    a.Dispose();
                }
                sessionHandle.Dispose();
                throw;
            }

            // 3. Apply per-process filter if requested.
            if (options.CurrentProcessOnly)
            {
                uint ownTgid = (uint)Environment.ProcessId;
                interop.SetTgidFilter(sessionHandle, ownTgid);
                logger.LogDebug("Per-process filter active: TGID {Tgid}", ownTgid);
            }

            // 4. Map the ring buffer.
            int rbFd = interop.GetRingBufFd(sessionHandle, options.RingBufferMapName);
            var mapping  = interop.MapRingBuffer(rbFd);
            ulong pageSize = OperatingSystem.IsLinux()
                ? NativeMethods.GetPageSize()
                : 4096UL;                           // fallback for mock implementations

            var ringBuffer = new RingBufferReader(mapping, pageSize);

            return new KernelTraceSession(interop, options, sessionHandle, attachments, ringBuffer, logger);

        }, cancellationToken).ConfigureAwait(false);

        // 4. Start the polling thread.
        session._pollingThread.Start(session._cts.Token);

        logger.LogInformation(
            "KernelTraceSession started. Polling thread: '{ThreadName}'",
            session._pollingThread.Name);

        return session;
    }

    // ── Consumer API ──────────────────────────────────────────────────────────

    /// <summary>
    /// Asynchronously streams kernel events as strongly-typed structs.
    /// </summary>
    /// <typeparam name="T">
    /// An <c>unmanaged</c> struct that matches the memory layout of the eBPF
    /// event struct.  Use <c>[StructLayout(LayoutKind.Sequential, Pack = 1)]</c>
    /// and the KernelTrace source generator to ensure alignment is correct.
    /// </typeparam>
    /// <param name="cancellationToken">
    /// Token to stop consuming events.  Does not stop the session itself.
    /// </param>
    /// <returns>
    /// An async sequence of <typeparamref name="T"/> values.  Each value is
    /// produced by a single struct-copy from the ring buffer's pooled memory.
    /// </returns>
    /// <exception cref="KernelStructMismatchException">
    /// Thrown on the first call if BTF validation is enabled and the C# struct
    /// size does not match the kernel-reported size.
    /// </exception>
    public async IAsyncEnumerable<T> ReadAsync<T>(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
        where T : unmanaged
    {
        ValidateStructLayout<T>();

        await foreach (var record in _channel.Reader
            .ReadAllAsync(cancellationToken)
            .ConfigureAwait(false))
        {
            T value;
            using (record)
            {
                if (record.Length < Unsafe.SizeOf<T>())
                {
                    _logger.LogWarning(
                        "Skipping record: expected >= {Expected} bytes for {Type}, got {Actual}",
                        Unsafe.SizeOf<T>(), typeof(T).Name, record.Length);
                    continue;
                }

                value = record.ReadAs<T>();
            }

            yield return value;
        }
    }

    /// <summary>
    /// Asynchronously streams raw kernel event bytes without struct projection.
    /// Each element is a copy of the record's payload as
    /// <see cref="ReadOnlyMemory{T}">ReadOnlyMemory&lt;byte&gt;</see>.
    /// </summary>
    /// <param name="cancellationToken">
    /// Token to stop consuming events.  Does not stop the session itself.
    /// </param>
    /// <returns>
    /// An async sequence of raw event payloads.  Use
    /// <see cref="System.Runtime.InteropServices.MemoryMarshal.Read{T}"/> or
    /// <see cref="ReadOnlyMemory{T}.Span"/> to interpret the bytes.
    /// </returns>
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    public async IAsyncEnumerable<ReadOnlyMemory<byte>> ReadRawAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await foreach (var record in _channel.Reader
            .ReadAllAsync(cancellationToken)
            .ConfigureAwait(false))
        {
            ReadOnlyMemory<byte> copy;
            using (record)
            {
                copy = record.AsMemory().ToArray();
            }

            yield return copy;
        }
    }

    /// <summary>
    /// High-throughput zero-copy variant.  The handler is called while the
    /// pooled buffer is still live — no struct copy occurs if the handler reads
    /// the data directly from <paramref name="handler"/>'s <c>in T</c> parameter.
    /// </summary>
    /// <typeparam name="T">An <c>unmanaged</c> event struct.</typeparam>
    /// <param name="handler">
    /// A delegate invoked for each event.  The <c>in T</c> parameter is backed
    /// by the pooled buffer; do not store a reference to it beyond the handler call.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task ProcessAsync<T>(
        KernelEventHandler<T> handler,
        CancellationToken cancellationToken = default)
        where T : unmanaged
    {
        ValidateStructLayout<T>();

        await foreach (var record in _channel.Reader
            .ReadAllAsync(cancellationToken)
            .ConfigureAwait(false))
        {
            using (record)
            {
                if (record.Length < Unsafe.SizeOf<T>())
                {
                    continue;
                }

                T value = record.ReadAs<T>();
                await handler(in value, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    // ── Hot-attach / hot-detach (Phase 5) ────────────────────────────────────

    /// <summary>
    /// Attaches an additional probe to the running session without restarting.
    /// </summary>
    /// <returns>
    /// A <see cref="SessionAttachmentToken"/> that can be passed to
    /// <see cref="DetachAsync"/> to remove the probe.
    /// </returns>
    [SupportedOSPlatform("linux")]
    public async Task<SessionAttachmentToken> AttachAsync(
        ProbeSpec probe,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(probe);

        var attachment = await Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            return probe switch
            {
                TracepointSpec tp => _interop.AttachTracepoint(_sessionHandle, tp.Category, tp.Name),
                KprobeSpec kp    => _interop.AttachKprobe(_sessionHandle, kp.FunctionName, kp.ReturnProbe),
                UprobeSpec up    => _interop.AttachUprobe(_sessionHandle, up.BinaryPath, up.Offset, up.ReturnProbe),
                _ => throw new NotSupportedException($"Unsupported probe type: {probe.GetType().Name}"),
            };
        }, cancellationToken).ConfigureAwait(false);

        lock (_validatedStructsLock)
        {
            _attachments.Add(attachment);
        }

        _logger.LogInformation("Hot-attached {Probe}", probe.Describe());
        return new SessionAttachmentToken(attachment);
    }

    /// <summary>
    /// Detaches a probe that was added via <see cref="AttachAsync"/>.
    /// </summary>
    [SupportedOSPlatform("linux")]
    public Task DetachAsync(SessionAttachmentToken token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        return Task.Run(() =>
        {
            _interop.Detach(token.Handle);
            lock (_validatedStructsLock)
            {
                _attachments.Remove(token.Handle);
            }
        }, cancellationToken);
    }

    // ── Polling thread ────────────────────────────────────────────────────────

    private void PollingLoop(object? state)
    {
        var ct = (CancellationToken)(state ?? CancellationToken.None);

        // Create the epoll fd on this thread so it stays local.
        int epollFd = -1;

        try
        {
            // The epoll fd is created here — we need the ring buffer fd.
            // For mock implementations the fd may be -1, so handle gracefully.
            int rbFd = _options.ChannelCapacity > 0 ? GetRingBufFdSafe() : -1;
            if (rbFd >= 0)
            {
                epollFd = _interop.CreateEpoll(rbFd);
            }

            while (!ct.IsCancellationRequested)
            {
                // Block until data is available (or timeout).
                int ready = (epollFd >= 0)
                    ? _interop.Poll(epollFd, _options.PollTimeoutMs)
                    : SimulatePoll(ct);

                if (ct.IsCancellationRequested)
                {
                    break;
                }

                if (ready > 0)
                {
                    int drained = _ringBuffer.DrainInto(_channel.Writer);
                    Metrics.AddReceived(drained);
                }

                Metrics.IncrementPolls();
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during shutdown.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error in ring buffer polling thread");
            _channel.Writer.TryComplete(ex);
            return;
        }
        finally
        {
            if (epollFd >= 0)
            {
                _interop.CloseFd(epollFd);
            }

            _pollingThreadExited.TrySetResult();
        }

        _channel.Writer.TryComplete();
    }

    private int GetRingBufFdSafe()
    {
        try { return _interop.GetRingBufFd(_sessionHandle, _options.RingBufferMapName); }
        catch { return -1; }
    }

    // Poll fallback for mock implementations that don't support epoll.
    private static int SimulatePoll(CancellationToken ct)
    {
        ct.WaitHandle.WaitOne(10);
        return 0;
    }

    // ── BTF struct validation ─────────────────────────────────────────────────

    private void ValidateStructLayout<T>() where T : unmanaged
    {
        if (!_options.ValidateStructLayouts)
        {
            return;
        }

        lock (_validatedStructsLock)
        {
            if (_validatedStructs.Contains(typeof(T)))
            {
                return;
            }

            _validatedStructs.Add(typeof(T));
        }

        // Look for the KernelEvent attribute to get the C struct name.
        var attr = typeof(T).GetCustomAttributes(false)
            .OfType<Events.KernelEventAttribute>()
            .FirstOrDefault();

        if (attr is null) return;   // No attribute — skip BTF check.

        int btfSize = _interop.GetBtfStructSize(_sessionHandle, attr.StructName);
        int csSize  = Unsafe.SizeOf<T>();

        if (btfSize > 0 && btfSize != csSize)
        {
            throw new KernelStructMismatchException(typeof(T).Name, btfSize, csSize);
        }

        _logger.LogDebug(
            "BTF validation OK: {Type} = {Size} bytes", typeof(T).Name, csSize);
    }

    // ── IAsyncDisposable ──────────────────────────────────────────────────────

    /// <summary>
    /// Stops the polling thread, detaches all probes, and releases native resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            return;

        _logger.LogInformation("Disposing KernelTraceSession");

        // Signal the polling thread to exit.
        await _cts.CancelAsync().ConfigureAwait(false);

        // Wait for the polling thread to finish (with a safety timeout).
        await _pollingThreadExited.Task
            .WaitAsync(TimeSpan.FromSeconds(5))
            .ConfigureAwait(false);

        // Release probe attachments.
        foreach (var attachment in _attachments)
        {
            attachment.Dispose();
        }

        _ringBuffer.Dispose();
        _sessionHandle.Dispose();
        _cts.Dispose();

        _logger.LogInformation("KernelTraceSession disposed");
    }
}

/// <summary>
/// Represents a probe attached to a running session via
/// <see cref="KernelTraceSession.AttachAsync"/>.
/// </summary>
public sealed class SessionAttachmentToken
{
    internal AttachmentHandle Handle { get; }

    internal SessionAttachmentToken(AttachmentHandle handle) => Handle = handle;
}

/// <summary>
/// Delegate for the zero-copy <see cref="KernelTraceSession.ProcessAsync{T}"/> API.
/// </summary>
/// <typeparam name="T">The <c>unmanaged</c> event struct type.</typeparam>
public delegate ValueTask KernelEventHandler<T>(in T @event, CancellationToken cancellationToken)
    where T : unmanaged;
