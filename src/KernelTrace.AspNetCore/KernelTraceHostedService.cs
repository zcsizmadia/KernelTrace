using KernelTrace.Sessions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Runtime.Versioning;

namespace KernelTrace.AspNetCore;

/// <summary>
/// An <see cref="IHostedService"/> that owns the <see cref="KernelTraceSession"/>
/// lifetime, starting it when the host starts and disposing it on shutdown.
/// </summary>
/// <remarks>
/// Register via
/// <see cref="KernelTraceServiceCollectionExtensions.AddKernelTrace"/>;
/// do not instantiate directly.
/// </remarks>
public sealed class KernelTraceHostedService : IHostedService, IAsyncDisposable
{
    private readonly SessionOptions _options;
    private readonly ILogger<KernelTraceSession> _sessionLogger;
    private KernelTraceSession? _session;

    /// <summary>
    /// The running <see cref="KernelTraceSession"/>.
    /// Available after <see cref="StartAsync"/> completes.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown if accessed before the host has started.
    /// </exception>
    public KernelTraceSession Session =>
        _session ?? throw new InvalidOperationException(
            "KernelTraceSession is not yet started. Ensure the host is running.");

    /// <inheritdoc cref="KernelTraceHostedService"/>
    public KernelTraceHostedService(
        SessionOptions options,
        ILogger<KernelTraceSession> sessionLogger)
    {
        _options       = options;
        _sessionLogger = sessionLogger;
    }

    /// <inheritdoc/>
    [SupportedOSPlatform("linux")]
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _session = await KernelTraceSession.CreateAsync(
            _options, _sessionLogger, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => ValueTask.CompletedTask.AsTask();

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_session is not null)
        {
            await _session.DisposeAsync().ConfigureAwait(false);
        }
    }
}
