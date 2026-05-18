using KernelTrace.Sessions;
using Microsoft.Extensions.Logging;

namespace KernelTrace;

/// <summary>
/// Extension methods that integrate <see cref="KernelTraceSession"/> event
/// streams with <see cref="ILogger"/>.
/// </summary>
public static class KernelTraceLoggerExtensions
{
    // ── IAsyncEnumerable<T> wrapping ──────────────────────────────────────────

    /// <summary>
    /// Wraps an <see cref="IAsyncEnumerable{T}"/> so that every yielded item is
    /// also written to <paramref name="logger"/> before being forwarded to the
    /// consumer.
    /// </summary>
    /// <typeparam name="T">Unmanaged event struct type.</typeparam>
    /// <param name="source">The upstream event stream.</param>
    /// <param name="logger">Logger to write each event to.</param>
    /// <param name="level">Log level (default: <see cref="LogLevel.Information"/>).</param>
    /// <param name="formatter">
    /// Optional custom formatter.  When <see langword="null"/>, the default
    /// <c>ToString()</c> representation of <typeparamref name="T"/> is used.
    /// </param>
    public static async IAsyncEnumerable<T> WithLogging<T>(
        this IAsyncEnumerable<T> source,
        ILogger logger,
        LogLevel level = LogLevel.Information,
        Func<T, string>? formatter = null)
        where T : unmanaged
    {
        await foreach (var item in source.ConfigureAwait(false))
        {
            if (logger.IsEnabled(level))
            {
                string message = formatter is not null
                    ? formatter(item)
                    : item.ToString() ?? typeof(T).Name;

                logger.Log(level, "{EventType}: {Event}", typeof(T).Name, message);
            }

            yield return item;
        }
    }

    // ── Fire-and-forget consumption ───────────────────────────────────────────

    /// <summary>
    /// Reads all events from a <see cref="KernelTraceSession"/> and logs each
    /// one using <paramref name="logger"/>.  Completes when
    /// <paramref name="cancellationToken"/> is cancelled.
    /// </summary>
    /// <typeparam name="T">Unmanaged event struct type.</typeparam>
    /// <param name="session">The active session to read from.</param>
    /// <param name="logger">Logger to write each event to.</param>
    /// <param name="formatter">
    /// Optional custom formatter; falls back to <c>ToString()</c> when
    /// <see langword="null"/>.
    /// </param>
    /// <param name="level">Log level for individual events.</param>
    /// <param name="cancellationToken">Token to stop reading.</param>
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    public static async Task LogEventsAsync<T>(
        this KernelTraceSession session,
        ILogger logger,
        Func<T, string>? formatter = null,
        LogLevel level = LogLevel.Information,
        CancellationToken cancellationToken = default)
        where T : unmanaged
    {
        logger.LogInformation("Starting event log loop for {EventType}.", typeof(T).Name);

        try
        {
            await foreach (var ev in session
                .ReadAsync<T>(cancellationToken)
                .WithLogging(logger, level, formatter)
                .ConfigureAwait(false))
            {
                // Events are already logged by WithLogging; nothing else to do.
                _ = ev;
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown — not an error.
        }
        finally
        {
            logger.LogInformation("Event log loop for {EventType} stopped.", typeof(T).Name);
        }
    }
}
