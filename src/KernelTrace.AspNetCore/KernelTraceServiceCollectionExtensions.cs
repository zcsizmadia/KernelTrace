using KernelTrace.Sessions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace KernelTrace.AspNetCore;

/// <summary>
/// Extension methods for registering KernelTrace in the
/// <see cref="IServiceCollection"/> / <see cref="IHostBuilder"/> pipeline.
/// </summary>
public static class KernelTraceServiceCollectionExtensions
{
    /// <summary>
    /// Registers a <see cref="KernelTraceHostedService"/> that starts
    /// automatically with the host and exposes a <see cref="KernelTraceSession"/>
    /// as a singleton in the DI container.
    /// </summary>
    /// <param name="services">The DI service collection.</param>
    /// <param name="configure">
    /// Action to configure <see cref="SessionOptions"/>.
    /// At minimum, set <see cref="SessionOptions.ProbePath"/>.
    /// </param>
    /// <returns>The same <paramref name="services"/> for chaining.</returns>
    /// <example>
    /// <code>
    /// builder.Services.AddKernelTrace(opts =>
    /// {
    ///     opts.ProbePath = "./probes/network_monitor.bpf.o";
    ///     opts.Probes    = [new TracepointSpec { Category = "syscalls", Name = "sys_enter_connect" }];
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddKernelTrace(
        this IServiceCollection services,
        Action<SessionOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new SessionOptionsBuilder();
        configure(options);
        services.TryAddSingleton<SessionOptions>(options.Build());

        services.AddSingleton<KernelTraceHostedService>();
        services.AddSingleton(sp => sp.GetRequiredService<KernelTraceHostedService>().Session);
        services.AddHostedService(sp => sp.GetRequiredService<KernelTraceHostedService>());

        return services;
    }
}

/// <summary>
/// Mutable builder for <see cref="SessionOptions"/> (required because
/// <see cref="SessionOptions"/> uses <c>init</c>-only setters).
/// </summary>
public sealed class SessionOptionsBuilder : SessionOptions
{
    [System.Diagnostics.CodeAnalysis.SetsRequiredMembers]
    public SessionOptionsBuilder() { ProbePath = string.Empty; }

    internal SessionOptions Build() => this;
}
