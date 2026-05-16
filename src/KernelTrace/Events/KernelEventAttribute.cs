namespace KernelTrace.Events;

/// <summary>
/// Annotates a <c>partial struct</c> so that the KernelTrace source generator
/// can auto-generate the correct <c>[StructLayout]</c>, field declarations,
/// and <see cref="IKernelEvent"/> implementation from the corresponding C struct
/// definition in the companion <c>.bpf.c</c> file.
/// </summary>
/// <remarks>
/// <para>
/// The generator looks for a <c>struct &lt;StructName&gt;</c> definition in any
/// <c>AdditionalFiles</c> item whose build action is <c>EbpfSource</c>.
/// </para>
/// <para>
/// The struct name lookup is case-sensitive and must exactly match the C struct
/// name (e.g., <c>sock_connect_event</c> → <c>"sock_connect_event"</c>).
/// </para>
/// </remarks>
/// <example>
/// In your <c>.csproj</c>:
/// <code>
/// &lt;ItemGroup&gt;
///   &lt;AdditionalFiles Include="probes/network_monitor.bpf.c" BuildAction="EbpfSource" /&gt;
/// &lt;/ItemGroup&gt;
/// </code>
/// In C#:
/// <code>
/// [KernelEvent("sock_connect_event")]
/// public partial struct SocketConnectEvent { }
/// // The generator produces:
/// // [StructLayout(LayoutKind.Sequential, Pack = 1)]
/// // public partial struct SocketConnectEvent : IKernelEvent
/// // {
/// //     public uint Pid;
/// //     public uint SrcIp;
/// //     public ushort DstPort;
/// // }
/// </code>
/// </example>
[AttributeUsage(AttributeTargets.Struct, AllowMultiple = false, Inherited = false)]
public sealed class KernelEventAttribute : Attribute
{
    /// <summary>
    /// The exact name of the C struct inside the eBPF source file.
    /// </summary>
    public string StructName { get; }

    /// <summary>
    /// Initialises the attribute with the C struct name to look up.
    /// </summary>
    /// <param name="structName">
    /// Exact C struct name (e.g., <c>"sock_connect_event"</c>).
    /// </param>
    public KernelEventAttribute(string structName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(structName);
        StructName = structName;
    }
}
