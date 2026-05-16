namespace KernelTrace.Events;

/// <summary>
/// Marker interface implemented by all kernel event structs (manually or
/// via the KernelTrace source generator).
/// </summary>
/// <remarks>
/// Implementing this interface on an <c>unmanaged</c> struct enables the
/// optional BTF size validation performed by
/// <see cref="Sessions.KernelTraceSession"/> on the first
/// <c>ReadAsync&lt;T&gt;</c> call.
/// </remarks>
public interface IKernelEvent { }
