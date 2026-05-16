namespace KernelTrace.Exceptions;

/// <summary>
/// Base exception for all KernelTrace errors.
/// </summary>
public class KernelTraceException : Exception
{
    /// <inheritdoc cref="KernelTraceException"/>
    public KernelTraceException(string message) : base(message) { }

    /// <inheritdoc cref="KernelTraceException"/>
    public KernelTraceException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// Thrown when the native <c>libkerneltrace.so</c> cannot be loaded or a
/// libbpf call returns an error.
/// </summary>
public sealed class NativeInteropException : KernelTraceException
{
    /// <summary>Gets the native error code returned by libkerneltrace.</summary>
    public int NativeErrorCode { get; }

    /// <inheritdoc cref="NativeInteropException"/>
    public NativeInteropException(int code, string message)
        : base($"libkerneltrace error {code}: {message}")
    {
        NativeErrorCode = code;
    }
}

/// <summary>
/// Thrown when the in-memory size of a C# event struct does not match the
/// size reported by the eBPF BTF metadata, indicating a struct layout mismatch.
/// </summary>
public sealed class KernelStructMismatchException : KernelTraceException
{
    /// <summary>The name of the C# struct type.</summary>
    public string StructTypeName { get; }

    /// <summary>Expected byte size (from BTF).</summary>
    public int ExpectedSize { get; }

    /// <summary>Actual byte size (from <c>sizeof(T)</c>).</summary>
    public int ActualSize { get; }

    /// <inheritdoc cref="KernelStructMismatchException"/>
    public KernelStructMismatchException(string typeName, int expectedSize, int actualSize)
        : base($"Struct '{typeName}' layout mismatch: expected {expectedSize} bytes (from BTF), " +
               $"got {actualSize} bytes. Check field types and [StructLayout] settings.")
    {
        StructTypeName = typeName;
        ExpectedSize = expectedSize;
        ActualSize = actualSize;
    }
}

/// <summary>
/// Thrown when a probe cannot be attached to the kernel, typically due to
/// insufficient privileges (requires <c>CAP_BPF</c> or root).
/// </summary>
public sealed class ProbeAttachException : KernelTraceException
{
    /// <inheritdoc cref="ProbeAttachException"/>
    public ProbeAttachException(string probeName, string reason)
        : base($"Failed to attach probe '{probeName}': {reason}") { }
}
