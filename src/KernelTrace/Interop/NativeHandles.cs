namespace KernelTrace.Interop;

/// <summary>
/// A <see cref="SafeHandle"/> that owns a native <c>kt_session*</c>.
/// Ensures <c>kt_session_close</c> is called even in exceptional paths.
/// </summary>
[SupportedOSPlatform("linux")]
internal class KernelProbeHandle : SafeHandle
{
    /// <summary>Initialises the handle with an existing raw pointer.</summary>
    internal KernelProbeHandle(nint handle) : base(nint.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    /// <inheritdoc/>
    public override bool IsInvalid => handle == nint.Zero;

    /// <inheritdoc/>
    protected override bool ReleaseHandle()
    {
        NativeMethods.SessionClose(handle);
        return true;
    }
}

/// <summary>
/// A <see cref="SafeHandle"/> that owns a native <c>kt_attachment*</c>.
/// Ensures <c>kt_detach</c> is called on disposal.
/// </summary>
[SupportedOSPlatform("linux")]
internal class AttachmentHandle : SafeHandle
{
    /// <summary>Initialises the handle with an existing raw pointer.</summary>
    internal AttachmentHandle(nint handle) : base(nint.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    /// <inheritdoc/>
    public override bool IsInvalid => handle == nint.Zero;

    /// <inheritdoc/>
    protected override bool ReleaseHandle()
    {
        NativeMethods.Detach(handle);
        return true;
    }
}
