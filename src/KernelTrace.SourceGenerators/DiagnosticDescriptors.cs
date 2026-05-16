using Microsoft.CodeAnalysis;

namespace KernelTrace.SourceGenerators;

/// <summary>
/// Centralised <see cref="DiagnosticDescriptor"/> definitions for the
/// KernelTrace source generator.
/// </summary>
internal static class DiagnosticDescriptors
{
    private const string Category = "KernelTrace";

    // ── Errors ───────────────────────────────────────────────────────────────

    public static readonly DiagnosticDescriptor StructNotFound = new(
        id: "KT0001",
        title: "eBPF struct not found",
        messageFormat: "No C struct named '{0}' was found in any EbpfSource AdditionalFile. " +
                       "Ensure the .bpf.c file is added as <AdditionalFiles BuildAction=\"EbpfSource\" />.",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    public static readonly DiagnosticDescriptor UnsupportedFieldType = new(
        id: "KT0002",
        title: "Unsupported eBPF field type",
        messageFormat: "Field '{0}' in struct '{1}' has type '{2}' which cannot be automatically mapped " +
                       "to a C# type. Add the field manually inside the partial struct body.",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    public static readonly DiagnosticDescriptor MustBePartial = new(
        id: "KT0003",
        title: "KernelEvent struct must be partial",
        messageFormat: "Struct '{0}' annotated with [KernelEvent] must be declared as 'partial'",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    public static readonly DiagnosticDescriptor MustBeUnmanaged = new(
        id: "KT0004",
        title: "KernelEvent struct must be unmanaged",
        messageFormat: "Struct '{0}' annotated with [KernelEvent] should only contain unmanaged field types " +
                       "to be usable with ReadAsync<T>",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    // ── Informational ────────────────────────────────────────────────────────

    public static readonly DiagnosticDescriptor StructGenerated = new(
        id: "KT0010",
        title: "KernelEvent struct generated",
        messageFormat: "Generated C# struct '{0}' from eBPF struct '{1}' ({2} fields, {3} bytes)",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Info,
        isEnabledByDefault: false);  // Off by default to reduce build noise.
}
