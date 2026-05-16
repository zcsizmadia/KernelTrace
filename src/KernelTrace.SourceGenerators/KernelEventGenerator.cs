using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace KernelTrace.SourceGenerators;

/// <summary>
/// Incremental Roslyn source generator that:
/// <list type="number">
///   <item>
///     Finds all <c>partial struct</c> declarations annotated with
///     <c>[KernelEvent("struct_name")]</c>.
///   </item>
///   <item>
///     Locates the matching C struct in any <c>AdditionalFiles</c> item
///     whose build action is <c>EbpfSource</c>.
///   </item>
///   <item>
///     Emits a generated <c>.g.cs</c> file containing the correctly-aligned
///     <c>[StructLayout(LayoutKind.Sequential, Pack=1)]</c> partial struct
///     with all fields and a compile-time size assertion.
///   </item>
/// </list>
/// </summary>
[Generator(LanguageNames.CSharp)]
public sealed class KernelEventGenerator : IIncrementalGenerator
{
    private const string AttributeFqn     = "KernelTrace.Events.KernelEventAttribute";
    private const string EbpfBuildAction  = "EbpfSource";

    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        // ── Step 1: collect annotated partial structs ─────────────────────────
        var annotatedStructs = context.SyntaxProvider
            .ForAttributeWithMetadataName(
                AttributeFqn,
                predicate: static (node, _) => node is StructDeclarationSyntax,
                transform: static (ctx, _) => ExtractStructInfo(ctx))
            .Where(static info => info is not null)
            .Select(static (info, _) => info!);

        // ── Step 2: collect EbpfSource additional files ───────────────────────
        var ebpfSources = context.AdditionalTextsProvider
            .Where(static file => file.Path.EndsWith(".bpf.c",
                System.StringComparison.OrdinalIgnoreCase))
            .Select(static (text, ct) => (path: text.Path, content: text.GetText(ct)?.ToString() ?? ""));

        // Combine all ebpf sources into one dictionary per compilation.
        var allStructs = ebpfSources
            .Collect()
            .Select(static (files, _) =>
            {
                var combined = new System.Collections.Generic.Dictionary<string, CStruct>(
                    System.StringComparer.Ordinal);

                foreach (var (_, content) in files)
                {
                    foreach (var kvp in CStructParser.ParseAll(content))
                    {
                    if (!combined.ContainsKey(kvp.Key))
                        combined[kvp.Key] = kvp.Value;
                    }
                }

                return combined as IReadOnlyDictionary<string, CStruct>;
            });

        // ── Step 3: combine and generate ─────────────────────────────────────
        var combined2 = annotatedStructs.Combine(allStructs);

        context.RegisterSourceOutput(combined2, (spc, pair) =>
            GenerateForStruct(spc, pair.Left, pair.Right));
    }

    // ── Extraction ────────────────────────────────────────────────────────────

    private static StructGenerationInfo? ExtractStructInfo(
        GeneratorAttributeSyntaxContext ctx)
    {
        if (ctx.TargetNode is not StructDeclarationSyntax sds)
        {
            return null;
        }

        // Validate: must be partial.
        bool isPartial = sds.Modifiers.Any(m => m.IsKind(SyntaxKind.PartialKeyword));
        if (!isPartial)
        {
            // We'll report the diagnostic in GenerateForStruct.
            return new StructGenerationInfo
            {
                CsTypeName   = sds.Identifier.Text,
                Namespace    = GetNamespace(sds),
                CStructName  = "",
                Location     = sds.GetLocation(),
                IsPartial    = false,
            };
        }

        // Extract struct name from the attribute argument.
        var attr = ctx.Attributes.FirstOrDefault();
        if (attr is null)
        {
            return null;
        }

        string cStructName = attr.ConstructorArguments.Length > 0
            ? attr.ConstructorArguments[0].Value?.ToString() ?? ""
            : "";

        return new StructGenerationInfo
        {
            CsTypeName  = sds.Identifier.Text,
            Namespace   = GetNamespace(sds),
            CStructName = cStructName,
            Location    = sds.GetLocation(),
            IsPartial   = true,
        };
    }

    // ── Code generation ───────────────────────────────────────────────────────

    private static void GenerateForStruct(
        SourceProductionContext spc,
        StructGenerationInfo info,
        IReadOnlyDictionary<string, CStruct>? allStructs)
    {
        if (!info.IsPartial)
        {
            spc.ReportDiagnostic(Diagnostic.Create(
                DiagnosticDescriptors.MustBePartial,
                info.Location,
                info.CsTypeName));
            return;
        }

        if (string.IsNullOrEmpty(info.CStructName) ||
            allStructs is null ||
            !allStructs.TryGetValue(info.CStructName, out var cStruct))
        {
            spc.ReportDiagnostic(Diagnostic.Create(
                DiagnosticDescriptors.StructNotFound,
                info.Location,
                info.CStructName));
            return;
        }

        string source = StructEmitter.Emit(
            info.Namespace,
            info.CsTypeName,
            cStruct,
            out var unsupported);

        foreach (var field in unsupported)
        {
            spc.ReportDiagnostic(Diagnostic.Create(
                DiagnosticDescriptors.UnsupportedFieldType,
                info.Location,
                field, cStruct.Name, field.Split(' ')[0]));
        }

        spc.AddSource(
            $"{info.CsTypeName}.KernelEvent.g.cs",
            SourceText.From(source, Encoding.UTF8));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string GetNamespace(SyntaxNode node)
    {
        SyntaxNode? parent = node.Parent;
        while (parent is not null)
        {
            if (parent is BaseNamespaceDeclarationSyntax ns)
            {
                return ns.Name.ToString();
            }
            parent = parent.Parent;
        }

        return "global";
    }
}

// ── Data transfer object ──────────────────────────────────────────────────────

internal sealed class StructGenerationInfo
{
    public string   CsTypeName  { get; init; } = "";
    public string   Namespace   { get; init; } = "";
    public string   CStructName { get; init; } = "";
    public Location Location    { get; init; } = Location.None;
    public bool     IsPartial   { get; init; }
}
