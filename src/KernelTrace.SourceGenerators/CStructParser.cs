using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace KernelTrace.SourceGenerators;

/// <summary>Represents one field parsed from a C struct definition.</summary>
internal sealed class CField
{
    public string CType    { get; init; } = "";
    public string CName    { get; init; } = "";
    public int?   ArrayLen { get; init; }   // non-null for fixed-length arrays

    /// <summary>Byte size of this field (best-effort from known types).</summary>
    public int ByteSize => ArrayLen.HasValue
        ? (KnownTypeSizes.TryGetValue(CType, out int s) ? s * ArrayLen.Value : 0)
        : (KnownTypeSizes.TryGetValue(CType, out int s2) ? s2 : 0);

    // ── Known C → byte-size table ─────────────────────────────────────────
    private static readonly Dictionary<string, int> KnownTypeSizes =
        new(StringComparer.Ordinal)
        {
            ["__u8"]  = 1, ["__s8"]  = 1, ["u8"]  = 1, ["s8"]  = 1, ["char"] = 1,
            ["__u16"] = 2, ["__s16"] = 2, ["u16"] = 2, ["s16"] = 2,
            ["__be16"] = 2, ["__le16"] = 2,
            ["__u32"] = 4, ["__s32"] = 4, ["u32"] = 4, ["s32"] = 4, ["int"] = 4,
            ["__be32"] = 4, ["__le32"] = 4,
            ["__u64"] = 8, ["__s64"] = 8, ["u64"] = 8, ["s64"] = 8, ["long"] = 8,
            ["__be64"] = 8, ["__le64"] = 8,
        };
}

/// <summary>Represents a parsed C struct definition.</summary>
internal sealed class CStruct
{
    public string         Name   { get; init; } = "";
    public List<CField>   Fields { get; init; } = new();
    public int TotalBytes => Sum(Fields);

    private static int Sum(List<CField> fields)
    {
        int t = 0;
        foreach (var f in fields)
        {
            t += f.ByteSize;
        }
        return t;
    }
}

/// <summary>
/// Lightweight parser that extracts C struct definitions from eBPF source files.
/// Only a subset of C is supported — the types that eBPF programs typically use.
/// </summary>
internal static class CStructParser
{
    // Matches: struct foo_event { ... };  (with optional typedef)
    private static readonly Regex StructBodyRe = new(
        @"struct\s+(?<name>\w+)\s*\{(?<body>[^}]*)\}",
        RegexOptions.Compiled | RegexOptions.Singleline);

    // Matches a field line, e.g.:
    //   __u32 pid;
    //   __u8  comm[16];
    //   u64   ts_ns;
    private static readonly Regex FieldRe = new(
        @"^\s*(?<type>(?:__)?[a-z][a-z0-9_]*)\s+(?<name>\w+)(?:\[(?<len>\d+)\])?\s*;",
        RegexOptions.Compiled | RegexOptions.Multiline | RegexOptions.IgnoreCase);

    /// <summary>
    /// Parses all struct definitions from <paramref name="source"/> and
    /// returns them keyed by struct name.
    /// </summary>
    public static Dictionary<string, CStruct> ParseAll(string source)
    {
        // Strip line comments to avoid false positives.
        source = Regex.Replace(source, @"//[^\n]*", "");
        // Strip block comments.
        source = Regex.Replace(source, @"/\*.*?\*/", "", RegexOptions.Singleline);

        var result = new Dictionary<string, CStruct>(StringComparer.Ordinal);

        foreach (Match m in StructBodyRe.Matches(source))
        {
            string name = m.Groups["name"].Value;
            string body = m.Groups["body"].Value;

            var fields = new List<CField>();
            foreach (Match fm in FieldRe.Matches(body))
            {
                string cType = fm.Groups["type"].Value;
                string cName = fm.Groups["name"].Value;
                int? arrayLen = fm.Groups["len"].Success
                    ? int.Parse(fm.Groups["len"].Value)
                    : (int?)null;

                fields.Add(new CField { CType = cType, CName = cName, ArrayLen = arrayLen });
            }

            if (fields.Count > 0)
            {
                result[name] = new CStruct { Name = name, Fields = fields };
            }
        }

        return result;
    }
}
