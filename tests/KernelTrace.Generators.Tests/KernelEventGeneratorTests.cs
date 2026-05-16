using System.Collections.Immutable;
using System.Reflection;
using KernelTrace.SourceGenerators;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace KernelTrace.Generators.Tests;

public sealed class KernelEventGeneratorTests
{
    // ── CStructParser ─────────────────────────────────────────────────────────

    [Test]
    public async Task CStructParser_ParsesSimpleStruct()
    {
        const string bpf = """
            struct sock_connect_event {
                __u32 pid;
                __u32 src_ip;
                __u16 dst_port;
                __u16 _pad;
            };
            """;

        var result = CStructParser.ParseAll(bpf);

        await Assert.That(result.ContainsKey("sock_connect_event")).IsTrue();
        var s = result["sock_connect_event"];
        await Assert.That(s.Fields.Count).IsEqualTo(4);
        await Assert.That(s.Fields[0].CName).IsEqualTo("pid");
        await Assert.That(s.Fields[0].CType).IsEqualTo("__u32");
        await Assert.That(s.Fields[2].CName).IsEqualTo("dst_port");
        await Assert.That(s.Fields[2].CType).IsEqualTo("__u16");
    }

    [Test]
    public async Task CStructParser_IgnoresLineComments()
    {
        const string bpf = """
            // This is a comment
            struct my_event {
                __u64 ts_ns; // timestamp
                __u32 pid;   // process id
            };
            """;

        var result = CStructParser.ParseAll(bpf);

        await Assert.That(result.ContainsKey("my_event")).IsTrue();
        await Assert.That(result["my_event"].Fields.Count).IsEqualTo(2);
    }

    [Test]
    public async Task CStructParser_ParsesFixedArrayField()
    {
        const string bpf = """
            struct proc_event {
                __u32 pid;
                char  comm[16];
            };
            """;

        var result = CStructParser.ParseAll(bpf);
        var fields = result["proc_event"].Fields;

        await Assert.That(fields[1].CName).IsEqualTo("comm");
        await Assert.That(fields[1].ArrayLen).IsEqualTo(16);
    }

    [Test]
    public async Task CStructParser_ParsesMultipleStructs()
    {
        const string bpf = """
            struct event_a { __u32 x; };
            struct event_b { __u64 y; };
            """;

        var result = CStructParser.ParseAll(bpf);

        await Assert.That(result.Count).IsEqualTo(2);
        await Assert.That(result.ContainsKey("event_a")).IsTrue();
        await Assert.That(result.ContainsKey("event_b")).IsTrue();
    }

    [Test]
    public async Task CStructParser_TotalBytes_ComputedCorrectly()
    {
        const string bpf = """
            struct size_test {
                __u8  a;   /* 1 */
                __u16 b;   /* 2 */
                __u32 c;   /* 4 */
                __u64 d;   /* 8 */
            };
            """;

        var result = CStructParser.ParseAll(bpf);
        await Assert.That(result["size_test"].TotalBytes).IsEqualTo(15);
    }

    // ── StructEmitter ─────────────────────────────────────────────────────────

    [Test]
    public async Task StructEmitter_EmitsStructLayoutAttribute()
    {
        const string bpf = "struct ev { __u32 pid; };";
        var structs = CStructParser.ParseAll(bpf);
        string src = StructEmitter.Emit("MyApp", "MyEvent", structs["ev"], out _);

        await Assert.That(src).Contains("[StructLayout(LayoutKind.Sequential, Pack = 1)]");
    }

    [Test]
    public async Task StructEmitter_EmitsIKernelEventInterface()
    {
        const string bpf = "struct ev { __u32 pid; };";
        var structs = CStructParser.ParseAll(bpf);
        string src = StructEmitter.Emit("MyApp", "MyEvent", structs["ev"], out _);

        await Assert.That(src).Contains(": IKernelEvent");
    }

    [Test]
    public async Task StructEmitter_MapsCTypesToCSharpTypes()
    {
        const string bpf = """
            struct type_map_test {
                __u8  a;
                __u16 b;
                __u32 c;
                __u64 d;
                __s32 e;
            };
            """;

        var structs = CStructParser.ParseAll(bpf);
        string src = StructEmitter.Emit("NS", "TypeMapTest", structs["type_map_test"], out _);

        await Assert.That(src).Contains("public byte A;");
        await Assert.That(src).Contains("public ushort B;");
        await Assert.That(src).Contains("public uint C;");
        await Assert.That(src).Contains("public ulong D;");
        await Assert.That(src).Contains("public int E;");
    }

    [Test]
    public async Task StructEmitter_EmitsSizeCheckForKnownSize()
    {
        const string bpf = "struct ev { __u32 pid; };";
        var structs = CStructParser.ParseAll(bpf);
        string src = StructEmitter.Emit("NS", "Ev", structs["ev"], out _);

        await Assert.That(src).Contains("_sizeCheck");
        await Assert.That(src).Contains("4"); // uint = 4 bytes
    }

    [Test]
    public async Task StructEmitter_ReportsUnsupportedFields()
    {
        const string bpf = """
            struct ev {
                __u32 pid;
                mysterious_type foobar;
            };
            """;
        var structs = CStructParser.ParseAll(bpf);
        StructEmitter.Emit("NS", "Ev", structs["ev"], out var unsupported);

        await Assert.That(unsupported.Count).IsGreaterThan(0);
    }

    // ── End-to-end: Generator produces compilable source ─────────────────────

    [Test]
    public async Task Generator_ProducesCompilableSource_ForSimpleStruct()
    {
        const string userCode = """
            using KernelTrace.Events;

            namespace MyApp;

            [KernelEvent("sock_event")]
            public partial struct SockEvent { }
            """;

        const string bpfSource = """
            struct sock_event {
                __u32 pid;
                __u16 port;
                __u16 _pad;
            };
            """;

        var (diagnostics, outputSource) = RunGenerator(userCode, bpfSource);

        // The generator should produce at least one source file.
        await Assert.That(outputSource.Count).IsGreaterThan(0);

        // No generator errors.
        var errors = diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        await Assert.That(errors.Count).IsEqualTo(0);
    }

    [Test]
    public async Task Generator_EmitsKT0001_WhenStructNotFoundInBpfFile()
    {
        const string userCode = """
            using KernelTrace.Events;
            namespace MyApp;
            [KernelEvent("nonexistent_struct")]
            public partial struct MyEvent { }
            """;

        var (diagnostics, _) = RunGenerator(userCode, "struct unrelated { __u32 x; };");

        bool hasKt0001 = diagnostics.Any(d =>
            d.Id == "KT0001" && d.Severity == DiagnosticSeverity.Error);

        await Assert.That(hasKt0001).IsTrue();
    }

    [Test]
    public async Task Generator_EmitsKT0003_WhenStructIsNotPartial()
    {
        const string userCode = """
            using KernelTrace.Events;
            namespace MyApp;
            [KernelEvent("my_event")]
            public struct MyEvent { }
            """;

        var (diagnostics, _) = RunGenerator(userCode, "struct my_event { __u32 x; };");

        bool hasKt0003 = diagnostics.Any(d =>
            d.Id == "KT0003" && d.Severity == DiagnosticSeverity.Error);

        await Assert.That(hasKt0003).IsTrue();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static (ImmutableArray<Diagnostic> Diagnostics, IReadOnlyList<string> Sources)
        RunGenerator(string userCode, string bpfSource)
    {
        var syntaxTree = CSharpSyntaxTree.ParseText(userCode);

        // Reference the KernelTrace assembly so the attribute is resolvable.
        var kernelTraceRef = MetadataReference.CreateFromFile(
            typeof(KernelTrace.Events.KernelEventAttribute).Assembly.Location);

        var compilation = CSharpCompilation.Create(
            "TestAssembly",
            [syntaxTree],
            [
                MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
                MetadataReference.CreateFromFile(
                    global::System.Reflection.Assembly.Load("System.Runtime").Location),
                kernelTraceRef,
            ],
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var additionalText = new InMemoryAdditionalText("test.bpf.c", bpfSource);
        var generator = new KernelEventGenerator();

        GeneratorDriver driver = CSharpGeneratorDriver.Create(
            generators: [generator.AsSourceGenerator()],
            additionalTexts: [additionalText]);

        driver = driver.RunGeneratorsAndUpdateCompilation(
            compilation, out _, out var generatorDiagnostics);

        var runResult = driver.GetRunResult();
        var sources   = runResult.GeneratedTrees
            .Select(t => t.GetText().ToString())
            .ToList();

        return (generatorDiagnostics, sources);
    }

    // ── In-memory additional text ─────────────────────────────────────────────

    private sealed class InMemoryAdditionalText : AdditionalText
    {
        private readonly string _content;

        public InMemoryAdditionalText(string path, string content)
        {
            Path = path;
            _content = content;
        }

        public override string Path { get; }

        public override SourceText? GetText(System.Threading.CancellationToken ct = default) =>
            SourceText.From(_content, System.Text.Encoding.UTF8);
    }
}
