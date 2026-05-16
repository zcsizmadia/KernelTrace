// Required for 'init' accessors when targeting netstandard2.0.
// The type is built into runtimes ≥ net5.0 but must be declared manually
// for netstandard2.0 targets such as Roslyn source generators.
namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit { }
}
