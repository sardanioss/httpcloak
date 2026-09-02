using System.Reflection;
using System.Text;

// Guards the public surface of HttpCloak.dll against removals.
//
// C# writes a call's full signature into the calling assembly, so removing or
// reshaping a public method breaks every already-compiled consumer with a
// MissingMethodException, at the call rather than at load. That is invisible
// in review and invisible in a build: the library still compiles, its own
// tests still pass, and only somebody else's binary falls over.
//
// So the rule enforced here is one-way. Adding members is always fine and the
// baseline simply grows. Removing or changing one is what fails, and the fix
// is to keep the old shape as a forwarding overload (see the forwarders at the
// end of Session.cs) rather than to edit the baseline.
//
//   ApiCheck <assembly> <baseline>            verify
//   ApiCheck <assembly> <baseline> --update    rewrite the baseline
//
// Exit codes: 0 ok, 1 signatures went missing, 2 bad usage.

if (args.Length < 2)
{
    Console.Error.WriteLine("usage: ApiCheck <assembly> <baseline> [--update]");
    return 2;
}

string assemblyPath = args[0], baselinePath = args[1];
bool update = args.Contains("--update");

if (!File.Exists(assemblyPath))
{
    Console.Error.WriteLine($"assembly not found: {assemblyPath}");
    return 2;
}

var current = Describe(Assembly.LoadFrom(assemblyPath));

if (update)
{
    var header = new[]
    {
        "# Public surface of HttpCloak.dll, one line per member.",
        "#",
        "# Every line here must keep resolving, because a binary compiled against any",
        "# shipped release recorded the exact shape it calls. Removing or reshaping a",
        "# member breaks those callers with MissingMethodException at the call site.",
        "#",
        "# Regenerate ONLY when the shapes that disappeared were never released. If a",
        "# shipped shape is missing, add a forwarding overload for it instead: see the",
        "# forwarders at the end of Session.cs, which carry the 1.6.8 and 1.7.0 shapes.",
        "#",
        $"# {current.Count} members.",
        "",
    };
    File.WriteAllLines(baselinePath, header.Concat(current));
    Console.WriteLine($"baseline written: {current.Count} public members");
    return 0;
}

if (!File.Exists(baselinePath))
{
    Console.Error.WriteLine($"baseline not found: {baselinePath}");
    Console.Error.WriteLine("create it with --update once the surface is known good");
    return 2;
}

var baseline = File.ReadAllLines(baselinePath)
    .Where(l => l.Length > 0 && !l.StartsWith('#'))
    .ToHashSet(StringComparer.Ordinal);

var missing = baseline.Where(b => !current.Contains(b)).OrderBy(x => x, StringComparer.Ordinal).ToList();
var added = current.Where(c => !baseline.Contains(c)).OrderBy(x => x, StringComparer.Ordinal).ToList();

foreach (var a in added) Console.WriteLine($"  + {a}");
if (added.Count > 0)
    Console.WriteLine($"{added.Count} member(s) added. That is fine; run with --update to record them.\n");

if (missing.Count == 0)
{
    Console.WriteLine($"public API intact: {baseline.Count} member(s) still present.");
    return 0;
}

Console.Error.WriteLine($"{missing.Count} public member(s) went missing:\n");
foreach (var m in missing) Console.Error.WriteLine($"  - {m}");
Console.Error.WriteLine(
    "\nEvery one of these breaks an already-compiled consumer at the call site.\n" +
    "Keep the old shape as a forwarding overload with no default values, next to\n" +
    "the others at the end of Session.cs, rather than updating the baseline.");
return 1;

// Renders each public member as a stable string. Parameter names are left out
// on purpose: renaming one is source-breaking but not binary-breaking, and this
// check is about the binary contract.
static SortedSet<string> Describe(Assembly asm)
{
    var set = new SortedSet<string>(StringComparer.Ordinal);
    foreach (var t in asm.GetExportedTypes().OrderBy(t => t.FullName, StringComparer.Ordinal))
    {
        foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
        {
            if (m.IsSpecialName) continue;             // property and event accessors
            set.Add($"{t.FullName}.{m.Name}({Params(m.GetParameters())}) : {Name(m.ReturnType)}");
        }
        foreach (var c in t.GetConstructors(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            set.Add($"{t.FullName}..ctor({Params(c.GetParameters())})");
        foreach (var p in t.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            set.Add($"{t.FullName}.{p.Name} : {Name(p.PropertyType)}");
        foreach (var f in t.GetFields(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            set.Add($"{t.FullName}.{f.Name} : {Name(f.FieldType)}");
    }
    return set;
}

static string Params(ParameterInfo[] ps) => string.Join(", ", ps.Select(p => Name(p.ParameterType)));

static string Name(Type t)
{
    if (!t.IsGenericType) return t.FullName ?? t.Name;
    var sb = new StringBuilder(t.GetGenericTypeDefinition().FullName!.Split('`')[0]);
    sb.Append('<').Append(string.Join(", ", t.GetGenericArguments().Select(Name))).Append('>');
    return sb.ToString();
}
