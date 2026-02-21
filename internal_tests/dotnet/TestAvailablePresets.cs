/*
 * Test AvailablePresets() returns Dictionary<string, PresetInfo> with protocol support.
 *
 * Usage:
 *   cd internal_tests/dotnet
 *   dotnet run --project TestAvailablePresets.csproj
 */

using System;
using System.Collections.Generic;
using System.Linq;
using HttpCloak;

class TestPresetsProgram
{
    static int Main() => TestAvailablePresets.Run();
}

static class TestAvailablePresets
{
    static readonly HashSet<string> ExpectedH3 = new()
    {
        "chrome-143", "chrome-143-windows", "chrome-143-linux", "chrome-143-macos",
        "chrome-144", "chrome-144-windows", "chrome-144-linux", "chrome-144-macos",
        "chrome-145", "chrome-145-windows", "chrome-145-linux", "chrome-145-macos",
        "safari-18", "chrome-143-ios", "chrome-144-ios", "chrome-145-ios",
        "safari-18-ios", "chrome-143-android", "chrome-144-android", "chrome-145-android",
    };

    static readonly HashSet<string> ExpectedNoH3 = new()
    {
        "chrome-133", "chrome-141", "firefox-133", "safari-17-ios"
    };

    static readonly HashSet<string> AllExpected = new(ExpectedH3.Concat(ExpectedNoH3));

    public static int Run()
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Test: AvailablePresets() dict format");
        Console.WriteLine(new string('=', 60));

        int passed = 0;
        int failed = 0;

        var presets = HttpCloakInfo.AvailablePresets();

        // 1. Return type is Dictionary
        var isDict = presets != null;
        Console.WriteLine($"  [{(isDict ? "PASS" : "FAIL")}] Return type is Dictionary: {presets?.GetType().Name}");
        if (isDict) passed++; else failed++;

        // 2. Has expected count
        var countOk = presets!.Count == AllExpected.Count;
        Console.WriteLine($"  [{(countOk ? "PASS" : "FAIL")}] Preset count: {presets.Count} (expected {AllExpected.Count})");
        if (countOk) passed++; else failed++;

        // 3. All expected presets present
        var keysSet = new HashSet<string>(presets.Keys);
        var missing = AllExpected.Except(keysSet).ToList();
        var extra = keysSet.Except(AllExpected).ToList();
        var allPresent = missing.Count == 0 && extra.Count == 0;
        Console.WriteLine($"  [{(allPresent ? "PASS" : "FAIL")}] All expected presets present");
        if (missing.Count > 0) Console.WriteLine($"         Missing: {string.Join(", ", missing)}");
        if (extra.Count > 0) Console.WriteLine($"         Extra: {string.Join(", ", extra)}");
        if (allPresent) passed++; else failed++;

        // 4. Each preset has protocols array
        var allHaveProtocols = true;
        foreach (var (name, info) in presets)
        {
            if (info?.Protocols == null)
            {
                Console.WriteLine($"  [FAIL] {name}: missing 'Protocols'");
                allHaveProtocols = false;
                break;
            }
        }
        Console.WriteLine($"  [{(allHaveProtocols ? "PASS" : "FAIL")}] All presets have Protocols array");
        if (allHaveProtocols) passed++; else failed++;

        // 5. All presets have h1 and h2
        var allHaveH1H2 = true;
        foreach (var (name, info) in presets)
        {
            var protos = info.Protocols;
            if (!protos.Contains("h1") || !protos.Contains("h2"))
            {
                Console.WriteLine($"  [FAIL] {name}: missing h1/h2, has [{string.Join(", ", protos)}]");
                allHaveH1H2 = false;
            }
        }
        Console.WriteLine($"  [{(allHaveH1H2 ? "PASS" : "FAIL")}] All presets have h1 and h2");
        if (allHaveH1H2) passed++; else failed++;

        // 6. H3-capable presets have h3
        var h3Correct = true;
        foreach (var name in ExpectedH3)
        {
            if (presets.TryGetValue(name, out var info))
            {
                if (!info.Protocols.Contains("h3"))
                {
                    Console.WriteLine($"  [FAIL] {name}: should have h3 but has [{string.Join(", ", info.Protocols)}]");
                    h3Correct = false;
                }
            }
        }
        Console.WriteLine($"  [{(h3Correct ? "PASS" : "FAIL")}] H3 presets have h3 protocol");
        if (h3Correct) passed++; else failed++;

        // 7. Non-H3 presets don't have h3
        var noH3Correct = true;
        foreach (var name in ExpectedNoH3)
        {
            if (presets.TryGetValue(name, out var info))
            {
                if (info.Protocols.Contains("h3"))
                {
                    Console.WriteLine($"  [FAIL] {name}: should NOT have h3 but has [{string.Join(", ", info.Protocols)}]");
                    noH3Correct = false;
                }
            }
        }
        Console.WriteLine($"  [{(noH3Correct ? "PASS" : "FAIL")}] Non-H3 presets don't have h3");
        if (noH3Correct) passed++; else failed++;

        // Summary
        Console.WriteLine();
        Console.WriteLine(new string('=', 60));
        int total = passed + failed;
        Console.WriteLine($"Result: {passed}/{total} checks passed");
        if (failed > 0)
        {
            Console.WriteLine("FAILED");
            return 1;
        }
        else
        {
            Console.WriteLine("ALL PASSED");
            return 0;
        }
    }
}
