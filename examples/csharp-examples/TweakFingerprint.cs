/**
 * Tweak Specific Fingerprint Values
 *
 * For most users, picking a built-in preset (chrome-latest, firefox-148, ...)
 * is enough — the wire bytes already match real browsers. This example is
 * for power users who want to tweak ONE OR TWO specific fingerprint values
 * while inheriting everything else from a built-in preset.
 *
 * The recipe:
 *   1. CustomPresets.Describe(name)        → JSON of all fingerprint fields
 *   2. JsonNode.Parse + edit               → mutate the values you want
 *   3. CustomPresets.LoadFromJson(json)    → registers under a new name
 *   4. new Session(preset: name)           → uses your customized version
 *
 * Why this works for any fingerprint field:
 * - Describe() emits ALL effective values (including inherited defaults
 *   like the per-resource-type priority table). Whatever you see in the
 *   output is editable.
 * - The mutated JSON round-trips byte-equal: same fingerprint mechanics,
 *   just the values you changed.
 * - Composes naturally: priority + headers + JA3 + akamai + settings can
 *   all be tweaked in one pass.
 *
 * Requirements:
 *   dotnet add package HttpCloak
 *
 * Run:
 *   dotnet run
 */

using HttpCloak;
using System.Text.Json;
using System.Text.Json.Nodes;

class TweakFingerprintExamples
{
    static async Task Main()
    {
        await Recipe1_BumpImagePriority();
        Recipe2_CustomizeHpackOrder();
        await Recipe3_FromPeetCapture();
        Recipe4_Cleanup();
        PrintSummary();
    }

    // ============================================================
    // Recipe 1: Bump image-request priority urgency
    // ============================================================
    // Real Chrome 147 emits weight=183 (urgency=2) for <img> requests.
    // Suppose you're impersonating a custom Chromium build that bumps
    // images to weight=220 (urgency=1). Tweak just the "image" entry —
    // every other fingerprint field stays inherited from chrome-147-windows.
    static async Task Recipe1_BumpImagePriority()
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Recipe 1: Bump image priority from u=2 (183) to u=1 (220)");
        Console.WriteLine(new string('-', 60));

        var root = JsonNode.Parse(CustomPresets.Describe("chrome-147-windows"))!;
        root["preset"]!["name"] = "chrome-147-img-bumped";
        root["preset"]!["http2"]!["priority_table"]!["image"] = new JsonObject
        {
            ["urgency"] = 1,
            ["incremental"] = true,
            ["emit_header"] = true,
        };
        CustomPresets.LoadFromJson(root.ToJsonString());

        using var session = new Session(preset: "chrome-147-img-bumped");
        var response = await session.GetAsync(
            "https://tls.peet.ws/api/all",
            headers: new Dictionary<string, string>
            {
                ["Sec-Fetch-Dest"] = "image",
            }
        );

        using var doc = JsonDocument.Parse(response.Text);
        if (doc.RootElement.TryGetProperty("http2", out var http2)
            && http2.TryGetProperty("sent_frames", out var sent))
        {
            foreach (var frame in sent.EnumerateArray())
            {
                if (frame.TryGetProperty("frame_type", out var ft)
                    && ft.GetString() == "HEADERS"
                    && frame.TryGetProperty("priority", out var pri))
                {
                    var weight = pri.TryGetProperty("weight", out var w) ? w.GetInt32() : 0;
                    // peet.ws encodes `exclusive` as a number (0/1), not a JSON boolean.
                    var exclusive = pri.TryGetProperty("exclusive", out var e)
                        && e.ValueKind == JsonValueKind.Number
                        && e.GetInt32() != 0;
                    Console.WriteLine($"H2 frame priority: weight={weight} exclusive={exclusive}");
                    Console.WriteLine("Expected weight=220 (u=1) instead of 183 (u=2)");
                    break;
                }
            }
        }
    }

    // ============================================================
    // Recipe 2: Customize HPACK header order
    // ============================================================
    // Insert an extra header into the canonical order so it gets emitted
    // in the right wire position. Same describe-edit-load loop.
    static void Recipe2_CustomizeHpackOrder()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("Recipe 2: Append a header to the HPACK header order");
        Console.WriteLine(new string('-', 60));

        var root = JsonNode.Parse(CustomPresets.Describe("chrome-147-windows"))!;
        root["preset"]!["name"] = "chrome-147-with-tracking-header";

        var order = root["preset"]!["http2"]!["hpack_header_order"]!.AsArray();
        // Insert "x-tracking-id" right before "priority" — the last entry.
        var priorityIdx = -1;
        for (int i = 0; i < order.Count; i++)
        {
            if (order[i]?.GetValue<string>() == "priority")
            {
                priorityIdx = i;
                break;
            }
        }
        if (priorityIdx >= 0)
        {
            order.Insert(priorityIdx, "x-tracking-id");
        }

        CustomPresets.LoadFromJson(root.ToJsonString());

        var names = order.Select(n => n!.GetValue<string>());
        Console.WriteLine($"New header order:\n  {string.Join(", ", names)}");
    }

    // ============================================================
    // Recipe 3: Start from a tls.peet.ws capture
    // ============================================================
    // Visit https://tls.peet.ws/api/all in the browser you want to mimic.
    // Copy:
    //   - data.tls.ja3                  → preset.tls.ja3
    //   - data.http2.akamai_fingerprint → preset.http2.akamai
    // The H2 priority frame in sent_frames[0].priority is the navigation
    // priority (dest=document) only. For per-dest priority across the full
    // resource set, run the H2 capture-server tool — see the local-server
    // documentation in internal_docs.
    static async Task Recipe3_FromPeetCapture()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("Recipe 3: Build a preset from a peet.ws capture");
        Console.WriteLine(new string('-', 60));

        // Replace these with actual values from your peet.ws visit.
        const string PeetJa3 =
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172"
            + "-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037,29-23-24,0";
        const string PeetAkamai = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";

        var root = JsonNode.Parse(CustomPresets.Describe("chrome-147-windows"))!;
        root["preset"]!["name"] = "from-peet-capture";
        root["preset"]!["tls"] = new JsonObject { ["ja3"] = PeetJa3 };
        // http2.akamai overrides settings/window/single-weight/pseudo-order.
        // The priority_table (per-dest) is independent — leave it inherited
        // or replace it from a multi-dest capture.
        root["preset"]!["http2"]!["akamai"] = PeetAkamai;
        CustomPresets.LoadFromJson(root.ToJsonString());

        using var session = new Session(preset: "from-peet-capture");
        var response = await session.GetAsync("https://tls.peet.ws/api/tls");
        using var doc = JsonDocument.Parse(response.Text);

        var tls = doc.RootElement.GetProperty("tls");
        var ja3Hash = tls.TryGetProperty("ja3_hash", out var h) ? h.GetString() : "N/A";
        var ja3Sent = tls.TryGetProperty("ja3", out var t) ? t.GetString() : "";
        Console.WriteLine($"JA3 hash:  {ja3Hash}");
        Console.WriteLine($"JA3 sent matches PeetJa3: {ja3Sent == PeetJa3}");
    }

    // ============================================================
    // Recipe 4: Clean up custom presets when done
    // ============================================================
    // Custom presets stay registered in-process until Unregister is called.
    // Long-running processes that build many presets dynamically should
    // clean up to avoid memory growth.
    static void Recipe4_Cleanup()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("Recipe 4: Unregister custom presets");
        Console.WriteLine(new string('-', 60));

        foreach (var name in new[]
        {
            "chrome-147-img-bumped",
            "chrome-147-with-tracking-header",
            "from-peet-capture",
        })
        {
            CustomPresets.Unregister(name);
            Console.WriteLine($"Unregistered: {name}");
        }
    }

    // ============================================================
    // Summary
    // ============================================================
    static void PrintSummary()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("Summary");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine(@"
The Describe → edit → LoadFromJson workflow lets you tweak ANY fingerprint
value while inheriting the rest. Common edit points:

    preset.http2.priority_table[dest]    per-resource priorities
    preset.http2.hpack_header_order      HPACK encoding order
    preset.http2.settings_order          SETTINGS frame ID order
    preset.http2.pseudo_order            HTTP/2 pseudo-headers
    preset.http2.akamai                  single-string override
    preset.http3                         HTTP/3 / QUIC params
    preset.tls.ja3                       JA3 string
    preset.tcp                           TCP/IP fingerprint
    preset.headers.values                static header values
    preset.headers.order                 request header order

Print CustomPresets.Describe(name) once to see the full editable surface.
");
    }
}
