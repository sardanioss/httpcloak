---
title: JSON Preset Builder
sidebar_position: 4
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# JSON Preset Builder

The JSON preset builder turns any built-in preset into editable JSON, lets you change whatever you want, and registers the result under a new name. No Go code change, no rebuild. Three function calls cover the round-trip.

## The three functions

| Function | What it does |
|---|---|
| `describe_preset(name)` | Returns the full preset spec as JSON. Inheritance is flattened. H2 / H3 default values are emitted explicitly. |
| `load_preset_from_json(json)` | Parses + builds a preset from JSON, registers it under the name in the JSON. |
| `unregister_preset(name)` | Drops a custom registration. Built-ins can't be unregistered. |

## Round-trip is byte-identical

Call `describe_preset`, then `load_preset_from_json`, then `describe_preset` again, and you get byte-for-byte identical JSON. We lean on that property internally; it's why our embedded Chrome 148 presets are JSON files instead of Go code. The round-trip is tested for every shipped preset.

The practical upshot: describe, edit, load, describe, diff. The diff shows exactly what changed. No surprise drift from defaults getting dropped.

## Use cases

- **Spoof a Chrome version we haven't shipped yet.** Grab `chrome-latest`, override the User-Agent and sec-ch-ua brand list, register under your own name, such as `chrome-152-windows-preview`. Five minutes of work. Pick a name no built-in uses: registering over a shipped preset is rejected.
- **Pin a UA OS that doesn't match your runtime.** A Linux box can ship the `chrome-148-windows` UA without touching the TLS handshake.
- **Remove or add a single TLS extension.** Override `tls.signature_algorithms` or `tls.alpn` without rebuilding the whole ClientHello.
- **Tweak one HTTP/2 SETTINGS value.** Bump `initial_window_size`, leave everything else alone.
- **Swap in a captured ClientHello from a real browser session.** See the [Build a custom preset from a tls.peet.ws capture](/recipes/build-custom-chrome-from-tls-peet) recipe.

## Walkthrough: dump, mutate, load, send

The shortest useful example: take `chrome-148-windows`, change the User-Agent, register the result as `my-chrome-mutant`, fire a request through it.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"

    "github.com/sardanioss/httpcloak"
    "github.com/sardanioss/httpcloak/fingerprint"
)

func main() {
    // 1. Dump chrome-148-windows as JSON.
    desc, err := fingerprint.Describe("chrome-148-windows")
    if err != nil { panic(err) }

    // 2. Parse it, mutate the User-Agent and the preset name.
    var pf fingerprint.PresetFile
    if err := json.Unmarshal([]byte(desc), &pf); err != nil { panic(err) }
    pf.Preset.Name = "my-chrome-mutant"
    pf.Preset.Headers.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/200.0.0.0 Safari/537.36"
    out, _ := json.MarshalIndent(&pf, "", "  ")

    // 3. Load it back. This builds + registers under the new name.
    p, err := fingerprint.LoadAndBuildPresetFromJSON(out)
    if err != nil { panic(err) }
    fingerprint.Register(p.Name, p)

    // 4. Use it.
    s := httpcloak.NewSession("my-chrome-mutant")
    defer s.Close()
    resp, _ := s.Get(context.Background(), "https://tls.peet.ws/api/all")
    body, _ := io.ReadAll(resp.Body)
    resp.Body.Close()
    fmt.Println(string(body))
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import json
import httpcloak

# 1. Dump chrome-148-windows as JSON.
desc = httpcloak.describe_preset("chrome-148-windows")

# 2. Parse, mutate, re-serialize.
pf = json.loads(desc)
pf["preset"]["name"] = "my-chrome-mutant"
pf["preset"]["headers"]["user_agent"] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/200.0.0.0 Safari/537.36"
)

# 3. Load back. Returns the registered name.
name = httpcloak.load_preset_from_json(json.dumps(pf))

# 4. Use it.
with httpcloak.Session(preset=name) as s:
    r = s.get("https://tls.peet.ws/api/all")
    print(r.text)
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
const { Session, describePreset, loadPresetFromJSON } = require("httpcloak");

// 1. Dump chrome-148-windows as JSON.
const desc = describePreset("chrome-148-windows");

// 2. Parse, mutate, re-serialize.
const pf = JSON.parse(desc);
pf.preset.name = "my-chrome-mutant";
pf.preset.headers.user_agent =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/200.0.0.0 Safari/537.36";

// 3. Load back. Returns the registered name.
const name = loadPresetFromJSON(JSON.stringify(pf));

// 4. Use it.
const s = new Session({ preset: name });
const r = await s.get("https://tls.peet.ws/api/all");
console.log(r.text);
s.close();
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using System.Text.Json;
using HttpCloak;

// 1. Dump chrome-148-windows as JSON.
var desc = CustomPresets.Describe("chrome-148-windows");

// 2. Parse, mutate, re-serialize.
var doc = JsonNode.Parse(desc)!;
doc["preset"]!["name"] = "my-chrome-mutant";
doc["preset"]!["headers"]!["user_agent"] =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/200.0.0.0 Safari/537.36";

// 3. Load back. Returns the registered name.
var name = CustomPresets.LoadFromJson(doc.ToJsonString());

// 4. Use it.
using var s = new Session(preset: name);
var r = await s.GetAsync("https://tls.peet.ws/api/all");
Console.WriteLine(r.Text);
```

</TabItem>
</Tabs>

What `tls.peet.ws/api/all` reflects back:

```text
user_agent:              Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/200.0.0.0 Safari/537.36
ja4:                     t13d1516h2_8daaf6152771_806a8c22fdea
peetprint_hash:          67c3e9111bed9e7f03d2f21d6d88994b
akamai_fingerprint_hash: 52d84b11737d980aef856699f885ca86
```

The User-Agent is our custom value. The TLS / H2 fingerprint is byte-identical to the original `chrome-148-windows`. The mutation lands on exactly the field we touched, and nothing else drifted.

## What `describe_preset` returns

A complete `PresetFile` with everything resolved:

```json
{
  "version": 1,
  "preset": {
    "name": "chrome-148-windows",
    "tls": {
      "client_hello": "chrome-146-windows",
      "psk_client_hello": "chrome-146-windows-psk",
      "quic_client_hello": "chrome-146-quic",
      "quic_psk_client_hello": "chrome-146-quic-psk"
    },
    "http2": {
      "header_table_size": 65536,
      "enable_push": false,
      "max_concurrent_streams": 0,
      "initial_window_size": 6291456,
      "max_frame_size": 0,
      "max_header_list_size": 262144,
      "connection_window_update": 15663105,
      "stream_weight": 256,
      "stream_exclusive": true,
      "no_rfc7540_priorities": false,
      "settings_order": [1, 2, 4, 6],
      "pseudo_order": [":method", ":authority", ":scheme", ":path"],
      "hpack_indexing_policy": "chrome",
      "stream_priority_mode": "chrome",
      "disable_cookie_split": true,
      "priority_table": {
        "document":  {"urgency": 0, "incremental": true,  "emit_header": true},
        "style":     {"urgency": 0, "incremental": false, "emit_header": true},
        "script":    {"urgency": 1, "incremental": false, "emit_header": true},
        "image":     {"urgency": 2, "incremental": true,  "emit_header": true},
        ...
      }
    },
    "http3": { ... },
    "headers": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
      "values": { "sec-ch-ua": "\"Chromium\";v=\"148\", ...", ... },
      "order": [
        {"key": "sec-ch-ua", "value": "..."},
        {"key": "sec-ch-ua-mobile", "value": "?0"},
        ...
      ]
    },
    "tcp": { "ttl": 128, "mss": 1460, "window_size": 64240, "window_scale": 8, "df_bit": true },
    "protocols": { "http3": true }
  }
}
```

Worth noting:

- Inheritance is flattened. `chrome-148-windows` is internally based on `chrome-147-windows`, which is based on `chrome-146-windows`, but the describe output has no `based_on` field. Every value is emitted explicitly, so there's no chain to chase.
- `tls.client_hello` says `chrome-146-windows`. That's the underlying utls ClientHelloID we use. TLS bytes haven't changed since Chrome 146 desktop; only the User-Agent and sec-ch-ua values have moved.
- Every H2 SETTINGS value shows up, even the zero ones (`max_concurrent_streams: 0`, `max_frame_size: 0`). Zero means "don't emit this SETTINGS entry on the wire", and that information survives the round-trip.
- The full RFC 7540 priority table lands under `http2.priority_table`. Chrome 147+ ships its real per-Sec-Fetch-Dest urgencies. Presets that opt out (Safari, iOS Chrome, iOS Safari) skip this block.

For the full schema with every field documented, see the [JSON Preset Spec](../reference/json-preset-spec).

## Inheritance with `based_on`

The dump-and-edit flow isn't the only option. A thin patch JSON listing only the fields you want to change, with `based_on` pointing at the parent, works just as well:

```json
{
  "version": 1,
  "preset": {
    "name": "my-chrome-mutant",
    "based_on": "chrome-148-windows",
    "headers": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/200.0.0.0 Safari/537.36"
    }
  }
}
```

That's exactly what our embedded `chrome-148-windows.json` does: a 28-line patch on top of `chrome-147-windows`. Inheritance is recursive with a loop guard, so cycles get caught at load time.

When to use which:

- `based_on` patches are tiny and readable. Prefer them for "I want N+1 of an existing browser version" cases.
- Full describe, mutate, load is mandatory when you need to override a field that's normally inherited, like clearing a sec-ch-ua brand the parent set. Setting a field to its zero value in a `based_on` patch is the same as not setting it, so the dump-and-edit path is the only way through.

## Strict registration vs overwrite

`load_preset_from_json` registers the preset by name and silently overwrites any existing custom registration with the same name. Built-in names are blocked, so you can't shadow `chrome-latest`.

For hard collision errors instead of silent overwrites, the Go API has `RegisterStrict`:

```go
p, _ := fingerprint.BuildPreset(spec)
if err := fingerprint.RegisterStrict(p.Name, p); err != nil {
    // name already taken, bail
}
```

Bindings (Python / Node / .NET) only expose the silent-overwrite path right now.

:::tip
This is the path for supporting a Chrome version we haven't shipped yet. Take `chrome-latest` as the base, override the sec-ch-ua brand list and User-Agent, and you've got `chrome-N+1` in five minutes. The TLS handshake stays correct because Chrome rarely changes the TLS layer between minor versions, and when it does we ship a new preset within a release cycle.
:::
