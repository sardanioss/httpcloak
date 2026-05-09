---
title: Per-Resource Priority
sidebar_position: 7
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Per-Resource Priority

Real browsers don't request every resource with the same priority. The HTML document gets the highest priority, the page's main stylesheet right behind it, the deferred scripts way at the back, images somewhere in the middle. The browser tells the server about this in two places:

- **RFC 7540 stream weights** in the H2 PRIORITY frame on the HEADERS. Numeric weight 1 to 256.
- **RFC 9218 priority HTTP header** sent on every H2 / H3 request. Format `u=N, i` where N is urgency 0-7 and `i` is the incremental flag.

Chrome 147+ desktop emits both. The header tells you the urgency, the wire weight is derived from urgency by the formula `weight = 256 - (urgency * 73) / 2`. So urgency 0 maps to wire weight 256, urgency 1 to 220, urgency 2 to 183, urgency 3 to 147 (Chrome's default), urgency 4 to 110.

Anti-bot vendors care because a single-weight H2 PRIORITY frame on every request is a giveaway. Real Chrome traffic varies the weight per resource type. A bot client that emits weight 256 (or weight 1) on every request looks nothing like Chrome.

## How httpcloak picks the priority

The transport reads `Sec-Fetch-Dest` from the outgoing request and looks it up in a 14-destination table:

| Sec-Fetch-Dest | Urgency | Incremental | Header sent |
|---|---|---|---|
| `document` | 0 | true  | `u=0, i` |
| `style`    | 0 | false | `u=0` |
| `script`   | 1 | false | `u=1` |
| `image`    | 2 | true  | `u=2, i` |
| `font`     | 1 | false | `u=1` |
| `manifest` | 2 | false | `u=2` |
| `audio`    | 3 | true  | `i` |
| `video`    | 3 | true  | `i` |
| `embed`    | 0 | true  | `u=0, i` |
| `iframe`   | 0 | true  | `u=0, i` |
| `empty`    | 1 | true  | `u=1, i` |
| `object`   | 0 | true  | `u=0, i` |
| `track`    | 3 | true  | `i` |
| `worker`   | 4 | true  | `u=4, i` |

This table is captured from real Chrome 147+ desktop traffic. Each Chrome / Firefox / Safari preset can override it via the `priority_table` field in the JSON spec. Presets that opt out entirely (Safari, iOS Chrome, iOS Safari, `no_rfc7540_priorities: true`) don't emit the H2 PRIORITY frame at all and only emit the priority header.

The wire weight on the H2 HEADERS frame is derived from the urgency. So `Sec-Fetch-Dest: image` produces wire weight 183 (urgency 2), and `Sec-Fetch-Dest: style` produces wire weight 256 (urgency 0). The priority HTTP header carries the same urgency value.

## What you set, what you get

Send three requests with three different `Sec-Fetch-Dest` values:

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
    "context"
    "io"

    "github.com/sardanioss/httpcloak"
)

func main() {
    s := httpcloak.NewSession("chrome-148-windows")
    defer s.Close()

    for _, dest := range []string{"document", "style", "script", "image", "empty"} {
        req := &httpcloak.Request{
            Method: "GET",
            URL:    "https://tls.peet.ws/api/all",
            Headers: map[string][]string{
                "Sec-Fetch-Dest": {dest},
                "Sec-Fetch-Mode": {"no-cors"},
                "Sec-Fetch-Site": {"same-origin"},
            },
        }
        resp, _ := s.Do(context.Background(), req)
        io.ReadAll(resp.Body)
        resp.Body.Close()
    }
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-148-windows") as s:
    for dest in ["document", "style", "script", "image", "empty"]:
        s.get(
            "https://tls.peet.ws/api/all",
            headers={
                "Sec-Fetch-Dest": dest,
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "same-origin",
            },
        )
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
const { Session } = require("httpcloak");

const s = new Session({ preset: "chrome-148-windows" });
for (const dest of ["document", "style", "script", "image", "empty"]) {
  await s.get("https://tls.peet.ws/api/all", {
    headers: {
      "Sec-Fetch-Dest": dest,
      "Sec-Fetch-Mode": "no-cors",
      "Sec-Fetch-Site": "same-origin",
    },
  });
}
s.close();
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-148-windows");
foreach (var dest in new[] { "document", "style", "script", "image", "empty" }) {
    await s.GetAsync("https://tls.peet.ws/api/all", headers: new Dictionary<string, string> {
        ["Sec-Fetch-Dest"] = dest,
        ["Sec-Fetch-Mode"] = "no-cors",
        ["Sec-Fetch-Site"] = "same-origin",
    });
}
```

</TabItem>
</Tabs>

The `priority` HTTP header reflected back from `tls.peet.ws/api/all` (read from `http2.sent_frames[].headers`) for each value:

```text
Sec-Fetch-Dest=document  -> priority: u=0, i
Sec-Fetch-Dest=style     -> priority: u=0
Sec-Fetch-Dest=script    -> priority: u=1
Sec-Fetch-Dest=image     -> priority: u=2, i
Sec-Fetch-Dest=empty     -> priority: u=1, i
```

The H2 wire stream weight on each HEADERS frame matches: 256 for the document, 256 for the style, 220 for the script, 183 for the image, 220 for the empty. Real Chrome traffic does this exact mapping.

:::info
If you don't set `Sec-Fetch-Dest`, httpcloak's auto-detect will set it for you. Top-level navigations get `document`, XHR / fetch() requests get `empty`, sub-resource loads (image / script / stylesheet tags) keep whatever value you passed in. Most sites don't actually check the H2 PRIORITY weight per-request, but Cloudflare and Akamai do at the H2 / H3 layer. If you're seeing CF challenges that you don't see when scripted browser-test, the priority weight mismatch is a likely culprit.
:::

## Capturing the wire-level frame

The HTTP header is easy to verify (`tls.peet.ws/api/all` reflects it). The H2 PRIORITY frame on the wire takes more work, it's part of the HEADERS frame, not a separate frame, and `tls.peet.ws` doesn't expose it. To see the actual wire weight you need a Wireshark capture with the TLS keylog file, or one of the H2 fingerprinting test sites like `cf.erika.cool` that decode and reflect the priority frame.

For setting up the keylog, see [TLS Keylog](../advanced-tls/tls-keylog).

## Overriding the priority table per preset

The default 14-dest table is what every Chrome preset inherits. To override:

1. Describe the preset.
2. Edit the `http2.priority_table` block in the JSON.
3. Load the result back as a custom preset.

Example: clamp every resource to urgency 1 (so all wire weights become 220 and the header is `u=1, i` for incremental, `u=1` for non-incremental):

```json
{
  "version": 1,
  "preset": {
    "name": "chrome-148-flat-priority",
    "based_on": "chrome-148-windows",
    "http2": {
      "priority_table": {
        "document": {"urgency": 1, "incremental": true,  "emit_header": true},
        "style":    {"urgency": 1, "incremental": false, "emit_header": true},
        "script":   {"urgency": 1, "incremental": false, "emit_header": true},
        "image":    {"urgency": 1, "incremental": true,  "emit_header": true},
        "font":     {"urgency": 1, "incremental": false, "emit_header": true},
        "manifest": {"urgency": 1, "incremental": false, "emit_header": true},
        "audio":    {"urgency": 1, "incremental": true,  "emit_header": true},
        "video":    {"urgency": 1, "incremental": true,  "emit_header": true},
        "embed":    {"urgency": 1, "incremental": true,  "emit_header": true},
        "iframe":   {"urgency": 1, "incremental": true,  "emit_header": true},
        "empty":    {"urgency": 1, "incremental": true,  "emit_header": true},
        "object":   {"urgency": 1, "incremental": true,  "emit_header": true},
        "track":    {"urgency": 1, "incremental": true,  "emit_header": true},
        "worker":   {"urgency": 1, "incremental": true,  "emit_header": true}
      }
    }
  }
}
```

Set `emit_header: false` for any resource where you want the priority HTTP header suppressed but the wire frame still emitted. Chrome does this for async / defer scripts, the wire weight is still 147 (urgency 3) but the priority header is dropped.

To disable per-resource priority entirely on a preset (so every request gets the static `stream_weight` from the H2 SETTINGS), set `priority_table` to an empty object `{}`. The transport falls back to the static weight.

## Per-preset behaviour

| Preset family | RFC 7540 PRIORITY frame | RFC 9218 priority header | Default table |
|---|---|---|---|
| Chrome desktop 147+ (incl. 148) | yes | yes | 14-dest table above |
| Chrome desktop 146 and below | yes (static weight 256, exclusive) | no | n/a |
| Chrome Android 148 | yes | yes | 14-dest table above |
| Firefox 148 | yes | yes (different urgencies, currently uses Chrome table, capture pending) | inherits Chrome table |
| Safari 18 desktop | no | yes | inherits Chrome table for header values; never emits H2 PRIORITY frame |
| iOS Chrome / iOS Safari | no | yes | same |

When you build a custom preset, you get the 14-dest table for free if you don't override it. If you want to opt out of RFC 7540 entirely (no PRIORITY frame on the wire), set `http2.no_rfc7540_priorities: true`. The priority HTTP header still fires unless you also set `emit_header: false` on every entry.

## Why this matters

A constant H2 stream weight on every request is one of the easiest H2 fingerprint giveaways. Cloudflare and Akamai both check it. The priority header check is more recent, RFC 9218 only stabilized in 2022, but is becoming standard at major edge providers. httpcloak handles both automatically as long as your preset is one of the modern ones (Chrome 147+, Firefox 148+, Safari 18+).

If you're seeing edge-vendor challenges that don't reproduce in a real browser session, capture the wire-level H2 frames from both, diff the priority weights, and check if your preset's `priority_table` matches. Chrome 146 and below will produce a constant `weight=256, exclusive=true` on every request, that's our oldest behaviour and it's flagged by modern Cloudflare. Use `chrome-latest` or any 147+ for new code.
