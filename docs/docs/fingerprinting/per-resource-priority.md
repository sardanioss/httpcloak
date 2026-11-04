---
title: Per-Resource Priority
sidebar_position: 7
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Per-Resource Priority

Browsers don't ask for every resource at the same priority. The HTML document goes out highest, the main stylesheet right behind it, deferred scripts way at the back, images somewhere in the middle. The browser signals this in two places:

- **RFC 7540 stream weights** on the H2 PRIORITY frame attached to HEADERS. Numeric weight 1 to 256.
- **RFC 9218 priority HTTP header** on H2 and H3 requests (Firefox sends it over HTTP/1.1 as well). Format `u=N, i` where N is urgency 0-7 and `i` is the incremental flag.

Chrome 147+ desktop emits both. The header carries urgency, and the wire weight is derived from urgency by `weight = 256 - (urgency * 73) / 2`. So urgency 0 lands on weight 256, urgency 1 on 220, urgency 2 on 183, urgency 3 on 147 (Chrome's default), urgency 4 on 110.

Anti-bot vendors watch this because a single-weight H2 PRIORITY frame on every request is a dead giveaway. Real Chrome traffic varies the weight per resource type, and a bot client that pumps weight 256 (or weight 1) on every request looks nothing like Chrome.

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

Captured from real Chrome 147+ desktop traffic. Each Chrome / Firefox / Safari preset can override it via the `priority_table` field in the JSON spec. Presets that set `no_rfc7540_priorities: true` (Safari, iOS Chrome, iOS Safari) advertise `SETTINGS_NO_RFC7540_PRIORITIES` and don't use the table at all: every request carries the preset's static weight, and any priority header comes from the preset's own header block.

The wire weight on the H2 HEADERS frame comes from the urgency. `Sec-Fetch-Dest: image` lands on wire weight 183 (urgency 2), and `Sec-Fetch-Dest: style` lands on wire weight 256 (urgency 0). The priority HTTP header carries the same urgency value.

### Chrome and Firefox work it out differently

The table above is Chrome's, and so is the rule that turns urgency into a weight. Firefox does neither. Its weight is a fixed number per resource type, unrelated to the urgency in its header: a document goes at 42, a stylesheet, script, iframe or `fetch()` at 22, a font at 32 and an image at 12, with headers of `u=0, i`, `u=2`, `u=4` and `u=5, i` to match. Measured on Firefox 133, 148 and 152, which agree on every entry. The Firefox presets carry that table.

Three more differences come with it, and a preset's `priority_model` (`chromium` or `table`) says which side it is on:

- **Who decides the weight.** On the `chromium` model a request that sets its own `priority` header gets the weight that goes with that urgency, as Chrome does for a `fetch()` with a priority hint. On the `table` model the weight always comes from the table entry, whatever header the request carries.
- **Stream dependencies.** Chrome never names stream 0 as the parent once two requests overlap on a connection: each new stream depends, exclusively, on the newest open stream at the same or a higher priority, so the tree is one chain. The `chromium` model builds that chain. Firefox names stream 0, never exclusive, and so does the `table` model.
- **HTTP/1.1.** Chrome sends no priority header over HTTP/1.1, and Firefox sends the same one it sends over HTTP/2. Chrome on iOS runs on WebKit and sends none there either. A preset can state this outright with `priority_over_http1`. On a preset that sends none, a `priority` you set yourself is dropped on HTTP/1.1 too, so the value meant for HTTP/2 does not leak when a request falls back. Exact-headers and TLS-only requests go out as you composed them.

Leave `priority_model` out and it is derived from `stream_exclusive`, which only Chromium sets. A table entry can also carry its own `weight` (1 to 256), which overrides the one derived from the urgency; that is how the Firefox table is written.

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
    s := httpcloak.NewSession("chrome-152-windows")
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

with httpcloak.Session(preset="chrome-152-windows") as s:
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

const s = new Session({ preset: "chrome-152-windows" });
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

using var s = new Session(preset: "chrome-152-windows");
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

The H2 wire stream weight on each HEADERS frame matches: 256 for document, 256 for style, 220 for script, 183 for image, 220 for empty. Real Chrome traffic ships this exact mapping.

:::info
Skip `Sec-Fetch-Dest` and httpcloak's auto-detect sets it for you. Top-level navigations get `document`, XHR / fetch() requests get `empty`, and sub-resource loads (image / script / stylesheet tags) keep whatever value you passed. Most sites don't check H2 PRIORITY weight per request, but Cloudflare and Akamai do at the H2 / H3 layer. CF challenges that don't show up in a real browser test often trace back to a priority weight mismatch.
:::

## Capturing the wire-level frame

The HTTP header is easy to verify since `tls.peet.ws/api/all` reflects it. The H2 PRIORITY frame on the wire takes more work. It's piggy-backed inside the HEADERS frame, not a separate frame, and `tls.peet.ws` doesn't expose it. Reading the actual wire weight needs a Wireshark capture with the TLS keylog file, or one of the H2 fingerprinting test sites like `cf.erika.cool` that decode and reflect the priority frame.

For keylog setup, see [TLS Keylog](../advanced-tls/tls-keylog).

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
    "based_on": "chrome-152-windows",
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

Flip `emit_header: false` on any resource where you want the priority HTTP header suppressed while the wire frame still goes out. Chrome does this for async / defer scripts: the wire weight stays 147 (urgency 3), and the priority header drops.

To turn per-resource priority off entirely on a preset (every request gets the static `stream_weight` from H2 SETTINGS), set `priority_table` to an empty object `{}`. The transport falls back to the static weight.

## Per-preset behaviour

| Preset family | Priority fields on HEADERS | `priority` header | Table |
|---|---|---|---|
| Chrome desktop and Android | weight from the urgency (256, 220, 183, ...), exclusive, chained onto the newest open stream at the same or a higher priority | HTTP/2 and HTTP/3, never HTTP/1.1 | Chrome's 14-destination table |
| Firefox | weight from Firefox's table (42, 32, 22, 12), never exclusive, parent stream 0 | every protocol, HTTP/1.1 included | Firefox's table |
| Safari, desktop and iOS | weight 255 on every request, never exclusive, parent stream 0 | none | none |
| Chrome on iOS | weight 255 on every request, never exclusive, parent stream 0 | HTTP/2 and HTTP/3, never HTTP/1.1 | none |

A custom preset inherits the 14-dest table for free unless you override it. Setting `http2.no_rfc7540_priorities: true` turns the table off and advertises `SETTINGS_NO_RFC7540_PRIORITIES`, the way Safari does; every request then goes at the static `stream_weight`.

## Why this matters

A constant H2 stream weight on every request is one of the easiest H2 fingerprint giveaways, and Cloudflare and Akamai both check it. The priority header check is newer, since RFC 9218 only stabilized in 2022, but it's becoming standard at major edge providers. httpcloak handles both as long as your preset is a modern one (Chrome 147+, Firefox 148+, Safari 18+).

Edge-vendor challenges that don't reproduce in a real browser session usually trace back to this layer. Capture the wire-level H2 frames from both, diff the priority weights, and check whether your preset's `priority_table` matches. Every Chrome preset, the older `chrome-133` and `chrome-141` included, uses the per-`Sec-Fetch-Dest` table; v1.6.5 gave it to the presets that predate it (issue #56). For new code, stick with `chrome-latest` or an explicit recent version.
