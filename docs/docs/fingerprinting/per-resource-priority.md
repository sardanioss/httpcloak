---
title: Per-Resource Priority
sidebar_position: 7
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Per-Resource Priority

Browsers don't ask for every resource at the same priority. The HTML document goes out highest, the main stylesheet right behind it, deferred scripts way at the back, images somewhere in the middle. The browser signals this in two places:

- **RFC 7540 stream weights** on the H2 PRIORITY frame attached to HEADERS. Numeric weight 1 to 256.
- **RFC 9218 priority HTTP header** on every H2 / H3 request. Format `u=N, i` where N is urgency 0-7 and `i` is the incremental flag.

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

Captured from real Chrome 147+ desktop traffic. Each Chrome / Firefox / Safari preset can override it via the `priority_table` field in the JSON spec. Presets that opt out entirely (Safari, iOS Chrome, iOS Safari, `no_rfc7540_priorities: true`) skip the H2 PRIORITY frame and only emit the priority header.

The wire weight on the H2 HEADERS frame comes from the urgency. `Sec-Fetch-Dest: image` lands on wire weight 183 (urgency 2), and `Sec-Fetch-Dest: style` lands on wire weight 256 (urgency 0). The priority HTTP header carries the same urgency value.

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

| Preset family | RFC 7540 PRIORITY frame | RFC 9218 priority header | Default table |
|---|---|---|---|
| Chrome desktop 147+ (incl. 148) | yes | yes | 14-dest table above |
| Chrome desktop 141 / 133 (legacy presets) | yes (static weight 256, exclusive) | no | n/a |
| Chrome Android 148 | yes | yes | 14-dest table above |
| Firefox 148 | yes | yes (different urgencies, currently uses Chrome table, capture pending) | inherits Chrome table |
| Safari 18 desktop | no | yes | inherits Chrome table for header values; never emits H2 PRIORITY frame |
| iOS Chrome / iOS Safari | no | yes | same |

A custom preset inherits the 14-dest table for free unless you override it. To opt out of RFC 7540 entirely (no PRIORITY frame on the wire), set `http2.no_rfc7540_priorities: true`. The priority HTTP header still fires unless you flip `emit_header: false` on every entry too.

## Why this matters

A constant H2 stream weight on every request is one of the easiest H2 fingerprint giveaways, and Cloudflare and Akamai both check it. The priority header check is newer, since RFC 9218 only stabilized in 2022, but it's becoming standard at major edge providers. httpcloak handles both as long as your preset is a modern one (Chrome 147+, Firefox 148+, Safari 18+).

Edge-vendor challenges that don't reproduce in a real browser session usually trace back to this layer. Capture the wire-level H2 frames from both, diff the priority weights, and check whether your preset's `priority_table` matches. The legacy `chrome-141` and `chrome-133` presets still ship a constant `weight=256, exclusive=true` on every request because they predate the per-resource priority work; modern Cloudflare flags that. The 143-148 family inherits the per-`Sec-Fetch-Dest` table after issue #56 (v1.6.5 retroactively gave chrome-141-through-chrome-147 the inherited table; v1.6.6 keeps that). For new code, stick with `chrome-latest` or any 143+ explicit version.
