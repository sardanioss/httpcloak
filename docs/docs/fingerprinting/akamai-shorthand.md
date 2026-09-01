---
title: Akamai Shorthand
sidebar_position: 6
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Akamai Shorthand

The Akamai HTTP/2 fingerprint is a compact string that captures how a client opens an H2 connection. It's the H2 equivalent of a JA3. Anti-bot vendors hash it and check against a known-browser allowlist, the same playbook as JA3.

## Format

Four pipe-separated fields:

```
SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
```

Real Chrome 148:

```
1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

Real Firefox 148:

```
1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
```

Real iOS Safari 18:

```
2:0;4:2097152;3:100;5:16384;9:1|10485760|0|m,s,p,a
```

### SETTINGS

Semicolon-separated `id:value` pairs from the SETTINGS frame. Standard H2 IDs:

| ID | Name | Notes |
|---|---|---|
| 1 | HEADER_TABLE_SIZE | Chrome 65536, Firefox 65536, Safari omits |
| 2 | ENABLE_PUSH | All browsers send 0 |
| 3 | MAX_CONCURRENT_STREAMS | Safari 100, Chrome / Firefox omit |
| 4 | INITIAL_WINDOW_SIZE | Chrome 6291456, Firefox 131072, Safari 2097152 |
| 5 | MAX_FRAME_SIZE | Firefox 16384, Safari 16384, Chrome omits |
| 6 | MAX_HEADER_LIST_SIZE | Chrome 262144, others omit |
| 9 | NO_RFC7540_PRIORITIES | Safari 1, others omit |

Pair order in the string matches wire-frame order. Chrome ships `1, 2, 4, 6`. Firefox: `1, 2, 4, 5`. Safari: `2, 4, 3, 5, 9`. iOS Chrome is slightly different: `2, 3, 4, 9`. Match the order or your akamai hash won't match either.

### WINDOW_UPDATE

The connection-level WINDOW_UPDATE increment sent right after SETTINGS. Chrome 148: 15663105. Firefox 148: 12517377. Safari 18: 10485760.

### PRIORITY

The H2 PRIORITY frame value. `0` means no PRIORITY frame goes out, which is what Chrome / Firefox / Safari all do as of 2026. They signal priority via the priority HTTP header instead. Older Chrome versions used to send a stream weight in this slot.

### PSEUDO_HEADER_ORDER

Comma-separated single-char identifiers for the order of pseudo-headers in the first HEADERS frame:

- `m` = `:method`
- `a` = `:authority`
- `s` = `:scheme`
- `p` = `:path`

Chrome: `m,a,s,p`. Firefox: `m,p,a,s`. Safari: `m,s,p,a`. iOS Chrome: `m,s,a,p`. Every browser is different, and the akamai hash captures it.

## When to override

The akamai shorthand override keeps the preset's TLS handshake intact and only tweaks the H2 fingerprint. Common cases:

- A target rejects the default Chrome H2 settings but takes a slightly larger initial window.
- You captured an akamai string from a real browser and want to mirror it exactly.
- You're spoofing a Chrome version we haven't shipped yet that bumped a single SETTINGS value.

For anything beyond H2 SETTINGS, like overriding the priority table, the HPACK header order, or per-request priorities, the [JSON Preset Builder](./json-preset-builder) is the right tool.

## API

`WithCustomFingerprint` accepts a JA3 and an akamai string. Set one, the other, or both.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
    "context"
    "fmt"
    "io"

    "github.com/sardanioss/httpcloak"
)

func main() {
    s := httpcloak.NewSession("chrome-152-windows",
        httpcloak.WithCustomFingerprint(httpcloak.CustomFingerprint{
            // Keep Chrome's TLS, override only H2.
            Akamai: "1:65536;2:0;4:8388608;6:262144|15663105|0|m,a,s,p",
        }),
    )
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
import httpcloak

with httpcloak.Session(
    preset="chrome-152-windows",
    akamai="1:65536;2:0;4:8388608;6:262144|15663105|0|m,a,s,p",
) as s:
    r = s.get("https://tls.peet.ws/api/all")
    print(r.json())
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
const { Session } = require("httpcloak");

const s = new Session({
  preset: "chrome-152-windows",
  akamai: "1:65536;2:0;4:8388608;6:262144|15663105|0|m,a,s,p",
});

const r = await s.get("https://tls.peet.ws/api/all");
console.log(r.json());
s.close();
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(
    preset: "chrome-152-windows",
    akamai: "1:65536;2:0;4:8388608;6:262144|15663105|0|m,a,s,p");

var r = await s.GetAsync("https://tls.peet.ws/api/all");
Console.WriteLine(r.Text);
```

</TabItem>
</Tabs>

## How shorthand interacts with the preset

When you set `Akamai`, the parser fills in only the slots that appear in your string. Slots you skip keep the preset's value.

- SETTINGS pairs you list overwrite the preset's same-ID values.
- SETTINGS IDs you don't list keep the preset's value.
- A non-empty `WINDOW_UPDATE` overrides; empty keeps the preset.
- A non-zero `PRIORITY` weight enables the H2 PRIORITY frame; zero disables it.
- A non-empty pseudo-header order overrides; empty keeps the preset's.

A minimal patch is enough, and the rest of the H2 state stays correct:

```
1:65536|0|0|m,a,s,p
```

That's a complete akamai string that sets `HEADER_TABLE_SIZE` to 65536 and leaves WINDOW_UPDATE, PRIORITY, and pseudo-header order at the preset's values (zero / default). The parser requires exactly four pipe-separated fields (`SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO`) and rejects empty SETTINGS values, so the absolute minimum is one valid `id:value` pair plus three placeholder fields.

## Verifying

Send a request through the override, read `tls.peet.ws`'s `http2.akamai_fingerprint` field. It matches what you sent:

```text
input akamai:           1:65536;2:0;4:8388608;6:262144|15663105|0|m,a,s,p
output akamai (peet):   1:65536;2:0;4:8388608;6:262144|15663105|0|m,a,s,p
output akamai_hash:     <stable MD5 over the string>
```

If the reflected akamai string doesn't match exactly, the parser dropped a field. Most common cause: a typo in the SETTINGS pair list. `1:65536;2:0` is fine; `1=65536,2=0` is not. The parser expects colon-separated pairs joined by semicolons.

:::warning
`akamai_fingerprint_hash` is an MD5 of the akamai string with sorted SETTINGS keys. Two strings that differ only in SETTINGS order produce the same hash, so `1:65536;4:6291456` and `4:6291456;1:65536` hash identically even though the strings differ. Wire-level SETTINGS frame order still matters for the H2 fingerprinters that look past the basic akamai hash, since those check the unsorted string. Always send fields in the order the real browser does.
:::

## Programmatic parsing

The `fingerprint` package exposes the parser directly. Useful when you've captured an akamai string from a real browser session and want to validate it before plugging into a preset, or when you're writing tooling that reads akamai strings out of a config file:

```go
import "github.com/sardanioss/httpcloak/fingerprint"

settings, pseudoOrder, err := fingerprint.ParseAkamai(
    "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
)
if err != nil {
    // string didn't match the SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO shape
}
// settings is *fingerprint.HTTP2Settings ready to drop into a custom preset
// pseudoOrder is the resolved [":method", ":authority", ":scheme", ":path"]
```

For richer introspection (which fields were present in the input vs which fields fell back to defaults), `ParseAkamaiDetailed` returns an `*AkamaiPresence` struct. That's the right call when you need to reason about partial overrides:

```go
pres, err := fingerprint.ParseAkamaiDetailed("1:65536|0|0|m,a,s,p")
// pres.Settings:        *HTTP2Settings with the parsed values
// pres.PseudoOrder:     []string with the resolved ":method" / ":authority" / ... slot order
// pres.SeenSettings:    map[uint16]bool of SETTINGS IDs that appeared in the string
// pres.HasWindowUpdate: true if the WINDOW_UPDATE field carried a value
// pres.HasStreamWeight: true if the PRIORITY field had a non-zero weight
```

Use `SeenSettings[id]` to tell "the input set SETTING N to a value (possibly zero)" apart from "the input never mentioned SETTING N, so the preset's value is in effect". Both parsers reject malformed input rather than silently filling defaults: a string with the wrong field count, an empty SETTINGS value, or a non-numeric SETTINGS pair returns an error. Validate user-supplied akamai strings through one of these before passing them into a preset and you avoid the parse-time crash that the `Akamai` session option would otherwise hit at first request.
