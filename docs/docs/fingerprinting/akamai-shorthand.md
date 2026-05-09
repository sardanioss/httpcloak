---
title: Akamai Shorthand
sidebar_position: 6
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Akamai Shorthand

The Akamai HTTP/2 fingerprint is a compact string that fully describes how a client opens an H2 connection. It's the H2 equivalent of a JA3 string. Anti-bot vendors hash it and check the hash against a known-browser allowlist, same playbook as JA3.

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

The order of pairs in the string matches the wire-frame order. For Chrome that's `1, 2, 4, 6`. Firefox is `1, 2, 4, 5`. Safari is `2, 4, 3, 5, 9`. iOS Chrome differs slightly: `2, 3, 4, 9`. Match the order or the akamai hash won't match.

### WINDOW_UPDATE

The connection-level WINDOW_UPDATE increment sent immediately after SETTINGS. Chrome 148 sends 15663105. Firefox 148 sends 12517377. Safari 18 sends 10485760.

### PRIORITY

The H2 PRIORITY frame value. `0` means no PRIORITY frame is sent (which is what Chrome / Firefox / Safari all do as of 2026, they signal priority via the priority HTTP header instead). Older Chrome versions sent a stream weight here.

### PSEUDO_HEADER_ORDER

Comma-separated single-char identifiers for the order of pseudo-headers in the first HEADERS frame:

- `m` = `:method`
- `a` = `:authority`
- `s` = `:scheme`
- `p` = `:path`

Chrome: `m,a,s,p`. Firefox: `m,p,a,s`. Safari: `m,s,p,a`. iOS Chrome: `m,s,a,p`. Each browser is different and the akamai hash captures it.

## When to override

Use the akamai shorthand override when you want to keep the preset's TLS handshake but tweak the H2 fingerprint. Common cases:

- A target rejects the default Chrome H2 settings but accepts a slightly larger initial window.
- You captured an akamai string from a real browser and want to mirror it exactly.
- You're trying to mimic a Chrome version we haven't shipped yet that bumped a single SETTINGS value.

When you need anything beyond H2 SETTINGS, like overriding the priority table, the HPACK header order, or per-request priorities, the [JSON Preset Builder](./json-preset-builder) is the right path.

## API

`WithCustomFingerprint` takes both a JA3 and an akamai string. You can set just one, just the other, or both.

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
    s := httpcloak.NewSession("chrome-148-windows",
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
    preset="chrome-148-windows",
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
  preset: "chrome-148-windows",
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
    preset: "chrome-148-windows",
    akamai: "1:65536;2:0;4:8388608;6:262144|15663105|0|m,a,s,p");

var r = await s.GetAsync("https://tls.peet.ws/api/all");
Console.WriteLine(r.Text);
```

</TabItem>
</Tabs>

## How shorthand interacts with the preset

When you set `Akamai`, the parser fills in only the slots present in your string. Slots you don't mention keep the preset's value.

- SETTINGS pairs you list overwrite the preset's same-ID values.
- SETTINGS IDs you don't list keep the preset's value.
- A non-empty `WINDOW_UPDATE` overrides; empty keeps the preset.
- A non-zero `PRIORITY` weight enables the H2 PRIORITY frame; zero disables it.
- A non-empty pseudo-header order overrides; empty keeps the preset's.

This means you can write a minimal patch and the rest of the H2 state stays correct:

```
1::|||
```

That's a valid akamai string that says "set HEADER_TABLE_SIZE to its default but don't change anything else". In practice you want at least three or four fields to be useful.

## Verifying

Send a request through the override, read `tls.peet.ws`'s `http2.akamai_fingerprint` field. It should match what you sent:

```text
input akamai:           1:65536;2:0;4:8388608;6:262144|15663105|0|m,a,s,p
output akamai (peet):   1:65536;2:0;4:8388608;6:262144|15663105|0|m,a,s,p
output akamai_hash:     <stable MD5 over the string>
```

If the reflected akamai string doesn't match exactly, the parser dropped a field. Most common cause: typo in the SETTINGS pair list (`1:65536;2:0` is fine, `1=65536,2=0` is not, the parser expects colon-separated pairs joined by semicolons).

:::warning
The `akamai_fingerprint_hash` is an MD5 of the akamai string with sorted SETTINGS keys. Two strings that differ only in SETTINGS order produce the same hash. So `1:65536;4:6291456` and `4:6291456;1:65536` hash identically even though they're different strings. The wire-level SETTINGS frame order matters for some H2 fingerprinters that go beyond the basic akamai hash; those care about the unsorted string. Always send fields in the order the real browser does.
:::
