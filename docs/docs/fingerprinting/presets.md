---
title: Presets
sidebar_position: 3
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Presets

A preset is a full bundle of fingerprint state for one specific browser version on one specific platform. It packs:

- TLS ClientHello (cipher list, extension list, supported groups, signature algorithms, ALPN, cert compression).
- HTTP/2 SETTINGS values, WINDOW_UPDATE, pseudo-header order.
- Default HTTP headers in the exact order Chrome / Firefox / Safari sends them.
- RFC 7540 stream priorities and the RFC 9218 priority table per Sec-Fetch-Dest.
- HTTP/3 / QUIC transport parameters (only on presets that support h3).
- TCP/IP fingerprint hints (TTL, MSS, window size: for OS-level matching).

You pick a preset by name, send a request, that's it. The wire bytes match the real browser.

## Picking the right preset

- **Default to `chrome-latest`.** This is what works against the widest range of targets. It auto-tracks the most recent Chrome version we've shipped support for.
- **Use `android-chrome-latest` if your target needs a mobile UA.** Mobile traffic gets different scoring on most anti-bot stacks. The TLS handshake is identical to desktop Chrome but the User-Agent and `sec-ch-ua-mobile: ?1` flag the mobile path.
- **Use `ios-safari-18` or `safari-18-ios` if you specifically need an iPhone fingerprint.** Different cipher list, different pseudo-header order, no RFC 7540 priorities, smaller QUIC stream window. Targets that profile iOS users will catch a Chrome preset pretending to be an iPhone in seconds.
- **Use `firefox-148` if a target only allows Firefox.** Different cipher list, different SETTINGS layout (smaller initial window, smaller max frame size), different pseudo-header order (`m,p,a,s` instead of Chrome's `m,a,s,p`).

## Available preset families

### Chrome

Versions 133, 141, 143, 144, 145, 146, 147, 148. Each version has per-OS variants:

| Family | Variants |
|---|---|
| Desktop | `chrome-148`, `chrome-148-windows`, `chrome-148-linux`, `chrome-148-macos` |
| Android | `chrome-148-android` (alias: `android-chrome-148`) |
| iOS     | `chrome-148-ios` (alias: `ios-chrome-148`) |

The bare `chrome-148` resolves to the host OS at runtime via `runtime.GOOS`. So on a Linux server, `chrome-148` returns `chrome-148-linux`. If you want a deterministic platform UA regardless of where the code runs, use the explicit variant.

### Chrome -latest aliases

Aliases that auto-track the newest shipped Chrome:

```
chrome-latest          → chrome-148
chrome-latest-windows  → chrome-148-windows
chrome-latest-linux    → chrome-148-linux
chrome-latest-macos    → chrome-148-macos
chrome-latest-android  → chrome-148-android
chrome-latest-ios      → chrome-148-ios
```

When we ship Chrome 149, those aliases bump in lockstep. Code that uses `chrome-latest` keeps working. Code that pinned `chrome-148-windows` keeps the exact same fingerprint.

### Firefox

`firefox-133`, `firefox-148`, `firefox-latest`. No per-OS variants, Firefox doesn't include enough OS info in its fingerprint to make per-OS variants useful. Doesn't support h3 (Firefox has its own h3 quirks we haven't built out yet).

### Safari

| Preset | Notes |
|---|---|
| `safari-18` (`safari-latest`) | Desktop macOS Safari 18, supports h3 |
| `safari-17-ios` (`ios-safari-17`) | iPhone Safari 17, h2 only |
| `safari-18-ios` (`ios-safari-18`, `safari-latest-ios`) | iPhone Safari 18, supports h3 |

Safari has `NoRFC7540Priorities=true`, meaning the H2 PRIORITY frame is never emitted. RFC 9218 priority headers handle the priority signal instead. This is the single biggest tell that distinguishes a Safari fingerprint from a Chrome one at the H2 layer, even though both ALPN as h2.

### Backwards-compat aliases

We also accept the older `<os>-<browser>-<version>` naming for users on older docs:

```
ios-chrome-148        → chrome-148-ios
ios-safari-18         → safari-18-ios
android-chrome-148    → chrome-148-android
```

Both forms resolve to the same preset.

## Inheritance: how a new Chrome version ships in 30 seconds

Each Chrome minor bump is usually pure UA + sec-ch-ua delta. The TLS fingerprint, H2 SETTINGS, header order, priority table, all the same as the previous version. So we don't ship Chrome 148 as a from-scratch Go file. We ship it as a JSON delta over Chrome 147:

```json
{
  "version": 1,
  "preset": {
    "name": "chrome-148-windows",
    "based_on": "chrome-147-windows",
    "headers": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
      "values": {
        "sec-ch-ua": "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\""
      },
      "order": [
        {"key": "sec-ch-ua", "value": "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\""},
        {"key": "sec-ch-ua-mobile", "value": "?0"},
        ...
      ]
    }
  }
}
```

That's the whole patch. The TLS bytes come from chrome-147-windows (which itself inherits TLS bytes from chrome-146-windows because nothing changed in 147). The H2 SETTINGS, priority table, everything else, all inherited.

You can do the same. Pick a preset, dump it, change three fields, register the result. See [JSON Preset Builder](./json-preset-builder).

## Verification

Hit `tls.peet.ws/api/all` with each preset and you get the matching JA4 / Akamai hash:

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
    for _, name := range []string{"chrome-latest", "android-chrome-148", "firefox-148", "safari-18-ios"} {
        s := httpcloak.NewSession(name)
        resp, _ := s.Get(context.Background(), "https://tls.peet.ws/api/all")
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        s.Close()
        fmt.Println(name, string(body))
    }
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

for name in ["chrome-latest", "android-chrome-148", "firefox-148", "safari-18-ios"]:
    with httpcloak.Session(preset=name) as s:
        r = s.get("https://tls.peet.ws/api/all")
        print(name, r.json())
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
const { Session } = require("httpcloak");

for (const name of ["chrome-latest", "android-chrome-148", "firefox-148", "safari-18-ios"]) {
  const s = new Session({ preset: name });
  const r = await s.get("https://tls.peet.ws/api/all");
  console.log(name, r.json());
  s.close();
}
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

foreach (var name in new[] { "chrome-latest", "android-chrome-148", "firefox-148", "safari-18-ios" }) {
    using var s = new Session(preset: name);
    var r = await s.GetAsync("https://tls.peet.ws/api/all");
    Console.WriteLine($"{name} {r.Text}");
}
```

</TabItem>
</Tabs>

Captured fingerprints (run on 2026-05, against `tls.peet.ws/api/all`):

```text
chrome-latest        ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd  peetprint_hash=1d4ffe9b0e34acac0bd883fa7f79d7b5  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
chrome-148-windows   ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd  peetprint_hash=1d4ffe9b0e34acac0bd883fa7f79d7b5  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
chrome-148-linux     ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd  peetprint_hash=1d4ffe9b0e34acac0bd883fa7f79d7b5  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
chrome-148-macos     ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd  peetprint_hash=1d4ffe9b0e34acac0bd883fa7f79d7b5  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
android-chrome-148   ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd  peetprint_hash=1d4ffe9b0e34acac0bd883fa7f79d7b5  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
firefox-148          ja4=t13d1717h2_5b57614c22b0_3cbfd9057e0d  peetprint_hash=89d89662b21018947a9a46658c4f5ede  akamai_fingerprint_hash=6ea73faa8fc5aac76bded7bd238f6433
safari-18            ja4=t13d2013h2_a09f3c656075_7f0f34a4126d  peetprint_hash=62b834de729e78a9f0ebd1dd099314a7  akamai_fingerprint_hash=90d8353e47699c4c38ecd773e9b5a089
safari-18-ios        ja4=t13d2013h2_a09f3c656075_7f0f34a4126d  peetprint_hash=62b834de729e78a9f0ebd1dd099314a7  akamai_fingerprint_hash=90d8353e47699c4c38ecd773e9b5a089
chrome-148-ios       ja4=t13d2013h2_a09f3c656075_7f0f34a4126d  peetprint_hash=62b834de729e78a9f0ebd1dd099314a7  akamai_fingerprint_hash=c52879e43202aeb92740be6e8c86ea96
```

Things to spot:

- All Chrome desktop variants share the same JA4 / peetprint / akamai hash. The TLS handshake is genuinely identical across Windows / Linux / macOS Chrome. Only the User-Agent and the `sec-ch-ua-platform` header tell you which OS you're on.
- Android Chrome shares the same fingerprint as desktop Chrome too. Same TLS, same H2. The only difference at the wire level is the UA string (Mobile Safari/537.36) and `sec-ch-ua-mobile: ?1`.
- Chrome on iOS is identified at the wire level as Safari, because iOS WebKit forces every browser to use the system networking stack. So `chrome-148-ios` shares its TLS handshake and JA4 hash with `safari-18-ios`. They differ only on the H2 SETTINGS values (chrome-148-ios advertises a different settings order: `2,3,4,9` vs Safari's `2,4,3,5,9`) and on the User-Agent header.
- Firefox and Safari each have their own JA4 / peetprint / akamai. Different cipher list, different SETTINGS, different pseudo-header order.

:::tip
The bare `ja3_hash` field will not be stable for Chrome presets across runs. Chrome shuffles its TLS extension order on every connection, so the raw JA3 string changes and so does its MD5 hash. JA4 sorts the extension list before hashing, which is why it's stable. Always verify against `ja4` and `peetprint_hash`, never against `ja3_hash`.
:::

## Full preset catalog

There are 69 preset names (counting -latest aliases and the old `<os>-<browser>` naming). For the exhaustive table with version numbers, supported protocols, and platform tags, see the [Presets reference](../reference/presets).
