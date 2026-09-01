---
title: Presets
sidebar_position: 3
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Presets

A preset is the full fingerprint bundle for one browser version on one platform. It packs:

- TLS ClientHello (cipher list, extension list, supported groups, signature algorithms, ALPN, cert compression).
- HTTP/2 SETTINGS values, WINDOW_UPDATE, pseudo-header order.
- Default HTTP headers in the exact order Chrome / Firefox / Safari ships them.
- RFC 7540 stream priorities and the RFC 9218 priority table per Sec-Fetch-Dest.
- HTTP/3 / QUIC transport parameters (only on presets that support h3).
- TCP/IP fingerprint hints (TTL, MSS, window size, for OS-level matching).

Pick one by name, send a request, the wire bytes match the real browser.

## Picking the right preset

- **Default to `chrome-latest`.** Works against the widest range of targets, and auto-tracks the newest Chrome we've shipped.
- **Reach for `android-chrome-latest` when you need a mobile UA.** Mobile traffic gets scored differently on most anti-bot stacks. The TLS handshake is identical to desktop Chrome, but the User-Agent and `sec-ch-ua-mobile: ?1` route the request onto the mobile path.
- **Use `ios-safari-18` (or `safari-18-ios`) for an iPhone fingerprint.** Different cipher list, different pseudo-header order, no RFC 7540 priorities, smaller QUIC stream window. Targets that profile iOS users will spot a Chrome preset pretending to be an iPhone in seconds.
- **Pick `firefox-148` when the target only accepts Firefox.** Different cipher list, different SETTINGS layout (smaller initial window, smaller max frame size), different pseudo-header order (`m,p,a,s` vs Chrome's `m,a,s,p`).

## Available preset families

### Chrome

Versions 133, 141, 143, 144, 145, 146, 147, 148, 149, 150, 151. The 143-151 line ships per-OS variants; 133 and 141 are desktop-only single presets without per-OS suffixes. Layout for the per-OS line (using 151 as the example):

| Family | Variants |
|---|---|
| Desktop | `chrome-152`, `chrome-152-windows`, `chrome-152-linux`, `chrome-152-macos` (and the same shape for 150, 149, 148 ...) |
| Android | `chrome-152-android` (alias: `android-chrome-152`) |
| iOS     | `chrome-152-ios` (alias: `ios-chrome-152`) |

Bare `chrome-152` resolves to the host OS at runtime via `runtime.GOOS`. On a Linux box, `chrome-152` gives you `chrome-152-linux`. For the same platform UA regardless of where the code runs, use the explicit variant.

### Chrome -latest aliases

Aliases that auto-track the newest shipped Chrome:

```
chrome-latest          → chrome-152
chrome-latest-windows  → chrome-152-windows
chrome-latest-linux    → chrome-152-linux
chrome-latest-macos    → chrome-152-macos
chrome-latest-android  → chrome-152-android
chrome-latest-ios      → chrome-152-ios
```

Every `chrome-latest*` alias tracks 152, iOS included: `chrome-152-ios` is built from real captures rather than derived, which matters because iOS Chrome spells its version out in full including a build number that cannot be guessed from the major version. Code on `chrome-latest` keeps rolling, and code that pinned `chrome-148-windows` stays on exactly the fingerprint it pinned.

### Firefox

`firefox-133`, `firefox-148`, `firefox-latest`, plus per-OS variants for both versions: `firefox-133-windows` / `-linux` / `-macos`, `firefox-148-windows` / `-linux` / `-macos`, and `firefox-latest-windows` / `-linux` / `-macos`.

The per-OS variants differ from their base in the User-Agent only. Firefox does not bake OS into the rest of its fingerprint the way Chrome does, so the TLS bytes, the HTTP/2 settings and the header order are identical across all three. They exist so you can pin Firefox-on-Windows from a Linux host without hand-overriding the User-Agent; the plain `firefox-148` still follows the host OS. No h3 yet; Firefox has its own h3 quirks we haven't built out.

### Safari

| Preset | Notes |
|---|---|
| `safari-18` (`safari-latest`) | Desktop macOS Safari 18, supports h3 |
| `safari-17-ios` (`ios-safari-17`) | iPhone Safari 17, h2 only |
| `safari-18-ios` (`ios-safari-18`, `safari-latest-ios`) | iPhone Safari 18, supports h3 |

Safari sets `NoRFC7540Priorities=true`, so it never emits the H2 PRIORITY frame, and RFC 9218 priority headers carry the signal instead. That's the single biggest tell that splits a Safari fingerprint from a Chrome one at the H2 layer, even though both ALPN as h2.

### Backwards-compat aliases

The older `<os>-<browser>-<version>` naming still works for code written against earlier docs:

```
ios-chrome-152        → chrome-152-ios
ios-safari-18         → safari-18-ios
android-chrome-152    → chrome-152-android
```

Both forms resolve to the same preset for version-pinned names. The `-latest` back-compat spellings are the exception and are frozen: `android-chrome-latest` still resolves to `chrome-148-android` and `ios-chrome-latest` to `chrome-148-ios`, while `chrome-latest-android` and `chrome-latest-ios` both track 152. Prefer the `chrome-latest-*` spelling.

## Inheritance: how a new Chrome version ships in 30 seconds

Each Chrome minor bump is usually pure UA plus sec-ch-ua delta. TLS fingerprint, H2 SETTINGS, header order, priority table, all the same as the version before. Chrome 148 isn't a from-scratch Go file; it's a JSON delta over Chrome 147:

```json
{
  "version": 1,
  "preset": {
    "name": "chrome-152-windows",
    "based_on": "chrome-152-windows",
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

That's the whole patch. TLS bytes come from chrome-147-windows, which itself inherits TLS bytes from chrome-146-windows since nothing changed in 147. H2 SETTINGS, priority table, everything else, all inherited.

The same path is open to you. Pick a preset, dump it, change three fields, register the result. See [JSON Preset Builder](./json-preset-builder).

## Verification

Hit `tls.peet.ws/api/all` with each preset and you'll see the matching JA4 / Akamai hash:

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
    for _, name := range []string{"chrome-latest", "android-chrome-152", "firefox-148", "safari-18-ios"} {
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

for name in ["chrome-latest", "android-chrome-152", "firefox-148", "safari-18-ios"]:
    with httpcloak.Session(preset=name) as s:
        r = s.get("https://tls.peet.ws/api/all")
        print(name, r.json())
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
const { Session } = require("httpcloak");

for (const name of ["chrome-latest", "android-chrome-152", "firefox-148", "safari-18-ios"]) {
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

foreach (var name in new[] { "chrome-latest", "android-chrome-152", "firefox-148", "safari-18-ios" }) {
    using var s = new Session(preset: name);
    var r = await s.GetAsync("https://tls.peet.ws/api/all");
    Console.WriteLine($"{name} {r.Text}");
}
```

</TabItem>
</Tabs>

Captured fingerprints (re-measured 2026-08):

```text
chrome-latest        ja4=t13d1517h2_8daaf6152771_cb7bf5808d99  peetprint_hash=fc97c1cdfb1409c9a9326c1b726d1dee  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
chrome-152-windows   ja4=t13d1517h2_8daaf6152771_cb7bf5808d99  peetprint_hash=fc97c1cdfb1409c9a9326c1b726d1dee  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
chrome-151-windows   ja4=t13d1516h2_8daaf6152771_806a8c22fdea  peetprint_hash=67c3e9111bed9e7f03d2f21d6d88994b  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
chrome-150-windows   ja4=t13d1516h2_8daaf6152771_806a8c22fdea  peetprint_hash=67c3e9111bed9e7f03d2f21d6d88994b  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
chrome-148-windows   ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd  peetprint_hash=1d4ffe9b0e34acac0bd883fa7f79d7b5  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
chrome-148-linux     ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd  peetprint_hash=1d4ffe9b0e34acac0bd883fa7f79d7b5  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
chrome-148-macos     ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd  peetprint_hash=1d4ffe9b0e34acac0bd883fa7f79d7b5  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
android-chrome-148   ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd  peetprint_hash=1d4ffe9b0e34acac0bd883fa7f79d7b5  akamai_fingerprint_hash=52d84b11737d980aef856699f885ca86
firefox-148          ja4=t13d1717h2_5b57614c22b0_3cbfd9057e0d  peetprint_hash=89d89662b21018947a9a46658c4f5ede  akamai_fingerprint_hash=6ea73faa8fc5aac76bded7bd238f6433
safari-18            ja4=t13d2013h2_a09f3c656075_7f0f34a4126d  peetprint_hash=62b834de729e78a9f0ebd1dd099314a7  akamai_fingerprint_hash=90d8353e47699c4c38ecd773e9b5a089
safari-18-ios        ja4=t13d2013h2_a09f3c656075_7f0f34a4126d  peetprint_hash=62b834de729e78a9f0ebd1dd099314a7  akamai_fingerprint_hash=90d8353e47699c4c38ecd773e9b5a089
chrome-148-ios       ja4=t13d2013h2_a09f3c656075_7f0f34a4126d  peetprint_hash=62b834de729e78a9f0ebd1dd099314a7  akamai_fingerprint_hash=c52879e43202aeb92740be6e8c86ea96
chrome-152-ios       ja4=t13d2013h2_a09f3c656075_7f0f34a4126d  peetprint_hash=62b834de729e78a9f0ebd1dd099314a7  akamai_fingerprint_hash=c52879e43202aeb92740be6e8c86ea96
```

:::note Chrome 152 has no single JA4

Chrome 152 puts a greased value at the head of `signature_algorithms`, drawn fresh
per handshake. The JA4 specification says to ignore greased values wherever they
appear, and implementations differ on whether they do it in the signature list.
One that strips them reports the stable `cb7bf5808d99` above; one that does not
reports a different tail on every connection, sixteen in all. Real Chrome 152
behaves exactly the same way, so a tail that moves is the profile working, not
failing. Compare on the parts before it, or on a tool you know strips greased
values everywhere.

:::


Things to spot:

- Every Chrome desktop variant lands on the same JA4 / peetprint / akamai. The TLS handshake is identical across Windows / Linux / macOS Chrome. Only the User-Agent and `sec-ch-ua-platform` header tell you which OS you're on.
- Android Chrome shares the same fingerprint as desktop Chrome. Same TLS, same H2. The wire-level difference is the UA string (Mobile Safari/537.36) and `sec-ch-ua-mobile: ?1`.
- Chrome on iOS shows up as Safari at the wire level, since iOS WebKit forces every browser onto the system networking stack. `chrome-152-ios` shares its TLS handshake and JA4 hash with `safari-18-ios`. They split only on H2 SETTINGS values (chrome-152-ios advertises `2,3,4,9` vs Safari's `2,4,3,5,9`) and the User-Agent.
- Firefox and Safari each get their own JA4 / peetprint / akamai. Different cipher list, different SETTINGS, different pseudo-header order.

:::tip
The bare `ja3_hash` field won't be stable for Chrome presets across runs. Chrome shuffles its TLS extension order on every connection, so the raw JA3 string changes and the MD5 changes with it. JA4 sorts the extension list before hashing, which is why it's stable. Always verify against `ja4` and `peetprint_hash`, never `ja3_hash`.
:::

## Full preset catalog

94 preset names total (counting -latest aliases and the old `<os>-<browser>` naming). For the exhaustive table with version numbers, supported protocols, and platform tags, see the [Presets reference](../reference/presets).
