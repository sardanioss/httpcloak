---
title: Presets Explained
sidebar_position: 3
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Presets Explained

A preset is the bundle of wire-level fingerprint data for one specific browser build. Calling `NewSession("chrome-152-windows")` loads all of this in one go:

- The TLS ClientHello: cipher list, extension order, supported groups, ALPN, signature algorithms, key shares, GREASE positions, ECH config.
- HTTP/2 SETTINGS frame values, the WINDOW_UPDATE delta, PRIORITY frame defaults, and the pseudo-header order on every request.
- Default request headers in the order Chrome sends them: `sec-ch-ua`, `accept`, `sec-fetch-*`, the rest.
- Per-resource priority (RFC 7540 stream weights for H2, RFC 9218 `priority` headers for H2/H3), keyed off `sec-fetch-dest`.
- For HTTP/3: QUIC initial parameters and the H3 SETTINGS frame Chrome ships with.

TLS and headers don't get picked separately. You pick a browser and a build, and the whole bundle moves together. That's the only way it stays self-consistent. A Chrome 148 ClientHello paired with Firefox header order looks broken to any serious fingerprinter.

## How to pick one

`chrome-latest` is the safe default. It tracks the newest shipped Chrome. For a specific OS variant (some sites gate on `sec-ch-ua-platform`), use `chrome-latest-windows`, `chrome-latest-linux`, `chrome-latest-macos`, `chrome-latest-android`, or `chrome-latest-ios`.

To pin a specific build, name it directly. If a target is blocking Chrome 148 and Chrome 144 still gets through, use `chrome-144-windows`.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
// Default desktop Chrome, OS picked by the latest alias map
sess := httpcloak.NewSession("chrome-latest")

// Mobile UA + matching TLS for a phone-shaped fingerprint
mobile := httpcloak.NewSession("chrome-152-android")

// Pinned to an older build
old := httpcloak.NewSession("chrome-144-windows")
```

</TabItem>
<TabItem value="python" label="Python">

```python
session = httpcloak.Session(preset="chrome-latest")
mobile  = httpcloak.Session(preset="chrome-152-android")
old     = httpcloak.Session(preset="chrome-144-windows")
```

</TabItem>
<TabItem value="node" label="Node.js">

```javascript
const session = new Session({ preset: "chrome-latest" });
const mobile  = new Session({ preset: "chrome-152-android" });
const old     = new Session({ preset: "chrome-144-windows" });
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using var session = new Session(preset: "chrome-latest");
using var mobile  = new Session(preset: "chrome-152-android");
using var old     = new Session(preset: "chrome-144-windows");
```

</TabItem>
</Tabs>

## What's available

Each preset family ships per-OS variants where the underlying browser differs by OS. Chrome differs across Windows, Linux, macOS, Android, and iOS (iOS Chrome is WebKit underneath, a different stack entirely). Firefox barely differs across desktop OSes, so there's a single desktop build.

**Chrome desktop**: 133, 141, 143, 144, 145, 146, 147, 148. The 143-148 line ships per-OS variants (`chrome-152-windows`, `chrome-152-linux`, `chrome-152-macos`); bare `chrome-152` aliases to whatever OS the library defaults to. The older 133 and 141 builds are desktop-only single presets without per-OS suffixes.

**Chrome mobile**: `chrome-143-android` through `chrome-152-android`, and `chrome-143-ios` through `chrome-152-ios`. Mobile Chrome has its own UA, its own sec-ch-ua values, and on iOS a completely different TLS stack (WebKit, again).

**Firefox**: 133 and 148 desktop. No per-OS split.

**Safari**: `safari-18` desktop, `safari-17-ios`, `safari-18-ios`.

**Latest aliases**: `chrome-latest`, `chrome-latest-windows`, `chrome-latest-linux`, `chrome-latest-macos`, `chrome-latest-android`, `chrome-latest-ios`, `firefox-latest`, `safari-latest`, `safari-latest-ios`. These re-point to the newest shipped major on every release. Use them when an exact build pin doesn't matter.

For the full list with protocol support per preset, see [Reference: Presets](/reference/presets).

## Inheritance: the `based_on` chain

Presets aren't standalone JSON blobs. They form a chain. Open `fingerprint/embedded/chrome-152-windows.json` and the file looks something like this:

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
      }
    }
  }
}
```

That's the whole file. Chrome 148 windows is "Chrome 147 windows with the UA and sec-ch-ua bumped to 148". TLS settings, H2 settings, header order, priority table, all inherited verbatim.

This is deliberate. Chrome rarely changes its TLS or H2 wire format between minor versions. Most of what's new in a point release is JS engine and rendering, not network. A wire-level delta only ships when the wire moves (cipher reordering, a new extension, a SETTINGS bump). Everything else is a UA bump on top of the `based_on` chain.

The chain bottoms out at a root preset that carries the full TLS and H2 spec. Loading `chrome-152-windows` walks the chain at startup and merges layer by layer.

To inspect the resolved bundle after the merge, there's a describe API. From Go: `fingerprint.Describe("chrome-152-windows")`. From Python: `httpcloak.describe_preset("chrome-152-windows")`.

## Building your own

A custom preset is a JSON file in your app, registered with httpcloak at startup. Useful when you've captured a real browser session and want to ship that exact fingerprint without hand-editing Go code.

The shape matches the embedded files. `based_on` is optional: point it at any registered preset to inherit, or omit it and supply the full TLS+H2 spec yourself.

See [JSON Preset Builder](/fingerprinting/json-preset-builder) for the full schema and a worked example.

## Where to next

- [Reference: Presets](/reference/presets) for the full table of protocol and OS support per preset.
- [What is TLS Fingerprinting](/fingerprinting/what-is-tls-fingerprinting) for context on why these wire bytes matter.
- [Custom JA3](/fingerprinting/custom-ja3) for overriding individual TLS bits without rebuilding a whole preset.
