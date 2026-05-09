---
title: What is TLS Fingerprinting
sidebar_position: 2
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# What is TLS Fingerprinting

A TLS fingerprint is just the shape of your TLS handshake on the wire. The ClientHello is a packed, ordered message: cipher list, extension list, supported groups, signature algorithms, all laid out in a specific sequence. Different clients pick different orders, so their ClientHellos look different byte-for-byte. Hash the bytes and you've got a fingerprint.

Anti-bot vendors keep an allowlist of known-browser hashes. Match one, you pass. Don't match, you're flagged. That's basically the whole game.

The same trick applies at the H2 layer. Once the handshake's done, the connection opens with a SETTINGS frame, a WINDOW_UPDATE, sometimes PRIORITY frames, and a fixed pseudo-header order on your first request. Every browser does this a little differently, so the H2 layer hashes too.

## The fingerprint formats you'll meet

### JA3

The OG. MD5 over five comma-separated lists pulled from the ClientHello:

```
TLSVersion,CipherSuites,Extensions,EllipticCurves,PointFormats
```

Chrome 148 example:

```
771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-17613-18-23-27-35-43-45-51-65037-65281,29-23-24,0
```

JA3 is basically dead. Modern Chrome shuffles its TLS extension order on every single connection, so the raw JA3 string and the `ja3_hash` change every time even though the actual browser version hasn't moved. Most defenders dropped JA3 ages ago. Don't waste energy matching it.

### JA4

The replacement everyone uses now. Compound and way more granular:

```
t13d1516h2_8daaf6152771_d8a2da3f94cd
```

Decoding:

- `t13`: TLS 1.3
- `d`: TCP (`q` if you're on QUIC)
- `1516`: 15 ciphers, 16 extensions
- `h2`: ALPN h2
- middle hash: sorted cipher suites
- last hash: sorted extensions and sig algs

JA4 sorts extensions before hashing, which kills Chrome's shuffle problem. This is the one you actually want to verify against.

### Akamai HTTP/2 hash

A separate fingerprint, one layer up. Hashes a tiny string with four parts:

```
SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
```

Chrome 148 looks like:

```
1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

That string captures the initial window size, the header table size, the connection-level window update, and the order Chrome sends `:method`, `:authority`, `:scheme`, `:path` in. Chrome and Safari ship a different pseudo-header order. Firefox lays out SETTINGS differently. All of it lands in one akamai hash, so a single value tells you a lot.

## Why default Go gets blocked

`net/http` builds its ClientHello with Go's standard `crypto/tls`. Cipher list, extensions, supported curves, all bog-standard Go defaults. No real browser produces that handshake. The JA4 hash for default Go matches zero browsers, anywhere.

So the bot vendor blocks by exclusion. Hash isn't on the allowlist, request is presumed bot, you eat a 403. Simple.

This is also why cranking `curl --tls-cipher` to reorder ciphers won't save you. Chrome isn't just sending a different cipher list. It's sending a different extension order, a different curve list, different sig algs, different ALPN, different cert compression. The whole packet is different. Reproducing all of that end-to-end is what httpcloak exists to do.

httpcloak puts ClientHello bytes on the wire that are byte-identical to a real Chrome / Firefox / Safari handshake. H2 SETTINGS, WINDOW_UPDATE, pseudo-header order all match. So does the order of regular HTTP headers Chrome sends on the first request, because Chrome being a lil bitch won't show you that order in DevTools, you can check `tls.peet.ws/api/all` for it.

## See for yourself

Hit `tls.peet.ws/api/all` with the `chrome-latest` preset and look at the JA4:

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
    s := httpcloak.NewSession("chrome-latest")
    defer s.Close()

    resp, err := s.Get(context.Background(), "https://tls.peet.ws/api/all")
    if err != nil { panic(err) }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-latest") as s:
    r = s.get("https://tls.peet.ws/api/all")
    print(r.text)
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
const { Session } = require("httpcloak");

const s = new Session({ preset: "chrome-latest" });
const r = await s.get("https://tls.peet.ws/api/all");
console.log(r.text);
s.close();
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-latest");
var r = await s.GetAsync("https://tls.peet.ws/api/all");
Console.WriteLine(r.Text);
```

</TabItem>
</Tabs>

What comes back (Chrome 148, captured 2026-05):

```text
ja4:                     t13d1516h2_8daaf6152771_d8a2da3f94cd
peetprint_hash:          1d4ffe9b0e34acac0bd883fa7f79d7b5
akamai_fingerprint_hash: 52d84b11737d980aef856699f885ca86
```

Those three match real Chrome 148 desktop. Run the same code through `net/http` and you'd see something like `t13d1517h2_acb858a92679_eb4d4c4c4f4f` for JA4, which matches no browser that ever shipped.

Heads up: `ja3_hash` won't be stable across runs because of Chrome's extension shuffle. `ja4` and `peetprint_hash` are stable. Verify against those two.

:::info
`tls.peet.ws/api/all` is the workhorse. It reflects everything back: TLS, H2, headers, and the order each piece arrived in. `cf.erika.cool` and `browserleaks.com` are useful when you specifically want to see what Cloudflare's edge sees. All three are safe to test against, no C&D risk.
:::

## What's next in this section

- [Presets](./presets): the bundled Chrome / Firefox / Safari profiles you can pick by name.
- [JSON Preset Builder](./json-preset-builder): dump a preset to JSON, mutate it, load it back as a new preset. The customization path you'll actually use.
- [Custom JA3](./custom-ja3): when you only want to override the JA3 string, this is the lightweight one.
- [Akamai Shorthand](./akamai-shorthand): same idea but for the H2 fingerprint.
- [Per-Resource Priority](./per-resource-priority): RFC 7540 stream weights and RFC 9218 priority headers driven by `Sec-Fetch-Dest`.
