---
title: Custom JA3
sidebar_position: 5
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Custom JA3

`WithCustomFingerprint` accepts a raw JA3 string and rebuilds the TLS ClientHello from it on every connection. The preset still drives HTTP/2 SETTINGS, headers, and the priority table, so only the TLS layer changes.

## When to use this

Reach for `WithCustomFingerprint` (JA3 only) when:

- You captured a JA3 from a real browser session and want to mirror that ClientHello exactly.
- You're testing what JA3 hashes look like for a given cipher / extension / curve permutation.
- TLS is the only layer you care about, since the preset's headers and H2 are fine.

Reach for the [JSON Preset Builder](./json-preset-builder) instead when:

- You need to tweak HTTP/2 SETTINGS along with the JA3.
- You want to change the User-Agent, sec-ch-ua list, or any other HTTP header.
- You want the change saved as a named preset for reuse.

JA3 is a one-liner. The JSON builder is a few more, and it's worth it the moment you need anything beyond TLS.

## JA3 string format

```
TLSVersion,CipherSuites,Extensions,EllipticCurves,PointFormats
```

Five comma-separated lists. Inside each list, values are dash-separated decimal IDs. Chrome 148 example:

```
771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
```

- `771`: TLS 1.2 protocol field. Everything modern advertises TLS 1.2 here and then upgrades to 1.3 inside extensions.
- `4865-4866-...`: cipher suite IDs (`TLS_AES_128_GCM_SHA256` is 4865, and so on).
- `0-23-65281-...`: TLS extension IDs (0=server_name, 23=session_ticket, 65281=renegotiation_info, etc). Order matters for the JA3 hash, but real Chrome shuffles this list per connection.
- `29-23-24`: supported groups / curves (29=x25519, 23=secp256r1, 24=secp384r1).
- `0`: EC point formats (0=uncompressed).

:::caution
DevTools won't show you what TLS extensions Chrome put on the wire, and the order it does show is misleading since Chrome shuffles per connection. Capture from `tls.peet.ws` or a passive observer for the wire-level truth.
:::

## API

`CustomFingerprint` carries the JA3 plus a few uTLS-level extras. Setting `JA3` flips the session into TLS-only mode automatically. Preset HTTP headers stop being applied, and you supply your own per request.

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
            JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
            // optional uTLS extras:
            ALPN:                []string{"h2", "http/1.1"},
            SignatureAlgorithms: []string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"},
            CertCompression:     []string{"brotli"},
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
    ja3="771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    extra_fp={
        "tls_alpn":                 ["h2", "http/1.1"],
        "tls_signature_algorithms": ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"],
        "tls_cert_compression":     ["brotli"],
    },
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
  ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
  extraFp: {
    tls_alpn:                 ["h2", "http/1.1"],
    tls_signature_algorithms: ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"],
    tls_cert_compression:     ["brotli"],
  },
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
    ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    extraFp: new Dictionary<string, object> {
        ["tls_alpn"]                 = new[] { "h2", "http/1.1" },
        ["tls_signature_algorithms"] = new[] { "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256" },
        ["tls_cert_compression"]     = new[] { "brotli" },
    });

var r = await s.GetAsync("https://tls.peet.ws/api/all");
Console.WriteLine(r.Text);
```

</TabItem>
</Tabs>

## Verification

Send the request, read the response, and check `tls.ja3` and `tls.ja3_hash`. They mirror your input exactly:

```text
INPUT JA3:        771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
INPUT akamai:     1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p

OUTPUT ja3:        771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
OUTPUT ja3_hash:   cd08e31494f9531f560d64c695473da9
OUTPUT ja4:        t13d1516h2_8daaf6152771_f37e75b10bcc
OUTPUT akamai:     1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
OUTPUT akamai_hash: 52d84b11737d980aef856699f885ca86
```

The reflected `ja3` is byte-identical to the input. `ja3_hash` is a stable MD5 of that string and stays stable across runs, unlike preset Chrome where extensions shuffle. `ja4` differs from the underlying `chrome-148-windows` (`d8a2da3f94cd` vs `f37e75b10bcc`) because we used a different extension list. That's expected, and it confirms the override took effect.

## TLS-only mode is automatic

Setting `JA3` flips the session into TLS-only mode. The preset's HTTP headers go away, the preset's `User-Agent` goes away, and every header is yours to set per request:

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
req := &httpcloak.Request{
    Method: "GET",
    URL:    "https://tls.peet.ws/api/all",
    Headers: map[string][]string{
        "User-Agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"},
        "Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        "Accept-Language": {"en-US,en;q=0.9"},
    },
}
resp, _ := s.Do(context.Background(), req)
```

</TabItem>
<TabItem value="python" label="Python">

```python
r = s.get(
    "https://tls.peet.ws/api/all",
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    },
)
```

</TabItem>
</Tabs>

For JA3 override **and** preset headers in the same session, use the JSON Preset Builder. Describe the preset, override `tls.ja3` in the JSON, leave `headers` alone, register, send.

## Limitations

- JA3 is deprecated for a reason. Modern anti-bot stacks key on JA4 / peetprint / akamai. Mirroring a Chrome JA3 while inheriting Chrome's H2 SETTINGS gets you the right JA4 / peetprint / akamai too, which is the case shown above. When your JA3 says one browser and your H2 says another, the result is inconsistent and easy to flag.
- Setting `JA3` clears the preset's `client_hello` ID. The session rebuilds a ClientHello from the JA3 on every connection. uTLS handles it, but the result is lossy compared to a real browser ClientHelloID. JA3 doesn't capture extension data like ALPS, key share groups, or application-settings, so the resulting handshake is close to real Chrome but not identical. For byte-exact Chrome bytes, use a preset.
- The `extras` (ALPN, SignatureAlgorithms, CertCompression, PermuteExtensions) are uTLS-specific knobs that ride alongside the JA3. They don't show up inside the JA3 string itself, but they do hit the wire.

## Programmatic parsing

The JA3 parser the lib uses internally is exported, useful for tools that validate JA3 strings before plugging them into a session, or that need a `*tls.ClientHelloSpec` for a custom transport without going through `WithCustomFingerprint`:

```go
import "github.com/sardanioss/httpcloak/fingerprint"

spec, err := fingerprint.ParseJA3(
    "771,4865-4866-...,0-23-65281-...,29-23-24,0",
    nil, // optional *JA3Extras to layer ALPN / sigalgs / cert-compression on top
)
if err != nil {
    // bad JA3 shape (wrong field count, malformed integers, unknown cipher / extension)
}

// quick presence check without a full parse
hasGREASE := fingerprint.JA3HasExtension(ja3, "27")
```

`ParseJA3` returns a uTLS `ClientHelloSpec` that any uTLS-aware code path can use directly. `JA3HasExtension` is a fast `string`-level check for "does this JA3 list extension X" without building the full spec. Both return well-typed errors on malformed input rather than panicking.
