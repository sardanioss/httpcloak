---
title: Custom JA3
sidebar_position: 5
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Custom JA3

`WithCustomFingerprint` accepts a raw JA3 string. The preset still picks the HTTP/2 SETTINGS, headers, and priority table, but the TLS ClientHello is rebuilt from the JA3 every connection.

## When to use this

Use `WithCustomFingerprint` (JA3 only) when:

- You captured a JA3 from a real browser session and want to mirror exactly that ClientHello.
- You're testing what JA3 hashes look like for a given cipher / extension / curve permutation.
- You only care about the TLS layer; the preset's headers and H2 are fine.

Use the [JSON Preset Builder](./json-preset-builder) instead when:

- You need to tweak HTTP/2 SETTINGS along with the JA3.
- You want to change the User-Agent, sec-ch-ua list, or any other HTTP header.
- You want the change saved as a named preset for reuse.

The JA3 path is one line of code. The JSON builder is a few more, but worth it as soon as you need anything beyond TLS.

## JA3 string format

```
TLSVersion,CipherSuites,Extensions,EllipticCurves,PointFormats
```

Five comma-separated lists. Inside each list, values are dash-separated decimal IDs. Example for Chrome 148:

```
771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
```

- `771`: TLS 1.2 protocol field (everything modern uses TLS 1.2 advertised, then upgrades to 1.3 inside extensions).
- `4865-4866-...`: cipher suite IDs (`TLS_AES_128_GCM_SHA256` is 4865, etc).
- `0-23-65281-...`: TLS extension IDs (0=server_name, 23=session_ticket, 65281=renegotiation_info, ...). The order here matters for the JA3 hash but real Chrome shuffles this list per connection.
- `29-23-24`: supported groups / curves (29=x25519, 23=secp256r1, 24=secp384r1).
- `0`: EC point formats (0=uncompressed).

:::caution
Chrome being a lil bitch won't show you header order, you can check tls.peet.ws/api/all for it. Same applies to TLS extensions: the live JA3 you see in DevTools won't match what hits the wire because Chrome shuffles. Capture from `tls.peet.ws` or a passive observer, not from devtools.
:::

## API

`CustomFingerprint` carries the JA3 plus a few uTLS-level extras. Setting `JA3` automatically enables TLS-only mode, preset HTTP headers won't be applied, you supply your own per request.

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
    preset="chrome-148-windows",
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
  preset: "chrome-148-windows",
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
    preset: "chrome-148-windows",
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

Send the request, read the response, look at `tls.ja3` and `tls.ja3_hash`. They should mirror the input exactly:

```text
INPUT JA3:        771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
INPUT akamai:     1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p

OUTPUT ja3:        771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
OUTPUT ja3_hash:   cd08e31494f9531f560d64c695473da9
OUTPUT ja4:        t13d1516h2_8daaf6152771_f37e75b10bcc
OUTPUT akamai:     1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
OUTPUT akamai_hash: 52d84b11737d980aef856699f885ca86
```

The `ja3` reflected back is byte-identical to the input. `ja3_hash` is a stable MD5 of that string, so it's stable across runs (unlike preset Chrome where extensions shuffle). `ja4` differs from the underlying `chrome-148-windows` (`d8a2da3f94cd` vs `f37e75b10bcc`) because we used a different extension list, that's expected and shows our override took effect.

## TLS-only mode is automatic

When you set `JA3`, httpcloak switches the session into TLS-only mode. The preset's HTTP headers are dropped, the preset's `User-Agent` is dropped, and you have to set everything per-request:

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

If you want JA3 override **and** preset headers, use the JSON Preset Builder approach instead. Describe the preset, override `tls.ja3` in the JSON, leave `headers` alone, register, send.

## Limitations

- JA3 is deprecated for a reason. Modern anti-bot stacks key on JA4 / peetprint / akamai. Mirroring a Chrome JA3 string but inheriting Chrome's H2 SETTINGS gets you the right JA4 / peetprint / akamai too: that's the case shown above. But if your JA3 says one browser and your H2 says another, you're inconsistent and detectable.
- Setting `JA3` clears the preset's `client_hello` ID. The session will rebuild a ClientHello from the JA3 string every connection. uTLS handles this: it's lossy compared to a real browser ClientHelloID (the JA3 doesn't capture extension data like ALPS, key share groups, application-settings) so the resulting handshake is close-but-not-identical to a real Chrome handshake. For full byte-exact Chrome bytes, use a preset.
- The `extras` (ALPN, SignatureAlgorithms, CertCompression, PermuteExtensions) are uTLS-specific knobs that supplement the JA3. They don't appear in the JA3 string itself but they do appear on the wire.
