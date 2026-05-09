---
title: Domain Fronting
sidebar_position: 5
---

# Domain Fronting

Domain fronting is the technique where the SNI in your TLS handshake
points at one host (call it host A, the "front") and the `Host:`
header inside the encrypted HTTP request points at another host
(host B, the "real target"). The CDN edge sees host A in the
ClientHello, terminates TLS, then routes the inner request based on
the Host header to host B's backend.

The historical use cases:

- Reaching a CDN-fronted service when host A is on a non-blocked
  domain and host B is the actual target.
- Censorship circumvention. Block host B at the network layer, and
  the SNI for host A still goes through cleanly.
- Internal routing where the public DNS for B doesn't exist but B
  is reachable as a virtual host on A's edge.

:::warning
Domain fronting is a deeply CDN-specific feature. Cloudflare blocks
it, AWS CloudFront blocks it, Fastly blocks it on most plans. Some
Azure Front Door and GCP Load Balancer setups still allow it. Read
your CDN provider's policy before relying on this for production.
:::

## Two related primitives in httpcloak

httpcloak gives you two things that look similar but solve different
problems.

### `WithConnectTo(requestHost, connectHost)`, IP-level rerouting

This maps a request hostname to a different TCP-connect target. The
TLS SNI and the Host header both stay as `requestHost`. Only the IP
the lib dials changes.

Think of it as the equivalent of curl's `--resolve` flag, or
manually editing `/etc/hosts`. You're saying "when I ask for host A,
open the TCP socket to host B's IP, but otherwise pretend nothing
changed". Useful for hitting a specific CDN edge node, testing a
new origin, or pinning to a known-good IP.

### Per-request `Host` header, classic SNI != Host fronting

For real domain fronting (SNI=A, Host=B), set the `Host` header
explicitly on the request. The URL you pass determines the TCP dial
target and the SNI. The Host header you set determines what the CDN
edge sees inside the decrypted HTTP request.

Both can be combined. For example, dial to a specific CDN IP via
`WithConnectTo`, terminate TLS with SNI = a "safe" front domain,
and send `Host: real-target.example.com` in the encrypted request.

## Classic fronting setup

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
    "context"
    "fmt"

    "github.com/sardanioss/httpcloak"
)

func main() {
    s := httpcloak.NewSession("chrome-latest")
    defer s.Close()

    // URL.Host = front-domain.example.com  -> TCP dial + TLS SNI = front-domain.example.com
    // Host header = real-target.example.com -> what the CDN routes by, after decrypting TLS
    req := &httpcloak.Request{
        Method: "GET",
        URL:    "https://front-domain.example.com/",
        Headers: map[string][]string{
            "Host": {"real-target.example.com"},
        },
    }
    resp, err := s.Do(context.Background(), req)
    if err != nil {
        panic(err)
    }
    body, _ := resp.Bytes()
    fmt.Println(resp.StatusCode, len(body))
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-latest") as s:
    r = s.get(
        "https://front-domain.example.com/",
        headers={"Host": "real-target.example.com"},
    )
    print(r.status_code, len(r.body))
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
const { Session } = require('httpcloak');

const s = new Session({ preset: 'chrome-latest' });
const r = await s.get('https://front-domain.example.com/', {
  headers: { Host: 'real-target.example.com' },
});
console.log(r.statusCode, r.body.length);
s.close();
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-latest");
var r = await s.GetAsync(
    "https://front-domain.example.com/",
    headers: new() { { "Host", "real-target.example.com" } });
Console.WriteLine($"{r.StatusCode} {r.Body.Length}");
```

</TabItem>
</Tabs>

What goes on the wire:

- TCP open to `front-domain.example.com`
- ClientHello with SNI = `front-domain.example.com`
- Encrypted HTTP/2 frame with `:authority: real-target.example.com`
  (or `Host: real-target.example.com` for HTTP/1.1)
- CDN routes to the real-target backend if its config allows it.

## IP-level rerouting (the WithConnectTo path)

Different goal, sometimes confused. `WithConnectTo` pins the TCP
target while keeping SNI and Host the same as the request URL.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
s := httpcloak.NewSession("chrome-latest",
    // Asking for example.com, but actually open the socket to example.org's IP.
    // SNI stays "example.com", Host header stays "example.com".
    httpcloak.WithConnectTo("example.com", "example.org"),
)
defer s.Close()

resp, _ := s.Get(context.Background(), "https://example.com/")
fmt.Println(resp.StatusCode)
```

</TabItem>
<TabItem value="python" label="Python">

```python
with httpcloak.Session(
    preset="chrome-latest",
    connect_to={"example.com": "example.org"},
) as s:
    r = s.get("https://example.com/")
    print(r.status_code)
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
const s = new Session({
  preset: 'chrome-latest',
  connectTo: { 'example.com': 'example.org' },
});
const r = await s.get('https://example.com/');
console.log(r.statusCode);
s.close();
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using var s = new Session(
    preset: "chrome-latest",
    connectTo: new Dictionary<string, string> {
        { "example.com", "example.org" }
    });
var r = await s.GetAsync("https://example.com/");
Console.WriteLine(r.StatusCode);
```

</TabItem>
</Tabs>

This will only succeed if the IP you're connecting to actually
serves a cert matching the SNI in the handshake. With most public
sites, dialing example.org's IP and asking for SNI = example.com
will trip cert validation. It works when the front and the target
share a wildcard cert or a SAN list.

## What works on which CDN

Reality as of recent testing:

- **Cloudflare**: classic SNI != Host fronting blocked at the edge.
  The edge checks SNI against the Host header and rejects mismatches.
  ECH-aware fronting via the Cloudflare ECH endpoint is a different
  beast and does work, see [ECH](./ech) and `WithECHFrom`.
- **AWS CloudFront**: blocked since 2018. The edge requires SNI
  match.
- **Fastly**: blocked on most public plans. Some enterprise SKUs
  permit it.
- **Azure Front Door**: SNI != Host still works on standard tiers
  in many regions. Verify with your tenant.
- **GCP HTTPS LB / Cloud CDN**: works on classic load balancers in
  some configs. The newer global LBs are stricter.
- **Older / smaller CDN-like setups (Akamai aside)**: case by case.
  Test before you assume.

If your front and target are different services on the *same*
origin (one ALB, one set of certs, multiple vhosts), fronting works
out of the box because there's no edge inspection layer to reject
the mismatch. This is the most reliable use case today.

## When fronting fails

You'll see one of:

- TLS handshake error: cert doesn't cover the front SNI on the
  edge node you reached.
- 421 Misdirected Request: the edge accepted TLS but rejected the
  Host header because the connection wasn't authorized for that
  vhost.
- 403 / 421 from the CDN with a vendor-specific error page: most
  CDNs that block fronting return an explicit error.
- Empty 200 with a "blocked by security policy" body: rare, mostly
  on enterprise CDN tiers with deep inspection.

If you hit any of these, the CDN is enforcing SNI=Host. There is no
client-side trick to get around it; the block is at the edge.

## ECH as a modern alternative

ECH (covered in [ECH](./ech)) is the spec-blessed successor to
domain fronting. Instead of hoping a CDN doesn't check, ECH wraps
the inner ClientHello (and therefore the inner SNI) in a second
encrypted handshake. The outer SNI is the ECH provider's name, the
real target is invisible to the network. CDN providers explicitly
support this, so it doesn't break their AUP.

If your goal is "hide the SNI from middleboxes", reach for ECH. If
your goal is "reach a backend the network thinks I shouldn't",
domain fronting is the older, riskier, increasingly rare path.
