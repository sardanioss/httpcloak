---
title: TLS Keylog
sidebar_position: 4
---

# TLS Keylog

Sometimes you genuinely need to see what's on the wire and not what
the lib *thinks* it sent. Wireshark is your friend, but TLS-encrypted
traffic in a capture is just noise unless you have the keys to
decrypt it. The standard trick across Chrome, curl, and httpcloak is
to dump TLS keys to a file in `SSLKEYLOGFILE` format, then point
Wireshark at that file. Wireshark uses the keys to decrypt the
session live in the UI.

`WithKeyLogFile(path)` opens the named file in append mode and feeds
every TLS handshake's per-connection secrets into it. Each new
handshake adds a few lines to the file. The format is simple, ASCII,
one secret per line.

## Format

Each line is space-separated:

```
<label> <client_random_hex> <secret_hex>
```

The label tells Wireshark which secret this is. For TLS 1.3 you'll
see (per connection):

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
CLIENT_TRAFFIC_SECRET_0         <client_random> <secret>
SERVER_TRAFFIC_SECRET_0         <client_random> <secret>
EXPORTER_SECRET                 <client_random> <secret>
```

For TLS 1.2 connections, you get one line:

```
CLIENT_RANDOM <client_random> <master_secret>
```

`<client_random>` is 64 hex chars (32 bytes), `<secret>` is 64 or 96
hex chars depending on the cipher suite. Wireshark matches lines to
captured connections by the client_random field.

## Setup

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/sardanioss/httpcloak"
)

func main() {
    keylog := "/tmp/httpcloak-keys.txt"
    _ = os.Remove(keylog) // start fresh

    s := httpcloak.NewSession("chrome-latest",
        httpcloak.WithKeyLogFile(keylog),
    )
    defer s.Close()

    resp, err := s.Get(context.Background(), "https://example.com/")
    if err != nil {
        panic(err)
    }
    fmt.Println("status:", resp.StatusCode)

    data, _ := os.ReadFile(keylog)
    fmt.Printf("keylog (%d bytes):\n%s", len(data), string(data))
}
```

Run it and you'll see something like:

```
status: 200
keylog (632 bytes):
CLIENT_HANDSHAKE_TRAFFIC_SECRET 2bb1...4f SERVER_HANDSHAKE_TRAFFIC_SECRET ...
CLIENT_TRAFFIC_SECRET_0 ...
SERVER_TRAFFIC_SECRET_0 ...
```

</TabItem>
</Tabs>

(Bindings get the same keylog support via the equivalent
`key_log_file` / `keyLogFile` option, but the workflow is identical.
The Go example above is the canonical one for Wireshark debugging.)

## Pointing Wireshark at the file

1. Edit > Preferences > Protocols > TLS.
2. Find the field `(Pre)-Master-Secret log filename`.
3. Browse to the path you passed to `WithKeyLogFile`.
4. Click OK.

Wireshark will watch the file. New lines appended while a capture is
open get picked up live. If you start a capture, run a request that
writes a new key, then look at the TLS stream in Wireshark, you'll
see a "Decrypted TLS" tab on the packet detail showing plaintext
HTTP/2 frames or the H1 request line.

For H3 (QUIC), the same keys are written but the Wireshark setting
to enable is QUIC TLS Decryption. As of Wireshark 4.x, pointing the
TLS keylog at your file is enough, QUIC inherits from it.

## Override priority

`WithKeyLogFile` overrides the global `SSLKEYLOGFILE` environment
variable for that specific session. If both are set, the explicit
path wins. If only the env var is set, all sessions write to it.
You can have one session keylogging while another doesn't, just by
toggling the option per session.

## Per-session vs global

| Setup                                | Behavior                                |
| :----------------------------------- | :-------------------------------------- |
| `SSLKEYLOGFILE=/tmp/k.log` env var   | Every session writes there              |
| `WithKeyLogFile("/tmp/s1.log")` only | Only that session writes, others silent |
| Both set                             | The explicit option wins for that session |
| Neither set                          | No keylog                               |

## When you actually need this

- Verifying ECH actually fired. Decrypt the inner ClientHello and
  inspect the `encrypted_client_hello` extension.
- Checking that header order on the wire matches what you set.
  Chrome being a lil bitch won't show you header order, you can
  check tls.peet.ws/api/all for it, but if you want byte-level
  proof from your own request, decrypt the capture.
- Debugging a server's H2 frame layout when something doesn't add
  up. Wireshark's HTTP/2 dissector is genuinely good and will tell
  you which frame the server sent in what order.
- Reproducing a Chromium DevTools-style waterfall but with raw
  bytes underneath. Useful for benchmarking and for proving
  correctness of a custom fingerprint.

## When you don't need this

- The far more common case is "the server's response is wrong, why".
  For that, just print the response headers and body. Keylogging is
  for when the disagreement is below the HTTP layer.
- Production. Don't ship `WithKeyLogFile` enabled into production.
  The file contains material that lets anyone with read access
  decrypt your live traffic. If you log to disk, log to a path
  that's tightly permissioned and rotated.

## Related recipes

For a step-by-step Wireshark walkthrough including capture filters
and TLS decryption setup, see [Debugging with
Wireshark](/recipes/debug-with-wireshark).
