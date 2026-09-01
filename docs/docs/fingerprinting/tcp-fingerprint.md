---
title: TCP Fingerprint
sidebar_position: 8
---

# TCP Fingerprint

TCP/IP fingerprinting is the bottom-of-the-stack inspection that vendors run on the very first packet your client sends. Before TLS, before HTTP, before any cookie or header reaches the server, the SYN packet has already declared a TTL, an MSS, an initial window size, a window scale, and a DF bit. Those five numbers carry enough signal to call the operating system the packet came from, often with embarrassing precision.

`WithTCPFingerprint(fp fingerprint.TCPFingerprint)` rewrites those values via `setsockopt` on the raw socket before `connect()` fires. The TLS layer above it still does its own work (uTLS handshake, real Chrome cipher list, extension order, supported groups). What this option fixes is the layer underneath: the OS-level shape of the SYN that arrives on the target's edge router.

Built-in Chrome, Firefox, and Safari presets ship with a zero-value `TCPFingerprint{}`. That's a deliberate choice. A zero TTL means the dialer control function returns `nil`, so the kernel default takes over and nothing is overridden. Opt in by passing `WithTCPFingerprint(...)` on the session, and the values you provide replace the per-field defaults the preset would otherwise use.

## The struct

```go
type TCPFingerprint struct {
    TTL         int  // IP Time-To-Live
    MSS         int  // TCP Maximum Segment Size
    WindowSize  int  // TCP Window Size in SYN
    WindowScale int  // TCP Window Scale option
    DFBit       bool // IP Don't Fragment flag
}
```

Each field maps to a passive observation a vendor can make from one captured SYN. The TTL field is the one most often used to call the bluff on a mismatched preset. Linux ships SYNs with TTL 64. Windows ships them with TTL 128. By the time a packet from a Linux box reaches the target's edge, a few hops have decremented the TTL into the 50s. A Windows box's TTL arrives in the 110-120 range. The hop-count math is mechanical, and a Linux server that gets a packet with arrival TTL 55 and a `User-Agent` claiming `Windows NT 10.0` knows something is off.

| Field | Windows 10/11 | Linux | macOS | Why it matters |
| --- | --- | --- | --- | --- |
| `TTL` | `128` | `64` | `64` | Hop-count math identifies the source OS family. |
| `MSS` | `1460` | `1460` | `1460` | Standard Ethernet MSS is the same across platforms; deviations stand out. |
| `WindowSize` | `64240` | `65535` | `65535` | Windows 10/11 advertises a slightly smaller initial window than Unix. |
| `WindowScale` | `8` | `7` | `6` | Each OS family picks a stable scale exponent. iOS/Android inherit from their kernels. |
| `DFBit` | `true` | `true` | `true` | Don't-Fragment is set on every modern client. Unset DF on a SYN is itself a tell. |

## Platform helpers

The fingerprint package ships four constructors that return ready-to-use values:

```go
fingerprint.WindowsTCPFingerprint() // {TTL:128, MSS:1460, WindowSize:64240, WindowScale:8, DFBit:true}
fingerprint.LinuxTCPFingerprint()   // {TTL:64,  MSS:1460, WindowSize:65535, WindowScale:7, DFBit:true}
fingerprint.MacOSTCPFingerprint()   // {TTL:64,  MSS:1460, WindowSize:65535, WindowScale:6, DFBit:true}
fingerprint.PlatformTCPFingerprint(platform string)
```

`PlatformTCPFingerprint` takes one of `"Windows"`, `"macOS"`, or anything else (which falls through to Linux). The platform string is the capitalised form, not `runtime.GOOS`. The helper paired with it lives one struct over: `fingerprint.GetPlatformInfo().Platform` returns exactly the value `PlatformTCPFingerprint` expects. Together they're the right pair when the preset itself is platform-aware:

```go
fp := fingerprint.PlatformTCPFingerprint(fingerprint.GetPlatformInfo().Platform)
```

Passing `runtime.GOOS` directly does NOT work; `runtime.GOOS` returns `"linux"` / `"windows"` / `"darwin"` (lowercase), none of which match the switch arms, so every host falls through to the Linux case.

Pass any of these into `WithTCPFingerprint` and the dialer control callback wired into every fresh socket will set the matching `setsockopt` calls before connect.

## Wiring it into a session

A Chrome-on-Windows preset paired with the Windows TCP fingerprint gives a coherent picture from layer 3 all the way up to the User-Agent string:

```go
package main

import (
    "context"
    "fmt"
    "io"

    "github.com/sardanioss/httpcloak"
    "github.com/sardanioss/httpcloak/fingerprint"
)

func main() {
    s := httpcloak.NewSession("chrome-latest",
        httpcloak.WithTCPFingerprint(fingerprint.WindowsTCPFingerprint()),
    )
    defer s.Close()

    r, err := s.Get(context.Background(), "https://tls.peet.ws/api/all")
    if err != nil { panic(err) }
    defer r.Close()

    body, _ := io.ReadAll(r.Body)
    fmt.Println(string(body))
}
```

The `tls.peet.ws/api/all` response carries a `tcp_ip` block alongside the `tls` block. After running this, the `tcp_ip.ttl` value should land at `128` (or near it, after a few hops), `tcp_ip.win` at `64240`, and `tcp_ip.win_scale` at `8`. Without `WithTCPFingerprint`, those values would reflect whatever the host kernel decided to put on the wire, which on a Linux scraping box means TTL 64 and scale 7 going out under a User-Agent claiming Windows.

## Per-platform support

The `setsockopt` surface differs by OS, so the same `TCPFingerprint` struct produces different on-the-wire results depending on where the binary runs.

| OS | TTL | MSS | Window size | DF bit | Notes |
| --- | --- | --- | --- | --- | --- |
| Linux | `IP_TTL` | `TCP_MAXSEG` | `SO_RCVBUF` + `TCP_WINDOW_CLAMP` | `IP_MTU_DISCOVER=PMTUDISC_DO` | Kernel doubles `SO_RCVBUF`, so the code requests half the target value. `TCP_WINDOW_CLAMP` constrains the advertised window so the scale factor in the SYN matches. |
| macOS | `IP_TTL` | `TCP_MAXSEG` | `SO_RCVBUF` (no doubling) | `IP_DONTFRAG` (option 28) | No `TCP_WINDOW_CLAMP` equivalent on Darwin, so window scale is what the BSD stack picks. |
| Windows | `IP_TTL` | not reliably settable | `SO_RCVBUF` | `IP_DONTFRAGMENT` (option 14) | `TCP_MAXSEG` doesn't survive Winsock; the field is accepted but the syscall is skipped. |
| Other (BSD, Solaris, Plan 9) | no-op | no-op | no-op | no-op | `tcpip_other.go` returns `nil` for every fingerprint apply call. The option compiles and runs, it just doesn't change the SYN. |

The build-tagged files (`tcpip_linux.go`, `tcpip_darwin.go`, `tcpip_windows.go`, `tcpip_other.go`) carry the per-platform `applyTCPFingerprint` implementations. The dispatcher in `tcpip.go` is identical everywhere; only the side-effects differ.

A Linux scraper sending a Windows fingerprint gets the closest match a non-Windows kernel can produce. The `IP_TTL` change is real, the `TCP_MAXSEG` change is real, the window clamp is real. What a Linux box can't fully replicate is the BSD-vs-Windows difference in TCP option ordering inside the SYN, which some advanced detectors do parse. For most vendor pipelines, the field-level values are what gets compared, and those land where you set them.

## When the option does nothing

A few quiet failure modes keep the option from changing the wire even when the call looks correct. Worth knowing about before you spend an evening packet-capturing.

The first is the zero-TTL short-circuit. `BuildDialerControl` returns `nil` if `fp.TTL == 0`, so a struct with every other field set but TTL left at zero installs no control function and applies nothing. Always set TTL.

The second is the Linux `rmem_max` clamp. `SO_RCVBUF` is bounded by `/proc/sys/net/core/rmem_max`. If that ceiling is below the requested value, the kernel silently caps the receive buffer, and the SYN's advertised window comes out smaller than the configured value. Read the cap with `sysctl net.core.rmem_max` and lift it if needed: `sysctl -w net.core.rmem_max=8388608`.

The third is the platform delta. Setting `WindowScale = 8` on macOS or Windows in the struct doesn't directly drive the SYN scale option, because neither stack exposes a clean knob for the scale exponent. The field still gets stored on the preset for completeness, and any future platform that gains support for it picks it up automatically. For now, the scale exponent on macOS and Windows is whatever the kernel computes from the buffer size and its own internal heuristics.

The fourth is QUIC. The TCP fingerprint applies to TCP sockets, which means H1 and H2 paths only. H3/QUIC traffic rides UDP, which has no TTL/window/MSS at the TCP layer. UDP sockets do still get IP-layer options, and a future release may set `IP_TTL` on QUIC sockets too; right now, an H3-only request from a Linux host carries the kernel default UDP TTL of 64 regardless of `WithTCPFingerprint`.

## Pairing with the right preset

Coherence is the thing to keep in mind. A `chrome-152-windows` preset claiming `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)` paired with a Linux TCP fingerprint is a layer-3-vs-layer-7 mismatch. The TLS handshake might be perfect, the headers might be authentic Chrome, the cookie order might be flawless. None of that survives a `tcp_ip.ttl=64` arriving with a Windows User-Agent.

How to stay coherent depends on which preset you pick:

- `*-windows` presets (`chrome-152-windows`, `chrome-152-windows`, etc) pair with `WindowsTCPFingerprint()`.
- `*-macos` presets pair with `MacOSTCPFingerprint()`.
- `*-linux` presets pair with `LinuxTCPFingerprint()`.
- Bare `chrome-latest` and `chrome-152` (no platform suffix) auto-detect the running OS at runtime via `GetPlatformInfo`, so on a Linux build host `chrome-latest` resolves to `chrome-152-linux`. Pair these with `PlatformTCPFingerprint(fingerprint.GetPlatformInfo().Platform)` to track whichever variant the registry hands you.
- Custom presets need the call to match whatever User-Agent string you set on the preset.

For session pools that span multiple personas, pre-build the fingerprint once and reuse it:

```go
winFP := fingerprint.WindowsTCPFingerprint()
macFP := fingerprint.MacOSTCPFingerprint()

chromeWin := httpcloak.NewSession("chrome-152-windows", httpcloak.WithTCPFingerprint(winFP))
chromeMac := httpcloak.NewSession("chrome-152-macos",   httpcloak.WithTCPFingerprint(macFP))
```

## What you can verify

`tls.peet.ws/api/all` returns a `tcp_ip` object in its JSON response. The fields line up directly with the struct fields:

```bash
curl -s https://tls.peet.ws/api/all | jq .tcp_ip
```

Expected snippet after a Windows-fingerprinted session has hit it:

```json
{
  "ttl": 120,
  "mss": 1460,
  "win": 64240,
  "win_scale": 8,
  "df": true
}
```

The arrival `ttl` won't be exactly `128` because it gets decremented by every router along the path. A starting TTL of 128 typically arrives in the 110-125 range from a North American or European source. The `win` and `win_scale` fields are observed straight off the SYN options, so those should match the configured values exactly. A `ttl` arriving at 50-something with `win:64240` would be a giveaway: the window value is Windows but the hop math says the source is Unix-like.

For a side-by-side compare without `WithTCPFingerprint`, run the same code with the option commented out. The `ttl` lands in the low 50s on a Linux host (starting from 64), `win` at `65535`, `win_scale` at `7`. That's the kernel default leaking through, and it's what every other Go HTTP client puts on the wire.

A more controlled way to verify is `tcpdump` on the source host. Capture the SYN that goes out on port 443 and read the IP and TCP header values directly:

```bash
sudo tcpdump -i any -nn -X 'tcp[tcpflags] & tcp-syn != 0 and dst port 443' -c 1
```

The output shows the source TTL (before any router decrements it), the MSS option, and the window value. A Windows-fingerprinted packet leaving a Linux box shows TTL 128, MSS 1460, and window 64240 right at the source, which is the proof that `setsockopt` actually took effect. The peet.ws JSON shows arrival values; `tcpdump` shows departure values. Both agree on the configured fingerprint when the wiring is correct.

For continuous-integration verification, a small Go test that checks the SYN against a known-good map per platform catches accidental drift if the dialer control function ever stops being installed:

```go
func TestTTLOnSYN(t *testing.T) {
    s := httpcloak.NewSession("chrome-latest",
        httpcloak.WithTCPFingerprint(fingerprint.WindowsTCPFingerprint()))
    defer s.Close()

    r, err := s.Get(context.Background(), "https://tls.peet.ws/api/all")
    if err != nil { t.Fatal(err) }
    defer r.Close()

    var parsed struct {
        TCPIP struct {
            TTL int `json:"ttl"`
            Win int `json:"win"`
        } `json:"tcp_ip"`
    }
    json.NewDecoder(r.Body).Decode(&parsed)
    if parsed.TCPIP.TTL < 100 {
        t.Errorf("TTL=%d, expected near 128 (Windows)", parsed.TCPIP.TTL)
    }
    if parsed.TCPIP.Win != 64240 {
        t.Errorf("win=%d, expected 64240 (Windows)", parsed.TCPIP.Win)
    }
}
```

## Bindings

All three bindings expose the TCP fingerprint fields on the `Session` constructor at runtime. The Node.js TypeScript declarations don't yet surface them, so TS callers either bypass the typings with a cast or extend their local `.d.ts` until the upstream typings are updated. Plain JavaScript works as written.

| Binding | Exposed kwargs / parameters |
| --- | --- |
| Python | `tcp_ttl`, `tcp_mss`, `tcp_window_size`, `tcp_window_scale`, `tcp_df` |
| Node.js | `tcpTtl`, `tcpMss`, `tcpWindowSize`, `tcpWindowScale`, `tcpDf` (runtime; missing from `.d.ts`) |
| .NET | `tcpTtl`, `tcpMss`, `tcpWindowSize`, `tcpWindowScale`, `tcpDf` |

```python
import httpcloak

with httpcloak.Session(
    preset="chrome-latest",
    tcp_ttl=128,
    tcp_mss=1460,
    tcp_window_size=64240,
    tcp_window_scale=8,
    tcp_df=True,
) as s:
    r = s.get("https://tls.peet.ws/api/all")
    print(r.json()["tcp_ip"])
```

```csharp
using HttpCloak;

using var s = new Session(
    preset: "chrome-latest",
    tcpTtl: 128,
    tcpMss: 1460,
    tcpWindowSize: 64240,
    tcpWindowScale: 8,
    tcpDf: true);

var r = s.Get("https://tls.peet.ws/api/all");
Console.WriteLine(r.Text);
```

```js
const { Session } = require("httpcloak");

// Plain JS: pass the kwargs as-is.
const s = new Session({
    preset: "chrome-latest",
    tcpTtl: 128,
    tcpMss: 1460,
    tcpWindowSize: 64240,
    tcpWindowScale: 8,
    tcpDf: true,
});

// TypeScript: bypass typings until the .d.ts is updated.
// const s = new Session({ preset: "chrome-latest", ...({ tcpTtl: 128 } as any) });
```

For arbitrary clients (curl, third-party SDKs, anything outside these three bindings), the cross-language workaround is `LocalProxy` with a registered session. A `LocalProxy` instance running in Go applies the registered session's TCP fingerprint to every outbound connection that session handles, and any client pointing at the proxy gets the right TCP shape on the wire to the actual target. See [Local Proxy Server](/recipes/local-proxy-server) for the full pattern including the session registry and per-request session selection header.
