---
title: Build Custom Chrome From tls.peet.ws
sidebar_position: 2
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Build Custom Chrome From tls.peet.ws

The shipped presets cover the Chrome versions httpcloak builds against directly. When the target wants a slightly different Chrome version, the recipe is to capture one from a real browser, convert it into JSON, and register it as a custom preset. The whole flow takes about ten minutes.

:::tip
This recipe is the path when a target expects a Chrome major that is not on the shipped list. Capture from real Chrome, edit the JSON, register the preset, no library release needed.
:::

## When to use this

This is the right tool when:

- A target site checks `User-Agent` against a specific Chrome major and the shipped `chrome-latest` is a version or two off.
- You want to reproduce a specific user's setup (Linux Chrome 145, macOS Chrome 147, etc.).
- You are debugging a fingerprint mismatch and want a side-by-side comparison of what real Chrome sends versus what the preset puts on the wire.

It is not the right tool for browsers httpcloak has not profiled at the TLS layer. JSON edits cover headers, User-Agent, and sec-ch-ua. They do not cover TLS extension order or new extensions, since those live in the utls profile. For that path, see [Custom JA3](../fingerprinting/custom-ja3).

## The flow

1. Open Chrome (the version you want to clone). Visit `https://tls.peet.ws/api/all`.
2. Save the response JSON.
3. Run `describe_preset("chrome-latest")` to dump the shipped preset to JSON.
4. Diff the two. The deltas usually land in the UA string, the sec-ch-ua brand list, and sometimes accept-language.
5. Edit the preset JSON to match the capture.
6. Load it with `load_preset_from_json` under a fresh name.
7. Hit tls.peet again with the new preset. Verify JA4, peetprint, and akamai hash all match the original capture.

## Step 1: Capture from real Chrome

Open Chrome, navigate to `https://tls.peet.ws/api/all`, save the JSON. On Linux with Chrome installed, this works from the command line:

```bash
google-chrome --headless --dump-dom https://tls.peet.ws/api/all > capture.json
```

The fields we care about (full response is much bigger):

```json
{
  "http_version": "h2",
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
  "tls": {
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-11-43-23-18-0-27-65281-45-16-5-17613-10-35-65037-13,4588-29-23-24,0",
    "ja3_hash": "f33ef28649dda9a281b02e75670c8139",
    "ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd",
    "peetprint_hash": "1d4ffe9b0e34acac0bd883fa7f79d7b5"
  },
  "http2": {
    "akamai_fingerprint": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    "akamai_fingerprint_hash": "52d84b11737d980aef856699f885ca86",
    "sent_frames": [
      {
        "frame_type": "HEADERS",
        "headers": [
          ":method: GET",
          ":authority: tls.peet.ws",
          ":scheme: https",
          ":path: /api/all",
          "sec-ch-ua: \"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\"",
          "sec-ch-ua-mobile: ?0",
          "sec-ch-ua-platform: \"Linux\"",
          "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
          "accept: text/html,...",
          "..."
        ]
      }
    ]
  }
}
```

Two pieces are worth pulling out:

1. `user_agent`, the exact Chrome version string. The major number and platform are both meaningful here.
2. `sec-ch-ua`, the brand-version list. This rotates with each Chrome major, and a stale value is a classic giveaway.

:::tip
DevTools shows the headers your code constructs, not the headers Chrome puts on the wire. The `sent_frames[].headers` block in the tls.peet response is the ground truth, since it captures the bytes after the network stack has finished with them.
:::

## Step 2: Describe the shipped preset

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
    "fmt"
    "os"

    "github.com/sardanioss/httpcloak/fingerprint"
)

func main() {
    j, err := fingerprint.Describe("chrome-latest")
    if err != nil {
        fmt.Println(err); os.Exit(1)
    }
    os.WriteFile("chrome-latest.json", []byte(j), 0644)
    fmt.Printf("wrote %d bytes\n", len(j))
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

j = httpcloak.describe_preset("chrome-latest")
with open("chrome-latest.json", "w") as f:
    f.write(j)
print(f"wrote {len(j)} bytes")
```

</TabItem>
</Tabs>

`Describe` returns the whole preset fully resolved, with no inheritance and no defaults to track down later. The output looks roughly like this:

```json
{
  "version": 1,
  "preset": {
    "name": "chrome-148-linux",
    "tls": {
      "client_hello": "chrome-146-linux",
      "psk_client_hello": "chrome-146-linux-psk",
      "quic_client_hello": "chrome-146-quic",
      "quic_psk_client_hello": "chrome-146-quic-psk"
    },
    "http2": {
      "header_table_size": 65536,
      "initial_window_size": 6291456,
      "max_header_list_size": 262144,
      "settings_order": [1, 2, 4, 6],
      "pseudo_order": [":method", ":authority", ":scheme", ":path"],
      "stream_priority_mode": "chrome",
      "priority_table": { "...": "..." }
    },
    "headers": {
      "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
      "values": {
        "sec-ch-ua": "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Linux\"",
        "Accept-Language": "en-US,en;q=0.9"
      },
      "order": [
        {"key": "sec-ch-ua", "value": "..."},
        {"key": "sec-ch-ua-mobile", "value": "..."},
        {"key": "sec-ch-ua-platform", "value": "..."},
        {"key": "upgrade-insecure-requests", "value": "1"},
        {"key": "user-agent", "value": "..."},
        {"key": "accept", "value": "..."}
      ]
    }
  }
}
```

## Step 3: Diff the capture vs the preset

Three fields usually drift between Chrome majors:

| Field | Where in capture | Where in preset |
|-------|------------------|-----------------|
| User-Agent | `user_agent` top-level | `headers.user_agent` |
| sec-ch-ua brand list | inside `sent_frames[].headers` | `headers.values."sec-ch-ua"` |
| sec-ch-ua-platform | same | `headers.values."sec-ch-ua-platform"` |

Two other places worth checking:

- `accept-language`. The default varies with Chrome locale.
- TLS extensions. If the capture's JA3 lists an extension the shipped preset doesn't have, a JSON edit won't fix it. The fix is a utls profile update. See [What is TLS fingerprinting](../fingerprinting/what-is-tls-fingerprinting).

In the example above both capture and shipped preset are Chrome 148 on Linux, so the deltas are minimal. For a capture from Chrome 150 on macOS, the edits would look like this:

:::danger Do not derive `sec-ch-ua` from the version number

Copy this value from a real capture. It cannot be worked out from the version.
Chrome regenerates its brand list per major version, and between 150 and 151 the
separator characters, the filler brand's version and the ORDER of the three
brands all changed at once:

```
150: "Not;A=Brand";v="8",  "Chromium";v="150", "Google Chrome";v="150"
151: "Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"
```

A guessed value is wrong in a way that is trivially checkable by anyone reading
the header, which defeats the point of the profile.

:::

```json
"user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",

"headers": {
  "values": {
    "sec-ch-ua": "\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\"",
    "sec-ch-ua-platform": "\"macOS\""
  }
}
```

## Step 4: Edit and rename

Always rename the preset before registering. `fingerprint.RegisterStrict(name, *Preset)` errors on any name collision, both with built-ins (`chrome-latest`, `chrome-148`, etc.) and with previously registered customs, so overwriting a shipped preset is rejected at registration time. The plain `fingerprint.Register` is the silent-overwrite path; the embedded preset loader uses `Register`, while the public JSON loaders push through `RegisterStrict`.

```json
{
  "version": 1,
  "preset": {
    "name": "chrome-148-linux-mine",
    "...": "everything else, edited as needed"
  }
}
```

## Step 5: Load + register

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
    "fmt"
    "os"

    "github.com/sardanioss/httpcloak/fingerprint"
)

func main() {
    data, err := os.ReadFile("chrome-148-linux-mine.json")
    if err != nil { fmt.Println(err); os.Exit(1) }

    p, err := fingerprint.LoadAndBuildPresetFromJSON(data)
    if err != nil { fmt.Println("build:", err); os.Exit(1) }

    if err := fingerprint.RegisterStrict("chrome-148-linux-mine", p); err != nil {
        fmt.Println("register:", err); os.Exit(1)
    }
    fmt.Println("registered chrome-148-linux-mine")
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with open("chrome-148-linux-mine.json") as f:
    name = httpcloak.load_preset_from_json(f.read())
print(f"registered {name}")
```

</TabItem>
</Tabs>

## Step 6: Verify the round-trip

This is the step that proves the rewrite worked. Send a fresh request through tls.peet using the new preset and compare the hashes against the original capture.

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "time"

    "github.com/sardanioss/httpcloak"
)

type peet struct {
    HTTPV string `json:"http_version"`
    UA    string `json:"user_agent"`
    TLS   struct {
        Ja4      string `json:"ja4"`
        PeetHash string `json:"peetprint_hash"`
    } `json:"tls"`
    HTTP2 struct {
        AkamaiHash string `json:"akamai_fingerprint_hash"`
    } `json:"http2"`
}

func capture(preset string) peet {
    s := httpcloak.NewSession(preset, httpcloak.WithSessionTimeout(30*time.Second))
    defer s.Close()
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    r, _ := s.Get(ctx, "https://tls.peet.ws/api/all")
    defer r.Close()
    b, _ := r.Bytes()
    var p peet
    json.Unmarshal(b, &p)
    return p
}

func main() {
    base := capture("chrome-latest")
    mine := capture("chrome-148-linux-mine")

    fmt.Printf("ja4   base=%s mine=%s match=%v\n", base.TLS.Ja4, mine.TLS.Ja4, base.TLS.Ja4 == mine.TLS.Ja4)
    fmt.Printf("peet  base=%s mine=%s match=%v\n", base.TLS.PeetHash, mine.TLS.PeetHash, base.TLS.PeetHash == mine.TLS.PeetHash)
    fmt.Printf("akama base=%s mine=%s match=%v\n", base.HTTP2.AkamaiHash, mine.HTTP2.AkamaiHash, base.HTTP2.AkamaiHash == mine.HTTP2.AkamaiHash)
    fmt.Printf("ua    base=%s\n        mine=%s\n", base.UA, mine.UA)

    if base.TLS.Ja4 != mine.TLS.Ja4 || base.TLS.PeetHash != mine.TLS.PeetHash || base.HTTP2.AkamaiHash != mine.HTTP2.AkamaiHash {
        os.Exit(1)
    }
    fmt.Println("PASS")
}
```

A clean run prints `PASS`. Sample output from running this recipe against the live tls.peet endpoint:

```
ja4   base=t13d1516h2_8daaf6152771_d8a2da3f94cd mine=t13d1516h2_8daaf6152771_d8a2da3f94cd match=true
peet  base=1d4ffe9b0e34acac0bd883fa7f79d7b5 mine=1d4ffe9b0e34acac0bd883fa7f79d7b5 match=true
akama base=52d84b11737d980aef856699f885ca86 mine=52d84b11737d980aef856699f885ca86 match=true
PASS
```

## Why JA3 might differ

Two captures from the same preset will produce different JA3 hashes. JA3 hashes the raw TLS extension IDs, and Chrome rotates GREASE values on every connection, so the same preset emits different JA3s every time. JA3 is unstable by design.

JA4, peetprint, and the akamai HTTP/2 hash all normalise GREASE before hashing. Those are the metrics that answer "did my preset round-trip correctly". A JA4 and peetprint match is a clean round-trip even when JA3 differs.

:::warning
Don't use JA3 hash equality as a CI pass criterion. It will flake. Use JA4 instead.
:::

## What this recipe doesn't cover

- **TLS extension order changes.** When a new Chrome major adds an extension or reshuffles the order, JSON edits cannot reach into the ClientHello. The fix is a utls profile bump.
- **HTTP/2 frame ordering.** The shipped presets cover the common Chrome shapes. A frame shape the shipped preset does not have is worth an issue, not a JSON workaround.
- **HTTP/3.** Same constraint as the TLS layer. The shipped `quic_client_hello` profiles define the QUIC handshake bytes; JSON only edits headers.

The path for any of those is a utls and sardanioss/net update, not a custom JSON preset.

## Related

- [JSON Preset Builder](../fingerprinting/json-preset-builder), full JSON
  schema reference
- [Presets](../fingerprinting/presets), what we ship
- [Custom JA3](../fingerprinting/custom-ja3), bypassing the preset system
- [Akamai Shorthand](../fingerprinting/akamai-shorthand), HTTP/2 fingerprint
  format
