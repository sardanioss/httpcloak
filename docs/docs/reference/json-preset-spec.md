---
title: JSON Preset Spec
sidebar_position: 3
---

# JSON Preset Spec

The canonical JSON schema for presets. This is the contract for any preset built programmatically or shipped as a file.

Source of truth: `fingerprint/custom_preset.go`, where `PresetSpec` and the surrounding types are defined. The schema is round-trip stable. `fingerprint.Describe(name)` produces JSON that `fingerprint.LoadPresetFromJSON` parses back into an identical preset.

:::note
JSON doesn't allow comments. The `// ...` annotations in the snippets below are docs only. Strip them before handing the JSON to the parser.
:::

---

## Top-level shape

The outer document carries a schema version and either a single preset or a pool.

```json
{
  "version": 1,
  "preset": { ... },
  "pool":   { ... }
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `version` | int | yes | Schema version. Currently `1`. |
| `preset` | object | one of `preset` / `pool` | Single preset definition. |
| `pool` | object | one of `preset` / `pool` | A pool of presets for round-robin or random rotation. |

Exactly one of `preset` or `pool` has to be set.

### Pool shape

Pools wrap a list of preset definitions plus a rotation strategy. The runtime picks one preset per session.

```json
{
  "version": 1,
  "pool": {
    "name": "my-rotation",
    "strategy": "random",       // or "round-robin"
    "presets": [
      { "name": "...", ... },
      { "name": "...", ... }
    ]
  }
}
```

---

## `preset` object

The full set of fields a single preset can declare. Each section corresponds to one layer of the wire fingerprint.

```json
{
  "name":     "my-chrome",          // required, unique
  "based_on": "chrome-148-windows", // optional, parent preset name
  "tls":      { ... },              // TLS fingerprint
  "http2":    { ... },              // HTTP/2 fingerprint
  "http3":    { ... },              // HTTP/3 + QUIC fingerprint
  "headers":  { ... },              // user-agent, header values, header order
  "tcp":      { ... },              // TCP/IP fingerprint
  "protocols":{ ... }               // protocol support flags
}
```

| Field | Type | Notes |
|---|---|---|
| `name` | string | The registry name. Used by `NewSession(name)`. |
| `based_on` | string | Parent preset. Inherits everything; this preset's fields overlay. Inheritance loops are detected at build time (looped chains return an error). |
| `tls` | object | See [TLS section](#tls-object). |
| `http2` | object | See [HTTP/2 section](#http2-object). |
| `http3` | object | See [HTTP/3 section](#http3-object). |
| `headers` | object | See [Headers section](#headers-object). |
| `tcp` | object | See [TCP section](#tcp-object). |
| `protocols` | object | See [Protocols section](#protocols-object). |

Omit a field and it inherits from `based_on`. With no parent, the field stays at its zero value.

---

## `tls` object

The TLS layer. Two configuration modes that don't mix: a named uTLS ClientHello (`client_hello`) or a raw JA3 string. The named mode covers Chrome, Firefox, Safari, and iOS variants tracked in uTLS; JA3 mode is for anything outside that set.

```json
"tls": {
  "client_hello":      "chrome-148-windows",       // mutually exclusive with ja3
  "psk_client_hello":  "chrome-148-windows-psk",
  "quic_client_hello": "chrome-148-quic",
  "quic_psk_client_hello": "chrome-148-quic-psk",

  "ja3":        "771,4865-...,0-23-...,29-23-24,0",
  "ja3_extras": { ... },

  "signature_algorithms":            [1027, 2052, 1025],
  "delegated_credential_algorithms": [1027, 2052],
  "alpn":               ["h2", "http/1.1"],
  "cert_compression":   ["brotli", "zlib", "zstd"],
  "permute_extensions": true,
  "record_size_limit":  16385,
  "key_share_curves":   1
}
```

| Field | Type | Notes |
|---|---|---|
| `client_hello` | string | uTLS ClientHello ID name (e.g. `"chrome-146-windows"`). Mutually exclusive with `ja3`. |
| `psk_client_hello` | string | PSK variant for TLS session resumption. Requires `client_hello` (directly or via `based_on`). |
| `quic_client_hello` | string | QUIC-specific ClientHello. Cannot be used with `ja3`. |
| `quic_psk_client_hello` | string | QUIC PSK variant. |
| `ja3` | string | Full JA3: `Version,Ciphers,Extensions,Curves,Formats`. Setting this clears any inherited `client_hello`. |
| `ja3_extras` | object | JA3-mode extras: sig-algs, ALPN, cert compression, etc. Only valid when `ja3` is set. |
| `signature_algorithms` | uint16[] | Signature-algorithm override for TCP (HTTP/1.1 and HTTP/2). Replaces the extension on top of whatever base the ClientHello produces, so it works with `based_on` and no `ja3`, which is exactly how the shipped Chrome 150/151 profiles add their post-quantum entries. Inherited by presets that derive from this one. |
| `quic_signature_algorithms` | uint16[] | The HTTP/3 counterpart. Separate because a browser's QUIC list can differ from its TCP one: Chrome 150 and 151 send post-quantum signature algorithms over TCP but not over QUIC. Leave unset to inherit the base. |
| `delegated_credential_algorithms` | uint16[] | Top-level shortcut. JA3 mode only. |
| `alpn` | string[] | ALPN protocol list. Default `["h2", "http/1.1"]`. JA3 mode only. |
| `cert_compression` | string[] | One or more of `"brotli"`, `"zlib"`, `"zstd"`. JA3 mode only. |
| `permute_extensions` | bool | When true, extension order shuffles per handshake (Chrome 110+ behaviour). |
| `record_size_limit` | uint16 | TLS extension 28 value. |
| `key_share_curves` | int | Number of curves to advertise key shares for. `1` for Chrome (X25519MLKEM768 only), `3` for Firefox. |

### `ja3_extras` shape

The same fields as the top-level shortcuts, nested under one object. Use this form when you want the JA3 string and its extras kept together as a single block.

```json
"ja3_extras": {
  "signature_algorithms":            [1027, 2052, ...],
  "delegated_credential_algorithms": [1027, 2052, ...],
  "alpn":               ["h2", "http/1.1"],
  "cert_compression":   ["brotli"],
  "permute_extensions": true,
  "record_size_limit":  16385,
  "key_share_curves":   1
}
```

### TLS validation rules

The build step rejects the following combinations:

- `ja3` and `client_hello` set in the same spec.
- `ja3_extras` without `ja3`.
- Any of `psk_client_hello`, `quic_client_hello`, `quic_psk_client_hello` when there's no primary `client_hello` or `ja3` to anchor them.
- `quic_client_hello` / `quic_psk_client_hello` / `psk_client_hello` paired with `ja3` (JA3 doesn't control QUIC TLS, use `client_hello` mode for QUIC).
- TLS extension fields (`signature_algorithms`, `alpn`, `cert_compression`, `permute_extensions`, `record_size_limit`) when `client_hello` is set without `ja3` (those fields only apply to JA3).

---

## `http2` object

The HTTP/2 layer. Covers SETTINGS values and order, WINDOW_UPDATE size, pseudo-header order, HPACK indexing, and the per-resource priority table.

```json
"http2": {
  "akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",

  "header_table_size":        65536,
  "enable_push":              false,
  "max_concurrent_streams":   0,
  "initial_window_size":      6291456,
  "max_frame_size":           0,
  "max_header_list_size":     262144,
  "connection_window_update": 15663105,
  "stream_weight":            256,
  "stream_exclusive":         true,
  "no_rfc7540_priorities":    false,

  "settings":       [{"id": 1, "value": 65536}, ...],
  "settings_order": [1, 2, 4, 6],
  "pseudo_order":   ["m", "a", "s", "p"],

  "hpack_header_order":   ["sec-ch-ua", "user-agent", ...],
  "hpack_indexing_policy":"chrome",
  "hpack_never_index":    ["cookie", "authorization"],
  "stream_priority_mode": "chrome",
  "disable_cookie_split": false,

  "priority_table": {
    "document": { "urgency": 0, "incremental": false, "emit_header": true },
    "image":    { "urgency": 5, "incremental": true,  "emit_header": true }
  }
}
```

### Akamai shorthand

`akamai` is a one-line shorthand for the four parts of an Akamai HTTP/2 fingerprint: `SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_ORDER`. The parser splits it and applies each part to the corresponding fields.

When both `akamai` and individual fields are set, resolution runs in this order:

1. Apply individual fields (`header_table_size`, `enable_push`, etc.) for any slots the akamai shorthand does **not** touch.
2. Apply `akamai` authoritatively for the slots it explicitly names.
3. Apply `settings` (the structured `[{id, value}]` list) last. Overrides both.

So with `akamai: "1:65536"` and `header_table_size: 99999`, the akamai value wins for slot 1. Slots the akamai string doesn't name (like `max_concurrent_streams`) take the individual value.

### Settings IDs

The numeric IDs HTTP/2 uses in `SETTINGS` frames.

| ID | Setting |
|---|---|
| 1 | `HEADER_TABLE_SIZE` |
| 2 | `ENABLE_PUSH` |
| 3 | `MAX_CONCURRENT_STREAMS` |
| 4 | `INITIAL_WINDOW_SIZE` |
| 5 | `MAX_FRAME_SIZE` |
| 6 | `MAX_HEADER_LIST_SIZE` |
| 9 | `NO_RFC7540_PRIORITIES` |

### HPACK and priority

How header compression and stream priorities behave on the wire.

| Field | Type | Values |
|---|---|---|
| `hpack_indexing_policy` | string | `"chrome"`, `"never"`, `"always"`, `"default"` |
| `stream_priority_mode` | string | `"chrome"`, `"default"` |
| `disable_cookie_split` | bool | When true, the `Cookie:` header is sent as one line instead of split into multiple HPACK entries. |
| `hpack_never_index` | string[] | Lowercase header names that must be sent without HPACK indexing. |

### `priority_table`

Maps `sec-fetch-dest` values (`document`, `image`, `script`, `style`, `font`, and so on) to per-resource priority settings. When populated, the transport emits a per-request RFC 7540 stream weight derived from `urgency` plus an RFC 9218 `priority:` header on every request, keyed off the request's `sec-fetch-dest`.

```json
"priority_table": {
  "document": { "urgency": 0, "incremental": false, "emit_header": true },
  "image":    { "urgency": 5, "incremental": true,  "emit_header": true },
  "style":    { "urgency": 1, "incremental": false, "emit_header": true }
}
```

| Field | Type | Notes |
|---|---|---|
| `urgency` | uint8 | 0 (highest) to 7 (lowest). Maps to RFC 9218. |
| `incremental` | bool | Whether the resource can be processed incrementally. |
| `emit_header` | bool | When true, the transport emits a `priority:` header on the request. |

Omit it and every request uses the preset's static `stream_weight` and `stream_exclusive`. That's the legacy single-weight behaviour from before the priority table existed.

---

## `http3` object

The HTTP/3 layer, including the QUIC transport parameters that anchor a Chrome-shaped initial packet.

```json
"http3": {
  "qpack_max_table_capacity": 65536,
  "qpack_blocked_streams":     100,
  "max_field_section_size":    65536,
  "enable_datagrams":          true,

  "quic_initial_packet_size":     1252,
  "quic_max_incoming_streams":    100,
  "quic_max_incoming_uni_streams":3,
  "quic_allow_0rtt":              true,
  "quic_chrome_style_initial":    true,
  "quic_disable_hello_scramble":  false,
  "quic_transport_param_order":   "chrome",   // or "random"
  "quic_connection_id_length":    8,
  "quic_max_datagram_frame_size": 65535,

  "max_response_header_bytes":    524288,
  "send_grease_frames":           true,

  "quic_initial_stream_receive_window":     2097152,
  "quic_initial_connection_receive_window": 16777216
}
```

| Field | Type | Notes |
|---|---|---|
| `qpack_max_table_capacity` | uint64 | QPACK encoder table cap advertised in `SETTINGS`. |
| `qpack_blocked_streams` | uint64 | Max QPACK-blocked streams. |
| `max_field_section_size` | uint64 | Max headers size. |
| `enable_datagrams` | bool | Whether to advertise H3 DATAGRAM support. |
| `quic_initial_packet_size` | uint16 | Initial packet size for QUIC handshake. Chrome uses 1252. |
| `quic_max_incoming_streams` | int64 | `initial_max_streams_bidi`. |
| `quic_max_incoming_uni_streams` | int64 | `initial_max_streams_uni`. |
| `quic_allow_0rtt` | bool | Enable 0-RTT data. |
| `quic_chrome_style_initial` | bool | Mimic Chrome's first-flight packet shape. |
| `quic_disable_hello_scramble` | bool | When true, don't permute extensions in QUIC ClientHello. |
| `quic_transport_param_order` | string | `"chrome"` or `"random"`. Chrome's order is fixed and identifying. |
| `quic_connection_id_length` | int | Length of source connection IDs. |
| `quic_max_datagram_frame_size` | uint64 | Max DATAGRAM frame size. |
| `max_response_header_bytes` | uint64 | Per-response header size cap. |
| `send_grease_frames` | bool | Send GREASE frames between real frames. |
| `quic_initial_stream_receive_window` | uint64 | `initial_max_stream_data_*`. iOS Safari uses 2 MiB; Chrome desktop uses different values. |
| `quic_initial_connection_receive_window` | uint64 | `initial_max_data`. iOS Safari uses 16 MiB. |

Omit a field (nil) and the quic-go default applies. The library only writes a slot when the spec asks for it.

---

## `headers` object

The HTTP request header bundle. User-Agent, all the named values, and the exact wire order they're sent in.

```json
"headers": {
  "user_agent": "Mozilla/5.0 ...",
  "values": {
    "accept-language": "en-US,en;q=0.9",
    "sec-ch-ua":       "..."
  },
  "order": [
    {"key": "sec-ch-ua",         "value": "..."},
    {"key": "user-agent",        "value": ""},
    {"key": "accept",            "value": "..."},
    {"key": "accept-encoding",   "value": "gzip, deflate, br, zstd"}
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `user_agent` | string | The `User-Agent` value. Set separately because the field is also referenced in `order` via `"key": "user-agent"`. |
| `values` | object (string→string) | Header values keyed by lowercase header name. Merged with the inherited `values` from `based_on`. |
| `order` | array of `{key, value}` | The exact header order on the wire. Lowercase keys. An empty `value` means "use the value from `values` or `user_agent`". |

Order matters. HTTP/2 and HTTP/3 don't enforce header order on the receiving side, but bot-detection products fingerprint it. Real Chrome and real Firefox sit far apart on this dimension.

---

## `tcp` object

The TCP/IP layer fingerprint. TTL, MSS, window size and scale, the Don't Fragment bit.

```json
"tcp": {
  "platform":     "Windows",   // shorthand: "Windows", "macOS", "Linux"
  "ttl":          128,
  "mss":          1460,
  "window_size":  65535,
  "window_scale": 8,
  "df_bit":       true
}
```

`platform` is a shorthand that fills in the typical TTL / MSS / window combo for that OS. Individual fields override the platform default field-by-field.

These only matter for the handful of bot-management products that fingerprint the TCP/IP stack. Most don't.

---

## `protocols` object

Feature flags that gate which protocols the preset participates in.

```json
"protocols": {
  "http3": true
}
```

| Field | Type | Notes |
|---|---|---|
| `http3` | bool | Whether the preset advertises HTTP/3 support. When false, the runtime won't try QUIC even if the host advertises it via Alt-Svc. |

---

## Round-trip guarantee

The chain `Describe -> LoadPresetFromJSON -> BuildPreset -> Describe` produces byte-identical JSON. CI uses this property to catch silent drift in the embedded presets.

```go
import "github.com/sardanioss/httpcloak/fingerprint"

orig, _ := fingerprint.Describe("chrome-148-windows")
pf, _ := fingerprint.LoadPresetFromJSON([]byte(orig))
rebuilt, _ := fingerprint.BuildPreset(pf.Preset)
fingerprint.Register(rebuilt.Name+"-rt", rebuilt)
again, _ := fingerprint.Describe(rebuilt.Name+"-rt")
// orig == again, modulo the renamed `name` field
```

The verified spot-check (chrome-148-windows, firefox-148, safari-18-ios) shows zero diff beyond the rename.

---

## Inheritance and validation

`based_on` resolves at build time. Inheritance loops are caught and reported as `based_on inheritance loop detected at "..."`. The chain terminates at a built-in preset whose `based_on` is empty.

`BuildPreset(spec)` does the following:

1. If `based_on` is set, the parent preset gets cloned (deep copy of headers, H2/H3 config, JA3 extras).
2. Each non-empty section in your spec overlays on top.
3. Validation runs: TLS rules, HPACK indexing policy values, stream priority mode values, QUIC transport param order values.
4. The built `*Preset` comes back. Register it with `fingerprint.Register(name, preset)` so `NewSession(name)` can find it.

A spec with no `name` is fine. `BuildPreset` returns a `*Preset` carrying whatever name `based_on` had, and you can rename it before registering.

---

## Loading from disk

Two-step: read and parse the JSON, then build and register the preset.

```go
pf, err := fingerprint.LoadPresetFromFile("/etc/httpcloak/presets/my-chrome.json")
preset, err := fingerprint.BuildPreset(pf.Preset)
fingerprint.Register("my-chrome", preset)

// Now NewSession("my-chrome") works.
```

Or, in one shot:

```go
preset, err := fingerprint.LoadAndBuildPreset("/path/to/preset.json")
fingerprint.Register(preset.Name, preset)
```

---

## A complete minimal example

A real preset that swaps only the User-Agent on top of `chrome-148-windows`:

```json
{
  "version": 1,
  "preset": {
    "name": "chrome-148-windows-headless",
    "based_on": "chrome-148-windows",
    "headers": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/148.0.0.0 Safari/537.36"
    }
  }
}
```

Everything else (TLS, HTTP/2, header order, HTTP/3, TCP) inherits from `chrome-148-windows`. The embedded JSONs use this same pattern to ship Chrome 147 and 148 without retyping 5000 lines per version.
