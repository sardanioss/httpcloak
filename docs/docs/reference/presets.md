---
title: Presets
sidebar_position: 2
---

# Presets

Every fingerprint preset that ships with httpcloak. Use this as the lookup when you need to know which preset produces which JA3, JA4, Akamai H2 hash, and User-Agent.

The data comes from the registry in `fingerprint/presets.go`. Newer Chrome versions (147 through 155) live in the embedded JSON registry at `fingerprint/embedded/*.json` and inherit from older presets via `based_on`.

:::tip
Want to see what a real browser sends right now? Hit [tls.peet.ws/api/all](https://tls.peet.ws/api/all). DevTools won't show you header order, so peet is your only source of truth there.
:::

---

## Aliases

The `-latest` aliases point to the newest tracked version. They're not separate fingerprints, just pointers that move when a new version lands.

| Alias | Resolves to |
|---|---|
| `chrome-latest` | `chrome-155` (auto-detects host OS) |
| `chrome-latest-windows` | `chrome-155-windows` |
| `chrome-latest-linux` | `chrome-155-linux` |
| `chrome-latest-macos` | `chrome-155-macos` |
| `chrome-latest-ios` | `chrome-155-ios` |
| `chrome-latest-android` | `chrome-155-android` |
| `firefox-latest` | `firefox-148` |
| `firefox-latest-windows` | `firefox-148-windows` |
| `firefox-latest-linux` | `firefox-148-linux` |
| `firefox-latest-macos` | `firefox-148-macos` |
| `safari-latest` | `safari-18` |
| `safari-latest-ios` | `safari-26-ios` |

iOS Chrome spells its version out in full, including a build number that cannot be
derived from the major version, so each iOS preset is built from a real capture rather
than generated. That is why there is no `chrome-153-ios` or `chrome-154-ios`: no capture
of either was made. `chrome-155-ios` comes from one.

The old-style names are kept for back-compat and follow the same targets:

| Alias | Resolves to |
|---|---|
| `ios-chrome-latest` | `chrome-155-ios` |
| `ios-safari-latest` | `safari-26-ios` |
| `android-chrome-latest` | `chrome-155-android` |

Version-pinned old-style names (`ios-chrome-NNN`, `android-chrome-NNN`) only exist for 143 through 148. For anything newer, use the `chrome-NNN-ios` / `chrome-NNN-android` spelling.

`chrome-155` with no platform suffix sniffs the running OS and dispatches to `chrome-155-windows`, `chrome-155-macos`, or `chrome-155-linux`. Pick this when the binary should match its host. Pick the explicit suffix when you want, say, a Windows fingerprint from a Linux scraper, which is the common case.

---

## Captured hashes (verified against tls.peet.ws)

Re-measured `2026-10-13` from the Linux build host for the Chrome 152 to 155 rows; the older rows are from `2026-08-31`. The Safari 26 iOS row was verified against a phone capture and the Go build on `2026-10-19`. Everything shows H2 because the endpoint used does not advertise H3.

| Preset | Protocol | JA3 hash | JA4 | Akamai HTTP/2 hash | PeetPrint |
|---|---|---|---|---|---|
| `chrome-latest` (resolves to `chrome-155-linux`) | h2 | rotates | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `52d84b11737d980aef856699f885ca86` | `fc97c1cdfb1409c9a9326c1b726d1dee` |
| `chrome-155-windows` | h2 | rotates | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `52d84b11737d980aef856699f885ca86` | `fc97c1cdfb1409c9a9326c1b726d1dee` |
| `chrome-155-android` | h2 | rotates | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `52d84b11737d980aef856699f885ca86` | `fc97c1cdfb1409c9a9326c1b726d1dee` |
| `chrome-154-windows` | h2 | rotates | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `52d84b11737d980aef856699f885ca86` | `fc97c1cdfb1409c9a9326c1b726d1dee` |
| `chrome-153-windows` | h2 | rotates | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `52d84b11737d980aef856699f885ca86` | `fc97c1cdfb1409c9a9326c1b726d1dee` |
| `chrome-152-windows` | h2 | rotates | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `52d84b11737d980aef856699f885ca86` | `fc97c1cdfb1409c9a9326c1b726d1dee` |
| `chrome-149-windows` | h2 | rotates | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `52d84b11737d980aef856699f885ca86` | `1d4ffe9b0e34acac0bd883fa7f79d7b5` |
| `chrome-148-windows` | h2 | rotates | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `52d84b11737d980aef856699f885ca86` | `1d4ffe9b0e34acac0bd883fa7f79d7b5` |
| `firefox-148` | h2 | `6f7889b9fb1a62a9577e685c1fcfa919` | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` | `6ea73faa8fc5aac76bded7bd238f6433` | `89d89662b21018947a9a46658c4f5ede` |
| `safari-18` | h2 | `c8af4d593e65bd6ba927ef9a0bdef541` | `t13d2013h2_a09f3c656075_7f0f34a4126d` | `90d8353e47699c4c38ecd773e9b5a089` | `62b834de729e78a9f0ebd1dd099314a7` |
| `safari-18-ios` | h2 | `e7c59d91e34d9d83e510732edf732b83` | `t13d2013h2_a09f3c656075_7f0f34a4126d` | `90d8353e47699c4c38ecd773e9b5a089` | `62b834de729e78a9f0ebd1dd099314a7` |
| `safari-26-ios` | h2 | `ecdf4f49dd59effc439639da29186671` | `t13d2013h2_a09f3c656075_7f0f34a4126d` | `c52879e43202aeb92740be6e8c86ea96` | `62b834de729e78a9f0ebd1dd099314a7` |

Notes:

- Every Chromium preset shows `rotates` for JA3 rather than a value, because it has no single value to show. Chrome permutes its ClientHello extensions on every handshake, so its JA3 differs connection to connection, and the presets reproduce that. Pinning one hash here would document a client that does not exist. JA4 is stable across those connections because it sorts the extension list before hashing, which is why it is the one worth comparing.
- Chrome 152 moved its JA4 to `t13d1517h2_...` because it added an extension, taking the count from 16 to 17. Versions 143 through 149 shared a single JA4; 150 changed the tail by adding signature algorithms, and 151 kept it. 153, 154 and 155 measure the same as 152 on every hash above; 155 was also checked on Linux, macOS and Android and matched.
- The Chrome 152 JA4 tail is only stable against a tool that discards greased values inside `signature_algorithms`, which the specification asks for but not every implementation does. Chrome 152 puts one at the head of that list per handshake, so an implementation that keeps it reports a different tail every connection, sixteen in all. Real Chrome does the same, so a moving tail is the profile working. The value above was measured against one that strips.
- `safari-18` and `safari-18-ios` share JA4 + Akamai because the H2 stack is identical. The JA3 differs because of platform-specific ClientHello extensions.

For any preset not listed, run the same capture yourself. The static parts (UA, sec-ch-ua, header order) are also visible in `fingerprint/embedded/<name>.json`.

---

## Chrome desktop

The Chrome desktop family. Versions 143 through 146 are Go-defined in `fingerprint/presets.go`. Versions 147 through 155 ship as JSON in `fingerprint/embedded/`, each inheriting from the one before it. Most bump only the User-Agent and the `sec-ch-ua` brand list; 150 and 152 also change the TLS layer, 150 by adding signature algorithms and 152 by adding the trust anchors extension and a greased signature algorithm. 154 keeps the same extensions but sends the trust anchor list sorted, on TCP and QUIC alike, where 152 and 153 send a fixed unsorted order on TCP and reshuffle it per connection on QUIC. 155 adds `image/jxl` to the `Accept` header, ahead of `image/avif`, on both document and image loads.

| Preset | UA | `sec-ch-ua` | Notes |
|---|---|---|---|
| `chrome-155-windows` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36` | `"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"` | Adds `image/jxl` to the document and image `Accept` headers. TLS inherited from 154. |
| `chrome-155-linux` | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36` | `"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"` | As above. |
| `chrome-155-macos` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36` | `"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"` | As above. |
| `chrome-155-android` | `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36` | `"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"` | As above, with `sec-ch-ua-mobile: ?1`. |
| `chrome-154-windows` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36` | `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"` | Trust anchor list sent sorted, and no longer reshuffled on QUIC. |
| `chrome-154-linux` | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36` | `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"` | As above. |
| `chrome-154-macos` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36` | `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"` | As above. |
| `chrome-154-android` | `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Mobile Safari/537.36` | `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"` | As above, with `sec-ch-ua-mobile: ?1`. |
| `chrome-153-windows` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36` | `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"` | Headers only. TLS inherited from 152. |
| `chrome-153-linux` | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36` | `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"` | As above. |
| `chrome-153-macos` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36` | `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"` | As above. |
| `chrome-153-android` | `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36` | `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"` | As above, with `sec-ch-ua-mobile: ?1`. |
| `chrome-152-windows` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36` | `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"` | New wire shape: trust anchors, plus a greased signature algorithm on TCP. |
| `chrome-152-linux` | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36` | `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"` | As above. |
| `chrome-152-macos` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36` | `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"` | As above. |
| `chrome-152-android` | `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Mobile Safari/537.36` | `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"` | As above, with `sec-ch-ua-mobile: ?1`. |
| `chrome-155-ios` | `Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/155.0.8059.37 Mobile/15E148 Safari/604.1` | not sent | Headers-only over 152: same TLS, HTTP/2 and header block, measured against a real iPhone capture. |
| `chrome-152-ios` | `Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/152.0.7977.64 Mobile/15E148 Safari/604.1` | not sent | WebKit TLS, so neither 152 wire change applies. Built from real captures. |
| `chrome-149-windows` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36` | `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"` | Inherits TLS from `chrome-148-windows`. |
| `chrome-149-linux` | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36` | `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"` | Inherits TLS from `chrome-148-linux`. |
| `chrome-149-macos` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36` | `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"` | Inherits TLS from `chrome-148-macos`. |
| `chrome-148-windows` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36` | `"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"` | Inherits TLS from `chrome-147-windows`. |
| `chrome-148-linux` | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36` | `"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"` | Inherits TLS from `chrome-147-linux`. |
| `chrome-148-macos` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36` | `"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"` | Inherits TLS from `chrome-147-macos`. |
| `chrome-147-windows` | `...Chrome/147.0.0.0 Safari/537.36` | `"Google Chrome";v="147", "Chromium";v="147", "Not.A/Brand";v="8"` | Inherits TLS from `chrome-146-windows`. |
| `chrome-147-linux` | `...Chrome/147.0.0.0 Safari/537.36` | `"Google Chrome";v="147", "Chromium";v="147", "Not.A/Brand";v="8"` | Inherits TLS from `chrome-146-linux`. |
| `chrome-147-macos` | `...Chrome/147.0.0.0 Safari/537.36` | `"Google Chrome";v="147", "Chromium";v="147", "Not.A/Brand";v="8"` | Inherits TLS from `chrome-146-macos`. |
| `chrome-146-windows` | `...Chrome/146.0.0.0 Safari/537.36` | `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="8"` | Native Go preset. ClientHello: `HelloChrome_146_Windows`. |
| `chrome-146-linux` | `...Chrome/146.0.0.0 Safari/537.36` | `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="8"` | Native Go preset. ClientHello: `HelloChrome_146_Linux`. |
| `chrome-146-macos` | `...Chrome/146.0.0.0 Safari/537.36` | `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="8"` | Native Go preset. ClientHello: `HelloChrome_146_macOS`. |
| `chrome-145-{windows,linux,macos}` | `...Chrome/145.0.0.0...` | matching brand list | Native Go preset, per-platform ClientHello. |
| `chrome-144-{windows,linux,macos}` | `...Chrome/144.0.0.0...` | matching brand list | Native Go preset, per-platform ClientHello. |
| `chrome-143-{windows,linux,macos}` | `...Chrome/143.0.0.0...` | matching brand list | Native Go preset, per-platform ClientHello. |
| `chrome-141` | `...Chrome/141.0.0.0...` | matching brand list | Legacy preset, no per-OS variants, no QUIC fingerprint (H1/H2 only). |
| `chrome-133` | `...Chrome/133.0.0.0...` | matching brand list | Legacy preset, no per-OS variants, no QUIC fingerprint (H1/H2 only). |

The unsuffixed names, `chrome-143` through `chrome-155`, resolve at runtime to whichever platform-suffixed variant matches the host OS. Pick the suffix when you want consistent results across machines.

The 143-and-newer Chrome desktop line:

- Speaks HTTP/3 via `tls.HelloChrome_<v>_QUIC` plus a PSK variant for resumption.
- Uses the Chrome H2 config (`chromeH2Config`): pseudo-header order `m,a,s,p`, settings order from real Chrome captures, RFC 7540 priorities on `HEADERS`.
- Default Akamai: `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`.

`chrome-141` and `chrome-133` are kept around for callers pinning a specific older Chrome version, but they ship without a QUIC fingerprint, so a session built on one of them will only negotiate H1 and H2.

---

## Chrome iOS

iOS Chrome is a WebKit wrapper, so its TLS fingerprint matches Safari iOS rather than desktop Chrome. `chrome-155-ios` and `chrome-152-ios` are listed with the desktop versions above. App Store policy forces this; Apple won't let third-party browsers ship their own engines on iOS.

| Preset | UA | TLS | Notes |
|---|---|---|---|
| `chrome-151-ios` | `...iPhone OS 26_6_0...CriOS/151.0.7922.112 Mobile/15E148 Safari/604.1` | `HelloIOS_18` | Headers-only over 150. Built from a real capture. |
| `chrome-150-ios` | `...iPhone OS 26_5_0...CriOS/150.0.7871.51 Mobile/15E148 Safari/604.1` | `HelloIOS_18` | Headers-only over 148. Built from a real capture. No ML-DSA: iOS uses the system TLS stack. |
| `chrome-148-ios` | `...iPhone OS 26_4_2...CriOS/148.0.7778.47 Mobile/15E148 Safari/604.1` | `HelloIOS_18` | Inherits from `chrome-146-ios`. |
| `chrome-147-ios` | `...CriOS/147.0.6917.0 Mobile/15E148 Safari/604.1` | `HelloIOS_18` | Inherits from `chrome-146-ios`. |
| `chrome-146-ios` | `...CriOS/146.0.6917.0 Mobile/15E148 Safari/604.1` | `HelloIOS_18` | Native Go preset. |
| `chrome-145-ios` | `...CriOS/145.0.0.0...` | `HelloIOS_18` | Native Go preset. |
| `chrome-144-ios` | `...CriOS/144.0.0.0...` | `HelloIOS_18` | Native Go preset. |
| `chrome-143-ios` | `...CriOS/143.0.0.0...` | `HelloIOS_18` | Native Go preset. |

All iOS Chrome presets:

- Use the iOS Safari H2 stack (`safariH2Config`): pseudo `m,s,p,a`, `NO_RFC7540_PRIORITIES=1`.
- Speak HTTP/3 via `HelloIOS_18_QUIC`.
- Default Akamai: `2:0;4:2097152;3:100;5:16384;9:1|10485760|0|m,s,p,a`.

---

## Chrome Android

Android Chrome ships its own native TLS stack, so the fingerprint matches desktop Chrome rather than the platform browser. No WebKit lockdown.

| Preset | UA | TLS | Notes |
|---|---|---|---|
| `chrome-148-android` | `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36` | `HelloChrome_<v>_Linux` | Inherits from `chrome-147-android`. |
| `chrome-147-android` | `...Chrome/147.0.0.0 Mobile Safari/537.36` | `HelloChrome_<v>_Linux` | Inherits from `chrome-146-android`. |
| `chrome-146-android` | `...Chrome/146.0.0.0 Mobile Safari/537.36` | `HelloChrome_146_Linux` | Native Go preset. |
| `chrome-145-android` | `...Chrome/145.0.0.0...` | `HelloChrome_145_Linux` | Native Go preset. |
| `chrome-144-android` | `...Chrome/144.0.0.0...` | `HelloChrome_144_Linux` | Native Go preset. |
| `chrome-143-android` | `...Chrome/143.0.0.0...` | `HelloChrome_143_Linux` | Native Go preset. |

`sec-ch-ua-mobile` becomes `?1` (versus `?0` on desktop) and `sec-ch-ua-platform` is `"Android"`. Default Akamai matches Chrome desktop because the H2 stack is identical.

---

## Firefox

Firefox uses a different TLS extension order from Chrome. Compare the JA3s in the table above and the difference is immediate.

| Preset | UA | TLS | Notes |
|---|---|---|---|
| `firefox-148` | `Mozilla/5.0 (...; rv:148.0) Gecko/20100101 Firefox/148.0` | JA3 mode (no native uTLS Firefox 148) | H3 not supported (no Firefox QUIC fingerprint in uTLS). |
| `firefox-133` | `Mozilla/5.0 (...; rv:133.0) Gecko/20100101 Firefox/133.0` | uTLS `HelloFirefox_133` | H3 not supported. |

All Firefox presets:

- Use the Firefox H2 stack (`firefoxH2Config`): pseudo `m,p,a,s`, `ENABLE_PUSH=0`, custom HPACK ordering.
- Send `TE: trailers`, which Chrome doesn't.
- Default Akamai for `firefox-148`: `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`.
- Skip `sec-ch-ua` headers entirely. Firefox doesn't implement Client Hints.

---

## Safari (macOS)

| Preset | UA | TLS | Notes |
|---|---|---|---|
| `safari-18` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15` | `HelloSafari_18` | H3 via `HelloIOS_18_QUIC` (Safari shares iOS QUIC). |

Safari macOS:

- Pseudo order `m,s,p,a`, different from both Chrome and Firefox.
- `NO_RFC7540_PRIORITIES=1`. Safari opts out of stream priorities.
- No `sec-ch-ua` (Safari doesn't ship Client Hints). Header order is shorter than Chrome's.
- Default Akamai: `2:0;4:2097152;3:100;5:16384;9:1|10485760|0|m,s,p,a`.

---

## Safari iOS

| Preset | UA | TLS | Notes |
|---|---|---|---|
| `safari-26-ios` | `...iPhone OS 18_7...Version/26.6.1 Mobile/15E148 Safari/604.1` | `HelloIOS_18` | Captured H2; HTTP/3 disabled pending a QUIC capture. |
| `safari-18-ios` | `Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1` | `HelloIOS_18` | H3 via `HelloIOS_18_QUIC`. |
| `safari-17-ios` | `...iPhone OS 17_0...Version/17.0 Mobile...` | `HelloIOS_17` | Older variant; H1 / H2 only (no proper H3 TLS spec for iOS Safari 17). |

The Safari 18 iOS and desktop presets share the older H2 fingerprint. Safari 26 iOS has the captured H2 changes described below.

---

## Per-preset details

For the static parts of a preset (UA, sec-ch-ua, header order, H2 settings), the source of truth is the JSON in `fingerprint/embedded/` for v147 and newer, or the Go function in `fingerprint/presets.go` for v146 and older.

To dump any registered preset as canonical JSON:

```go
import "github.com/sardanioss/httpcloak/fingerprint"

j, err := fingerprint.Describe("chrome-152-windows")
// j is the round-trip-stable JSON form
```

The same JSON loads back through `fingerprint.LoadPresetFromJSON` and `fingerprint.BuildPreset` unmodified, so this is also the way to snapshot a preset to disk for diffing across versions.

---

## Picking a preset

Rough guide based on what you're aiming for:

| Goal | Use |
|---|---|
| Just scrape something modern | `chrome-latest` |
| Looking like a Windows desktop user | `chrome-latest-windows` |
| Looking like a phone | `chrome-latest-android` or `safari-latest-ios` |
| Sites that allowlist Firefox quirks (HPACK, TE: trailers) | `firefox-latest` |
| Sites that block Chrome but pass Safari | `safari-latest` |
| Pinning to a specific version for reproducibility | `chrome-155-windows` (no `-latest`) |

For sites that fingerprint the TCP/IP stack (rare, but a few bot-management products do), pair the preset with `WithTCPFingerprint(...)` to spoof TTL, window size, and MSS.

For everything else, start with `chrome-latest`, capture against `tls.peet.ws/api/all`, compare against a real Chrome on the same OS, and file an issue if JA3, Akamai, or JA4 doesn't match.

### Safari 26 on iOS

`safari-26-ios` and `ios-safari-26` reproduce a Safari 26.6.1 iPhone HTTP/2
capture from October 19, 2026. Both iOS Safari latest aliases now select it.
Desktop Safari and explicit Safari 17/18 presets retain their existing profiles.

TLS uses the existing `HelloIOS_18` implementation. The captured JA3 is
`ecdf4f49dd59effc439639da29186671`, JA4 is
`t13d2013h2_a09f3c656075_7f0f34a4126d`, and Peetprint is
`62b834de729e78a9f0ebd1dd099314a7`. The HTTP/2 fingerprint is
`2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`, with no PRIORITY field
on HEADERS. Navigation uses the captured Safari 26.6.1 UA, header order,
`priority: u=0, i`, and `gzip, deflate, br, zstd`, without `sec-fetch-user`.

The source capture used `en-AU,en;q=0.9`; the preset keeps the library's
`en-US,en;q=0.9` default. Override Accept-Language to reproduce that locale.
HTTP/3 is disabled for this preset because no QUIC capture was supplied.
The sanitized reference in `fingerprint/testdata/safari-26-ios-capture.json`
contains no IP addresses, cookies, TLS randoms, session IDs or key-share bytes.
