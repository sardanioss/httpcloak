# MASQUE Proxy Chrome Fingerprinting Limitations

This document explains why certain Chrome fingerprinting parameters cannot be used when making HTTP/3 connections through a MASQUE proxy tunnel.

## Overview

When using MASQUE (RFC 9484) to tunnel HTTP/3 connections through a proxy, the inner QUIC connection (to the target server) has different constraints than direct connections. Some Chrome fingerprinting features that work for direct connections fail through the MASQUE tunnel.

## Working Parameters

The following Chrome fingerprinting parameters **work** through MASQUE:

| Parameter | Status | Description |
|-----------|--------|-------------|
| `ClientHelloID` | ✅ Works | uTLS generates Chrome-like TLS ClientHello with proper extensions and cipher suites |
| `TransportParameterOrder: Chrome` | ✅ Works | QUIC transport parameters sent in Chrome's order |
| `TransportParameterShuffleSeed` | ✅ Works | Consistent shuffle of transport parameters |
| `DisableClientHelloScrambling` | ✅ Works | Sends ClientHello in natural order (fewer packets), matching Chrome |
| `ECHConfigList` | ✅ Works | Encrypted Client Hello encrypts SNI through tunnel |

## Parameter Status

The following parameters have special handling through MASQUE:

### 1. `CachedClientHelloSpec`

**What it does:** Pre-caches a TLS ClientHelloSpec generated from `ClientHelloID` with a specific shuffle seed. This maintains consistent TLS extension ordering across all connections in a session (matching Chrome's behavior of shuffling once per session, not per connection).

**Status: ✅ FIXED**

The issue was that sharing the same `CachedClientHelloSpec` between outer (proxy) and inner (target) connections caused state corruption. The cached spec has mutable internal state that got corrupted after the outer connection used it.

**Solution:** Use a **separate** `CachedClientHelloSpec` for inner connections (`cachedClientHelloSpecInner`), generated with the same shuffle seed but not shared with the outer connection. This ensures:
- JA4 hash is consistent across all inner requests (same TLS extension order)
- No state corruption from outer connection usage
- Full Chrome-like TLS fingerprint through the tunnel

### 2. `ChromeStyleInitialPackets`

**What it does:** Creates Chrome-like frame patterns in QUIC Initial packets:
- Uses smaller CRYPTO frames (~150 bytes each instead of filling packets)
- Adds PING frames interspersed between CRYPTO frames
- Distributes padding across multiple Initial packets (~275 bytes per packet)
- Targets ~975 bytes of frame data per Initial packet

**Why it fails through MASQUE:**
- **Note:** The proxy CANNOT decrypt or modify QUIC packet content - it only forwards encrypted UDP datagrams
- Creates multiple smaller Initial packets instead of fewer larger ones
- Each QUIC packet becomes a separate HTTP/3 datagram through the tunnel
- UDP characteristics apply: no ordering guarantee, potential packet loss
- More packets = higher probability of packet loss or out-of-order delivery
- QUIC handshake is sensitive to packet loss during Initial exchange
- Added latency from datagram encapsulation may trigger retransmission timers

**Is it solvable?** Potentially, but the core issue is UDP's lack of ordering/reliability guarantees:
1. **Fewer packets:** Use standard QUIC Initial packets (fewer, larger) to reduce loss exposure
2. **Retransmission tuning:** Adjust QUIC retransmission timers for tunnel latency
3. **Accept trade-off:** Standard Initial packets still pass most fingerprint detection (JA3/JA4 focus on TLS, not QUIC packet patterns)

## Technical Details

### MASQUE Tunnel Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         MASQUE Tunnel                                 │
│                                                                       │
│  Client                    Proxy                     Target Server    │
│    │                         │                            │           │
│    │◄─── Outer QUIC ────────►│                            │           │
│    │     (Full Chrome        │                            │           │
│    │      fingerprint)       │                            │           │
│    │                         │                            │           │
│    │    ┌────────────────────┴────────────────────┐       │           │
│    │    │  HTTP/3 CONNECT-UDP Stream              │       │           │
│    │    │  (Carries inner QUIC as datagrams)      │       │           │
│    │    └────────────────────┬────────────────────┘       │           │
│    │                         │                            │           │
│    │                         │◄─── Inner QUIC ───────────►│           │
│    │                         │     (Limited Chrome        │           │
│    │                         │      fingerprint)          │           │
└──────────────────────────────────────────────────────────────────────┘
```

### Why Two Different Fingerprints?

1. **Outer connection (client ↔ proxy):** Uses full Chrome fingerprinting including `CachedClientHelloSpec` and `ChromeStyleInitialPackets`. This makes the proxy connection look like real Chrome traffic.

2. **Inner connection (through proxy ↔ target):** Uses limited Chrome fingerprinting. The inner QUIC packets are carried as HTTP/3 datagrams. The proxy cannot see or modify the encrypted content, but UDP characteristics (no ordering guarantee, potential loss) affect reliability.

### Fingerprint Comparison

| Feature | Direct Connection | Through MASQUE |
|---------|-------------------|----------------|
| TLS ClientHello extensions | Full Chrome (cached spec) | Full Chrome (separate cached spec) |
| TLS extension order | Consistent per session | Consistent per session (JA4 stable) |
| Initial packet pattern | Chrome-style (~150B CRYPTO, PING interspersed) | Standard (larger CRYPTO frames) |
| SNI scrambling | Disabled (Chrome-like) | Disabled (Chrome-like) |
| Transport param order | Chrome | Chrome |
| ECH support | Yes | Yes |

## Impact on Detection

The inner connection fingerprint is **nearly identical** to a direct Chrome connection:

1. **TLS fingerprint:** ✅ Passes JA3/JA4 fingerprint checks - full Chrome cipher suites and extensions
2. **JA4 consistency:** ✅ Consistent per session (fixed via separate cached spec)
3. **QUIC fingerprint:** ✅ Transport parameters match Chrome ordering
4. **Packet pattern:** ⚠️ Does not match Chrome's Initial packet pattern (only difference)

The only remaining difference is the QUIC Initial packet pattern. Most detection systems focus on TLS fingerprint (JA3/JA4) rather than QUIC packet patterns, making MASQUE connections nearly undetectable.

## Recommendations

1. **For maximum stealth:** Use direct HTTP/3 connections when possible
2. **For proxy requirements:** Accept the fingerprint limitations - still passes most detection
3. **For SOCKS5 proxies:** Same limitations apply but datagram handling may differ
4. **For testing:** Use Cloudflare's `/cdn-cgi/trace` endpoint to verify `sni=encrypted` and `http=http/3`

## Future Work

Potential improvements that could enable full Chrome fingerprinting through MASQUE:

1. **Fix ChromeStyleInitialPackets:** Investigate if multi-packet Initial patterns can work with adjusted retransmission timers
2. **Reduce packet count:** Optimize ChromeStyleInitialPackets to use fewer, slightly larger packets while maintaining similar fingerprint
3. **Adaptive fingerprinting:** Detect tunnel conditions and adjust fingerprint accordingly
