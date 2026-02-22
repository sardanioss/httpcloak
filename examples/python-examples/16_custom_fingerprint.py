#!/usr/bin/env python3
"""
Custom JA3 & Akamai Fingerprinting with httpcloak

Override the preset's TLS and HTTP/2 fingerprints with custom JA3 and Akamai
strings for fine-grained control over how your connections appear on the wire.

What you'll learn:
- How to set a custom JA3 TLS fingerprint
- How to set a custom Akamai HTTP/2 fingerprint
- How to use extra fingerprint options (ALPN, signature algorithms, etc.)
- How to combine JA3 + Akamai for full fingerprint control
- How to verify your fingerprint against tls.peet.ws

Requirements:
    pip install httpcloak

Run:
    python 16_custom_fingerprint.py
"""

import httpcloak

# A real Chrome 131 JA3 string (different from the default preset)
CHROME_131_JA3 = (
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172"
    "-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037,29-23-24,0"
)

# A real Chrome Akamai HTTP/2 fingerprint
CHROME_AKAMAI = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"


# ============================================================
# Example 1: Custom JA3 Fingerprint
# ============================================================
# Override the TLS fingerprint with a specific JA3 string.
# TLS-only mode is automatically enabled when JA3 is set.

print("=" * 60)
print("Example 1: Custom JA3 Fingerprint")
print("-" * 60)

with httpcloak.Session(preset="chrome-145", ja3=CHROME_131_JA3) as session:
    response = session.get("https://tls.peet.ws/api/tls")
    data = response.json()

    tls_data = data.get("tls", {})
    ja3_hash = tls_data.get("ja3_hash", "N/A")
    ja3_text = tls_data.get("ja3", "N/A")
    print(f"JA3 hash: {ja3_hash}")
    print(f"JA3 text: {ja3_text[:80]}...")
    print("\nThe TLS fingerprint now matches the custom JA3 string,")
    print("not the chrome-145 preset.")

# ============================================================
# Example 2: Custom Akamai HTTP/2 Fingerprint
# ============================================================
# Override the HTTP/2 SETTINGS, WINDOW_UPDATE, PRIORITY, and
# pseudo-header order with an Akamai fingerprint string.

print("\n" + "=" * 60)
print("Example 2: Custom Akamai HTTP/2 Fingerprint")
print("-" * 60)

with httpcloak.Session(preset="chrome-145", akamai=CHROME_AKAMAI) as session:
    response = session.get("https://tls.peet.ws/api/all")
    data = response.json()

    akamai_fp = data.get("http2", {}).get("akamai_fingerprint", "N/A")
    print(f"Akamai fingerprint: {akamai_fp}")
    print(f"Expected:           {CHROME_AKAMAI}")
    print(f"Match: {akamai_fp == CHROME_AKAMAI}")

# ============================================================
# Example 3: JA3 + Akamai Combined
# ============================================================
# Full control over both TLS and HTTP/2 fingerprints.

print("\n" + "=" * 60)
print("Example 3: Combined JA3 + Akamai")
print("-" * 60)

with httpcloak.Session(
    preset="chrome-145",
    ja3=CHROME_131_JA3,
    akamai=CHROME_AKAMAI,
) as session:
    response = session.get("https://tls.peet.ws/api/all")
    data = response.json()

    ja3_hash = data.get("tls", {}).get("ja3_hash", "N/A")
    akamai_fp = data.get("http2", {}).get("akamai_fingerprint", "N/A")
    print(f"JA3 hash:    {ja3_hash}")
    print(f"Akamai:      {akamai_fp}")
    print("\nBoth TLS and HTTP/2 fingerprints are fully custom.")

# ============================================================
# Example 4: Extra Fingerprint Options
# ============================================================
# Fine-tune TLS extensions beyond what JA3 captures using extra_fp.
# Available options:
#   - tls_signature_algorithms: list of signature algorithm names
#   - tls_alpn: list of ALPN protocols
#   - tls_cert_compression: list of cert compression algorithms
#   - tls_permute_extensions: randomize TLS extension order

print("\n" + "=" * 60)
print("Example 4: Extra Fingerprint Options")
print("-" * 60)

with httpcloak.Session(
    preset="chrome-145",
    ja3=CHROME_131_JA3,
    extra_fp={
        "tls_alpn": ["h2", "http/1.1"],
        "tls_cert_compression": ["brotli"],
        "tls_permute_extensions": True,
    },
) as session:
    response = session.get("https://tls.peet.ws/api/tls")
    data = response.json()

    tls_data = data.get("tls", {})
    ja3_hash = tls_data.get("ja3_hash", "N/A")
    print(f"JA3 hash: {ja3_hash}")
    print("Extensions are randomly permuted — JA3 hash will vary each run")
    print("but cipher suites and curves remain the same.")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 60)
print("Summary: Custom Fingerprinting Options")
print("=" * 60)
print("""
JA3 fingerprint (ja3):
  - Overrides the TLS ClientHello fingerprint
  - Format: TLSVersion,Ciphers,Extensions,Curves,PointFormats
  - Automatically enables TLS-only mode (no preset HTTP headers)

Akamai fingerprint (akamai):
  - Overrides HTTP/2 SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order
  - Format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
  - Works alongside the preset's TLS fingerprint

Extra options (extra_fp):
  - tls_alpn: ["h2", "http/1.1"]
  - tls_signature_algorithms: ["ecdsa_secp256r1_sha256", ...]
  - tls_cert_compression: ["brotli", "zlib", "zstd"]
  - tls_permute_extensions: true/false
  - Used in combination with ja3 to fine-tune the fingerprint
""")
