#!/usr/bin/env python3
"""
TLS-Only Mode with httpcloak

TLS-only mode lets you use the browser's TLS fingerprint (JA3/JA4, Peetprint,
Akamai) while having full control over HTTP headers.

What you'll learn:
- What TLS-only mode does vs normal mode
- When to use TLS-only mode
- How to set custom headers in TLS-only mode

Requirements:
    pip install httpcloak

Run:
    python 11_tls_only_mode.py
"""

import httpcloak

# ============================================================
# Example 1: Normal Mode (default behavior)
# ============================================================
# In normal mode, preset headers are automatically applied

print("=" * 60)
print("Example 1: Normal Mode (preset headers applied)")
print("-" * 60)

with httpcloak.Session(preset="chrome-latest") as session:
    response = session.get("https://httpbin.org/headers")
    headers = response.json().get("headers", {})

    print("Headers sent to server:")
    for key, value in sorted(headers.items()):
        if key.startswith(("Sec-", "Accept", "User-Agent", "Priority", "Upgrade")):
            print(f"  {key}: {value[:60]}{'...' if len(value) > 60 else ''}")

    print(f"\nTotal headers: {len(headers)}")
    print("Note: All Chrome preset headers are automatically included")

# ============================================================
# Example 2: TLS-Only Mode (no preset headers)
# ============================================================
# TLS fingerprint is applied, but HTTP headers are not

print("\n" + "=" * 60)
print("Example 2: TLS-Only Mode (custom headers only)")
print("-" * 60)

with httpcloak.Session(preset="chrome-latest", tls_only=True) as session:
    # Only our custom headers will be sent
    response = session.get("https://httpbin.org/headers", headers={
        "User-Agent": "MyBot/1.0",
        "X-Custom-Header": "my-value",
    })
    headers = response.json().get("headers", {})

    print("Headers sent to server:")
    for key, value in sorted(headers.items()):
        print(f"  {key}: {value}")

    print(f"\nTotal headers: {len(headers)}")
    print("Note: Only our custom headers + minimal required headers")

# ============================================================
# Example 3: TLS-Only for API Clients
# ============================================================
# Useful when you need TLS fingerprint but specific API headers

print("\n" + "=" * 60)
print("Example 3: TLS-Only for API Clients")
print("-" * 60)

with httpcloak.Session(preset="chrome-latest", tls_only=True) as session:
    # API-style request with custom headers
    response = session.get("https://httpbin.org/headers", headers={
        "Authorization": "Bearer my-api-token",
        "X-API-Key": "secret-key-123",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    headers = response.json().get("headers", {})

    print("API request headers:")
    for key, value in sorted(headers.items()):
        if not key.startswith("X-Amzn"):  # Skip AWS trace headers
            print(f"  {key}: {value}")

    print("\nNo Sec-Ch-Ua or browser-specific headers leaked!")

# ============================================================
# Example 4: Comparing Fingerprints
# ============================================================
# Both modes produce the same TLS fingerprint

print("\n" + "=" * 60)
print("Example 4: TLS Fingerprint Comparison")
print("-" * 60)

# Check TLS fingerprint in normal mode
with httpcloak.Session(preset="chrome-latest") as session:
    response = session.get("https://tls.peet.ws/api/all")
    data = response.json()
    ja4 = data.get("tls", {}).get("ja4", "N/A")
    print(f"Normal mode JA4:   {ja4}")

# Check TLS fingerprint in TLS-only mode
with httpcloak.Session(preset="chrome-latest", tls_only=True) as session:
    response = session.get("https://tls.peet.ws/api/all")
    data = response.json()
    ja4 = data.get("tls", {}).get("ja4", "N/A")
    print(f"TLS-only mode JA4: {ja4}")

print("\nBoth have identical TLS fingerprints!")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 60)
print("Summary: When to use TLS-Only Mode")
print("=" * 60)
print("""
Use TLS-only mode when you need:

1. Full control over HTTP headers
   - API clients with specific header requirements
   - Custom User-Agent strings
   - No browser-specific headers (Sec-Ch-Ua, etc.)

2. TLS fingerprint without HTTP fingerprint
   - Pass TLS-based bot detection
   - But use your own HTTP header set

3. Minimal header footprint
   - Only send headers you explicitly set
   - Useful for testing or specific protocols

Normal mode is better when:
- You want to fully mimic a browser
- You need automatic browser headers
- You're accessing websites (not APIs)
""")
