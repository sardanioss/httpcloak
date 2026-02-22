#!/usr/bin/env python3
"""
Authentication and Proxy Usage

This example demonstrates:
- Basic authentication
- Using proxies
- Timeout configuration
- Error handling
"""

import httpcloak

# Basic authentication
print("=" * 60)
print("Example 1: Basic Authentication")
print("-" * 60)

# Per-request auth
r = httpcloak.get(
    "https://httpbin.org/basic-auth/user/pass",
    auth=("user", "pass")
)
print(f"Status: {r.status_code}")
print(f"Authenticated: {r.json().get('authenticated')}")
print(f"User: {r.json().get('user')}")

# Auth with wrong credentials
r = httpcloak.get(
    "https://httpbin.org/basic-auth/user/pass",
    auth=("wrong", "credentials")
)
print(f"\nWrong credentials - Status: {r.status_code}")

# Global auth configuration
print("\n" + "=" * 60)
print("Example 2: Global Auth Configuration")
print("-" * 60)

httpcloak.configure(
    preset="chrome-145",
    auth=("user", "pass"),
)

r = httpcloak.get("https://httpbin.org/basic-auth/user/pass")
print(f"Status: {r.status_code}")
print(f"Auth header sent automatically")

# Reset configuration
httpcloak.configure(preset="chrome-145")

# Timeout configuration
print("\n" + "=" * 60)
print("Example 3: Timeout Configuration")
print("-" * 60)

# Session-level timeout
session = httpcloak.Session(preset="chrome-145", timeout=10)

try:
    # This should complete within timeout
    r = session.get("https://httpbin.org/delay/2")
    print(f"2s delay - Status: {r.status_code} (completed)")
except httpcloak.HTTPCloakError as e:
    print(f"2s delay - Error: {e}")

session.close()

# Per-request timeout
print("\nPer-request timeout:")
session = httpcloak.Session(preset="chrome-145", timeout=30)

try:
    r = session.get("https://httpbin.org/delay/1", timeout=5)
    print(f"1s delay with 5s timeout - Status: {r.status_code}")
except httpcloak.HTTPCloakError as e:
    print(f"Error: {e}")

session.close()

# Error handling
print("\n" + "=" * 60)
print("Example 4: Error Handling")
print("-" * 60)

r = httpcloak.get("https://httpbin.org/status/404")
print(f"404 response - Status: {r.status_code}, OK: {r.ok}")

try:
    r.raise_for_status()
except httpcloak.HTTPCloakError as e:
    print(f"raise_for_status() raised: {e}")

r = httpcloak.get("https://httpbin.org/status/500")
print(f"500 response - Status: {r.status_code}, OK: {r.ok}")

# Proxy example (commented - requires actual proxy)
print("\n" + "=" * 60)
print("Example 5: Proxy Configuration (Reference)")
print("-" * 60)

print("""
# To use a proxy:
session = httpcloak.Session(
    preset="chrome-145",
    proxy="http://user:pass@proxy.example.com:8080"
)

# Or with configure():
httpcloak.configure(
    preset="chrome-145",
    proxy="socks5://user:pass@proxy.example.com:1080"
)

# Supported proxy formats:
# - http://host:port
# - http://user:pass@host:port
# - socks5://host:port
# - socks5://user:pass@host:port

# Speculative TLS optimization (disabled by default):
# Sends CONNECT + TLS ClientHello together, saving one round-trip (~25% faster).
# Enable it for compatible proxies:
session = httpcloak.Session(
    preset="chrome-145",
    proxy="http://user:pass@proxy.example.com:8080",
    enable_speculative_tls=True
)
""")

print("=" * 60)
print("Auth and proxy examples completed!")
print("=" * 60)
