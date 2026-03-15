#!/usr/bin/env python3
"""
Runtime Proxy Switching

This example demonstrates:
- Switching proxies mid-session without creating new sessions
- Split proxy configuration (different proxies for TCP and UDP)
- Getting current proxy configuration
- H2 and H3 proxy switching
"""

import httpcloak

# Test URL that shows your IP
TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"


def parse_trace(body):
    """Parse cloudflare trace response to get IP and colo."""
    result = {}
    for line in body.strip().split('\n'):
        if '=' in line:
            key, val = line.split('=', 1)
            result[key] = val
    return result


# Basic proxy switching
print("=" * 60)
print("Example 1: Basic Proxy Switching")
print("-" * 60)

# Create session without proxy (direct connection)
session = httpcloak.Session(preset="chrome-latest")

# Make request with direct connection
r = session.get(TEST_URL)
trace = parse_trace(r.text)
print(f"Direct connection:")
print(f"  Protocol: {r.protocol}, IP: {trace.get('ip', 'N/A')}, Colo: {trace.get('colo', 'N/A')}")

# Switch to a proxy (replace with your actual proxy)
# session.set_proxy("http://user:pass@proxy.example.com:8080")
# r = session.get(TEST_URL)
# trace = parse_trace(r.text)
# print(f"\nAfter switching to HTTP proxy:")
# print(f"  Protocol: {r.protocol}, IP: {trace.get('ip', 'N/A')}")

# Switch back to direct connection
# session.set_proxy("")
# print(f"\nSwitched back to direct: {session.get_proxy()}")

session.close()

# Getting current proxy
print("\n" + "=" * 60)
print("Example 2: Getting Current Proxy Configuration")
print("-" * 60)

session = httpcloak.Session(preset="chrome-latest")

print(f"Initial proxy: '{session.get_proxy()}' (empty = direct)")
print(f"TCP proxy: '{session.get_tcp_proxy()}'")
print(f"UDP proxy: '{session.get_udp_proxy()}'")

session.close()

# Split proxy configuration
print("\n" + "=" * 60)
print("Example 3: Split Proxy Configuration (TCP vs UDP)")
print("-" * 60)

print("""
# Use different proxies for HTTP/1.1+HTTP/2 (TCP) and HTTP/3 (UDP):

session = httpcloak.Session(preset="chrome-latest")

# Set TCP proxy for HTTP/1.1 and HTTP/2
session.set_tcp_proxy("http://tcp-proxy.example.com:8080")

# Set UDP proxy for HTTP/3 (requires SOCKS5 with UDP ASSOCIATE or MASQUE)
session.set_udp_proxy("socks5://udp-proxy.example.com:1080")

# Now HTTP/2 requests go through TCP proxy
# and HTTP/3 requests go through UDP proxy

print(f"TCP proxy: {session.get_tcp_proxy()}")
print(f"UDP proxy: {session.get_udp_proxy()}")
""")

# HTTP/3 proxy switching
print("\n" + "=" * 60)
print("Example 4: HTTP/3 Proxy Switching")
print("-" * 60)

print("""
# HTTP/3 requires special proxy support:
# - SOCKS5 with UDP ASSOCIATE (most residential proxies)
# - MASQUE (CONNECT-UDP) - premium providers like Bright Data, Oxylabs

session = httpcloak.Session(preset="chrome-latest", http_version="h3")

# Direct H3 connection
r = session.get("https://example.com")
print(f"Direct: {r.protocol}")

# Switch to SOCKS5 proxy with UDP support
session.set_udp_proxy("socks5://user:pass@proxy.example.com:1080")
r = session.get("https://example.com")
print(f"Via SOCKS5: {r.protocol}")

# Switch to MASQUE proxy
session.set_udp_proxy("https://user:pass@brd.superproxy.io:10001")
r = session.get("https://example.com")
print(f"Via MASQUE: {r.protocol}")
""")

# Proxy rotation pattern
print("\n" + "=" * 60)
print("Example 5: Proxy Rotation Pattern")
print("-" * 60)

print("""
# Rotate through multiple proxies without recreating sessions:

proxies = [
    "http://proxy1.example.com:8080",
    "http://proxy2.example.com:8080",
    "http://proxy3.example.com:8080",
]

session = httpcloak.Session(preset="chrome-latest")

for i, proxy in enumerate(proxies):
    session.set_proxy(proxy)
    r = session.get("https://api.ipify.org")
    print(f"Request {i+1} via {proxy}: IP = {r.text}")

session.close()
""")

print("\n" + "=" * 60)
print("Proxy switching examples completed!")
print("=" * 60)
