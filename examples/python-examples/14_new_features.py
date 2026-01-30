#!/usr/bin/env python3
"""
New Features: Refresh, Local Address Binding, TLS Key Logging

This example demonstrates:
- refresh() - simulate browser page refresh (close connections, keep TLS cache)
- Local Address Binding - bind to specific local IP (IPv4 or IPv6)
- TLS Key Logging - write TLS keys for Wireshark decryption
"""

import os
import httpcloak

TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"


def parse_trace(body):
    """Parse cloudflare trace response."""
    result = {}
    for line in body.strip().split('\n'):
        if '=' in line:
            key, val = line.split('=', 1)
            result[key] = val
    return result


# ==========================================================
# Example 1: Refresh (Browser Page Refresh Simulation)
# ==========================================================
print("=" * 60)
print("Example 1: Refresh (Browser Page Refresh)")
print("-" * 60)

session = httpcloak.Session(preset="chrome-144", timeout=30)

# Make initial request - establishes TLS session
r = session.get(TEST_URL)
trace = parse_trace(r.text)
print(f"First request: Protocol={r.protocol}, IP={trace.get('ip', 'N/A')}")

# Simulate browser refresh (F5)
# This closes TCP/QUIC connections but keeps TLS session cache
session.refresh()
print("Called refresh() - connections closed, TLS cache kept")

# Next request uses TLS resumption (faster handshake)
r = session.get(TEST_URL)
trace = parse_trace(r.text)
print(f"After refresh: Protocol={r.protocol}, IP={trace.get('ip', 'N/A')} (TLS resumption)")

session.close()


# ==========================================================
# Example 2: TLS Key Logging
# ==========================================================
print("\n" + "=" * 60)
print("Example 2: TLS Key Logging")
print("-" * 60)

keylog_path = "/tmp/python_keylog_example.txt"

# Remove old keylog file
if os.path.exists(keylog_path):
    os.remove(keylog_path)

# Create session with key logging enabled
session = httpcloak.Session(
    preset="chrome-144",
    timeout=30,
    key_log_file=keylog_path
)

# Make request - TLS keys written to file
r = session.get(TEST_URL)
print(f"Request completed: Protocol={r.protocol}")

session.close()

# Check if keylog file was created
if os.path.exists(keylog_path):
    size = os.path.getsize(keylog_path)
    print(f"Key log file created: {keylog_path} ({size} bytes)")
    print("Use in Wireshark: Edit -> Preferences -> Protocols -> TLS -> Pre-Master-Secret log filename")
else:
    print("Key log file not found")


# ==========================================================
# Example 3: Local Address Binding
# ==========================================================
print("\n" + "=" * 60)
print("Example 3: Local Address Binding")
print("-" * 60)

print("""
Local address binding allows you to specify which local IP to use
for outgoing connections. This is essential for IPv6 rotation scenarios.

Usage:

# Bind to specific IPv6 address
session = httpcloak.Session(
    preset="chrome-144",
    local_address="2001:db8::1"
)

# Bind to specific IPv4 address
session = httpcloak.Session(
    preset="chrome-144",
    local_address="192.168.1.100"
)

Note: When local address is set, target IPs are filtered to match
the address family (IPv6 local -> only connects to IPv6 targets).

Example with your machine's IPs:
""")

# This is a demonstration - replace with actual local IP
# Uncomment to test with your real IPv6/IPv4:
#
# session = httpcloak.Session(
#     preset="chrome-144",
#     local_address="YOUR_LOCAL_IP_HERE",
#     timeout=30
# )
#
# r = session.get("https://api.ipify.org")
# print(f"Server saw IP: {r.text}")
# session.close()


print("\n" + "=" * 60)
print("New features examples completed!")
print("=" * 60)
