#!/usr/bin/env python3
"""
QUIC Idle Timeout Configuration

This example demonstrates:
- Configuring QUIC idle timeout for HTTP/3 connections
- Preventing connection drops on long-lived idle connections
- When to use higher idle timeouts

By default, QUIC connections have a 30-second idle timeout. If your application
keeps connections open for longer periods without activity (e.g., connection pooling,
long polling), you may need to increase this value.

The keepalive is automatically set to half of the idle timeout to prevent
connection closure.
"""

import httpcloak
import time

print("=" * 60)
print("QUIC Idle Timeout Configuration Examples")
print("=" * 60)

# Example 1: Default QUIC idle timeout (30 seconds)
print("\n[Example 1] Default QUIC Idle Timeout")
print("-" * 50)

session = httpcloak.Session(
    preset="chrome-latest",
    http_version="h3"  # Force HTTP/3 to use QUIC
)

response = session.get("https://cloudflare.com")
print(f"Status: {response.status_code}")
print(f"Protocol: {response.protocol}")
print("Default idle timeout: 30 seconds")
print("Default keepalive: 15 seconds (half of idle timeout)")

session.close()

# Example 2: Extended QUIC idle timeout for long-lived connections
print("\n[Example 2] Extended QUIC Idle Timeout (2 minutes)")
print("-" * 50)

session = httpcloak.Session(
    preset="chrome-latest",
    http_version="h3",
    quic_idle_timeout=120  # 2 minutes
)

response = session.get("https://cloudflare.com")
print(f"Status: {response.status_code}")
print(f"Protocol: {response.protocol}")
print("Custom idle timeout: 120 seconds")
print("Custom keepalive: 60 seconds (half of idle timeout)")

# Simulate idle period
print("\nSimulating 5 second idle period...")
time.sleep(5)

# Connection should still be alive
response = session.get("https://cloudflare.com")
print(f"After idle - Status: {response.status_code}, Protocol: {response.protocol}")

session.close()

# Example 3: Very long idle timeout for persistent connections
print("\n[Example 3] Very Long Idle Timeout (5 minutes)")
print("-" * 50)

session = httpcloak.Session(
    preset="chrome-latest",
    http_version="h3",
    quic_idle_timeout=300  # 5 minutes
)

response = session.get("https://cloudflare.com")
print(f"Status: {response.status_code}")
print(f"Protocol: {response.protocol}")
print("Custom idle timeout: 300 seconds (5 minutes)")
print("Custom keepalive: 150 seconds (2.5 minutes)")

session.close()

# Example 4: Combined with other session options
print("\n[Example 4] Combined with Other Options")
print("-" * 50)

session = httpcloak.Session(
    preset="chrome-latest",
    http_version="h3",
    quic_idle_timeout=180,  # 3 minutes
    timeout=60,             # Request timeout
    retry=3                 # Retry count
)

response = session.get("https://cloudflare.com")
print(f"Status: {response.status_code}")
print(f"Protocol: {response.protocol}")
print("QUIC idle timeout: 180s, Request timeout: 60s, Retries: 3")

session.close()

# Usage guidance
print("\n" + "=" * 60)
print("When to Adjust QUIC Idle Timeout")
print("=" * 60)

print("""
Use HIGHER idle timeout (60-300s) when:
  - Your app keeps connections pooled for reuse
  - Making periodic requests with gaps > 30 seconds
  - Using long polling or server-sent events over HTTP/3
  - Experiencing "connection closed" errors after idle periods

Use DEFAULT idle timeout (30s) when:
  - Making quick, one-off requests
  - Request patterns have < 30 second gaps
  - Memory is constrained (longer timeouts = more memory)

Note: The keepalive is automatically set to half of idle timeout.
This ensures keepalive packets are sent before the connection
would otherwise be closed due to inactivity.
""")

print("=" * 60)
print("QUIC idle timeout examples completed!")
print("=" * 60)
