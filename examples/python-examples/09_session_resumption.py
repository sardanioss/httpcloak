#!/usr/bin/env python3
"""
Session Resumption (0-RTT)

This example demonstrates TLS session resumption which dramatically
improves bot detection scores by making connections look like
returning visitors rather than new connections.

Key concepts:
- First connection: Bot score ~43 (new TLS handshake)
- Resumed connection: Bot score ~99 (looks like returning visitor)
- Cross-domain warming: Session tickets work across same-infrastructure sites
"""

import httpcloak
import os

# =============================================================================
# Example 1: Basic Session Save/Load (File-based)
# =============================================================================
print("=" * 60)
print("Example 1: Save and Load Session (File)")
print("-" * 60)

SESSION_FILE = "session_state.json"

# Check if we have a saved session
if os.path.exists(SESSION_FILE):
    print("Loading existing session...")
    session = httpcloak.Session.load(SESSION_FILE)
    print("Session loaded with TLS tickets!")
else:
    print("Creating new session...")
    session = httpcloak.Session(preset="chrome-143")

    # Warm up - this acquires TLS session tickets
    print("Warming up session...")
    r = session.get("https://cloudflare.com/cdn-cgi/trace")
    print(f"Warmup complete - Protocol: {r.protocol}")

# Make request (will use 0-RTT if session was loaded)
r = session.get("https://www.cloudflare.com/cdn-cgi/trace")
print(f"Request - Protocol: {r.protocol}")

# Save session for next run
session.save(SESSION_FILE)
print(f"Session saved to {SESSION_FILE}")
session.close()

# =============================================================================
# Example 2: Marshal/Unmarshal (For databases, Redis, etc.)
# =============================================================================
print("\n" + "=" * 60)
print("Example 2: Marshal/Unmarshal Session (String)")
print("-" * 60)

# Create and warm up session
session = httpcloak.Session(preset="chrome-143")
session.get("https://cloudflare.com/")

# Export to JSON string (store in Redis, database, etc.)
session_data = session.marshal()
print(f"Marshaled session: {len(session_data)} bytes")
session.close()

# Later: restore from string
restored = httpcloak.Session.unmarshal(session_data)
r = restored.get("https://www.cloudflare.com/cdn-cgi/trace")
print(f"Restored session request - Protocol: {r.protocol}")
restored.close()

# =============================================================================
# Example 3: Cross-Domain Session Warming (Cloudflare)
# =============================================================================
print("\n" + "=" * 60)
print("Example 3: Cross-Domain Warming")
print("-" * 60)

session = httpcloak.Session(preset="chrome-143")

# Warm up on cloudflare.com (safe, no bot detection)
print("Warming up on cloudflare.com...")
r = session.get("https://cloudflare.com/cdn-cgi/trace")
print(f"Warmup - Protocol: {r.protocol}")

# The TLS session ticket works on OTHER Cloudflare sites!
# This is because they share infrastructure/IPs
print("\nUsing warmed session on cf.erisa.uk (CF-protected)...")
r = session.get("https://cf.erisa.uk/")
data = r.json()
bot_score = data.get("botManagement", {}).get("score", "N/A")
print(f"Bot Score: {bot_score}")
print(f"Protocol: {r.protocol}")

session.close()

# =============================================================================
# Example 4: Session Warming Best Practice
# =============================================================================
print("\n" + "=" * 60)
print("Example 4: Production Pattern")
print("-" * 60)

def get_or_create_session(session_key: str) -> httpcloak.Session:
    """
    Get existing session or create and warm up a new one.
    In production, you'd use Redis/database instead of files.
    """
    session_file = f"{session_key}.json"

    if os.path.exists(session_file):
        return httpcloak.Session.load(session_file)

    # Create new session and warm it up
    session = httpcloak.Session(preset="chrome-143")

    # Warm up on a neutral Cloudflare endpoint
    session.get("https://cloudflare.com/cdn-cgi/trace")

    # Save for future use
    session.save(session_file)

    return session

# Usage
session = get_or_create_session("my_scraper")
r = session.get("https://cf.erisa.uk/")
print(f"Bot Score: {r.json().get('botManagement', {}).get('score')}")
session.close()

# Cleanup example files
for f in [SESSION_FILE, "my_scraper.json"]:
    if os.path.exists(f):
        os.remove(f)

print("\n" + "=" * 60)
print("Session resumption examples completed!")
print("=" * 60)
