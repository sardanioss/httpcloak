#!/usr/bin/env python3
"""
High-Performance Downloads with httpcloak

This example demonstrates the fastest way to download files using httpcloak.

What you'll learn:
- Using get_fast() for maximum download speed
- Buffer pooling and memory efficiency
- When to use get_fast() vs get()
- Best practices for high-throughput scenarios

Performance comparison (100MB local file):
- get():      ~500-1000 MB/s (safe, copies data)
- get_fast(): ~5000 MB/s (zero-copy, uses memoryview)

Requirements:
    pip install httpcloak

Run:
    python 06_fast_downloads.py
"""

import time
import httpcloak

print("=" * 70)
print("httpcloak - High-Performance Downloads with get_fast()")
print("=" * 70)

# =============================================================================
# Understanding get_fast()
# =============================================================================
print("\n[INFO] Understanding get_fast()")
print("-" * 50)
print("""
get_fast() is optimized for maximum download speed by:
1. Using pre-allocated buffer pools (no per-request allocation)
2. Returning memoryview instead of bytes (zero-copy)
3. Minimizing memory allocations

IMPORTANT: The memoryview in response.content may be reused by
subsequent get_fast() calls. Copy if you need to keep the data.
""")

# Create a session for multiple requests
session = httpcloak.Session(preset="chrome-latest")

# =============================================================================
# Example 1: Basic get_fast() Usage
# =============================================================================
print("\n[1] Basic get_fast() Usage")
print("-" * 50)

response = session.get_fast("https://httpbin.org/bytes/10240")

print(f"Status Code: {response.status_code}")
print(f"Protocol: {response.protocol}")
print(f"Content Type: {type(response.content)}")  # memoryview
print(f"Content Length: {len(response.content)} bytes")

# Access the data
first_10_bytes = bytes(response.content[:10])
print(f"First 10 bytes: {first_10_bytes.hex()}")

# =============================================================================
# Example 2: Copy Data If You Need to Keep It
# =============================================================================
print("\n[2] Copy Data If You Need to Keep It")
print("-" * 50)

response = session.get_fast("https://httpbin.org/bytes/1024")

# The memoryview is only valid until the next get_fast() call
# Copy it if you need to keep it
data_copy = bytes(response.content)
print(f"Copied {len(data_copy)} bytes to keep after next request")

# Now make another request - the original memoryview may be reused
response2 = session.get_fast("https://httpbin.org/bytes/1024")

# data_copy is still valid, but response.content from first request is not
print(f"data_copy still valid: {len(data_copy)} bytes")

# =============================================================================
# Example 3: Process In Place (Most Efficient)
# =============================================================================
print("\n[3] Process In Place (Most Efficient)")
print("-" * 50)

response = session.get_fast("https://httpbin.org/json")

# Parse JSON directly from the memoryview (zero-copy)
import json
data = json.loads(response.content)
print(f"Parsed JSON with keys: {list(data.keys())}")

# =============================================================================
# Example 4: Download Speed Comparison
# =============================================================================
print("\n[4] Download Speed Comparison")
print("-" * 50)

# Using a public endpoint for testing
test_url = "https://httpbin.org/bytes/102400"  # 100KB

# Warmup
session.get_fast(test_url)

# Test get_fast()
iterations = 10
total_bytes = 0
start = time.perf_counter()
for _ in range(iterations):
    r = session.get_fast(test_url)
    total_bytes += len(r.content)
elapsed = time.perf_counter() - start

speed_fast = (total_bytes / (1024 * 1024)) / elapsed
print(f"get_fast(): {iterations} requests, {total_bytes/1024:.0f} KB")
print(f"           Time: {elapsed*1000:.0f}ms, Speed: {speed_fast:.1f} MB/s")

# Test regular get()
total_bytes = 0
start = time.perf_counter()
for _ in range(iterations):
    r = session.get(test_url)
    total_bytes += len(r.content)
elapsed = time.perf_counter() - start

speed_regular = (total_bytes / (1024 * 1024)) / elapsed
print(f"get():      {iterations} requests, {total_bytes/1024:.0f} KB")
print(f"           Time: {elapsed*1000:.0f}ms, Speed: {speed_regular:.1f} MB/s")

if speed_fast > speed_regular:
    print(f"\nget_fast() is {speed_fast/speed_regular:.1f}x faster!")

# =============================================================================
# Example 5: When to Use get_fast() vs get()
# =============================================================================
print("\n[5] When to Use get_fast() vs get()")
print("-" * 50)
print("""
USE get_fast() when:
- Downloading large files (>1MB)
- High-throughput scenarios (many requests)
- Processing data immediately (JSON parsing, writing to file)
- Memory efficiency is important

USE get() when:
- You need to store response.content for later
- Making occasional small requests
- Simpler code is preferred
- Thread safety is needed (get() returns independent copy)
""")

# =============================================================================
# Example 6: Writing to File
# =============================================================================
print("\n[6] Writing Downloaded Data to File")
print("-" * 50)

response = session.get_fast("https://httpbin.org/bytes/10240")

# Write directly from memoryview to file (efficient)
import tempfile
import os

with tempfile.NamedTemporaryFile(delete=False) as f:
    f.write(response.content)
    temp_path = f.name

file_size = os.path.getsize(temp_path)
print(f"Wrote {file_size} bytes to {temp_path}")
os.unlink(temp_path)

# =============================================================================
# Example 7: Forced Protocol with get_fast()
# =============================================================================
print("\n[7] get_fast() with Different Protocols")
print("-" * 50)

# Force HTTP/2
session_h2 = httpcloak.Session(preset="chrome-latest", http_version="h2")
response = session_h2.get_fast("https://cloudflare.com/cdn-cgi/trace")
print(f"HTTP/2: {len(response.content)} bytes, protocol: {response.protocol}")
session_h2.close()

# Force HTTP/3 (QUIC)
session_h3 = httpcloak.Session(preset="chrome-latest", http_version="h3")
response = session_h3.get_fast("https://cloudflare.com/cdn-cgi/trace")
print(f"HTTP/3: {len(response.content)} bytes, protocol: {response.protocol}")
session_h3.close()

# =============================================================================
# Cleanup
# =============================================================================
session.close()

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("""
get_fast() provides maximum download performance by:
1. Using pre-allocated buffer pools
2. Returning memoryview (zero-copy)
3. Minimizing memory allocations

Remember:
- Copy data with bytes(response.content) if you need to keep it
- memoryview is reused between calls
- Use for high-throughput and large file scenarios
""")
