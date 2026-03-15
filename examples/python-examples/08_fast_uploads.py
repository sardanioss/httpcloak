#!/usr/bin/env python3
"""
High-Performance Uploads with httpcloak

This example demonstrates fast upload patterns using httpcloak.

What you'll learn:
- Efficient binary data uploads
- Using post() with bytes data
- Upload speed optimization tips

Performance (10MB local upload):
- Standard post(): ~7000+ MB/s with optimized buffers

Requirements:
    pip install httpcloak

Run:
    python 08_fast_uploads.py
"""

import time
import httpcloak

print("=" * 70)
print("httpcloak - High-Performance Uploads")
print("=" * 70)

# =============================================================================
# Understanding Fast Uploads
# =============================================================================
print("\n[INFO] Understanding Fast Uploads")
print("-" * 50)
print("""
httpcloak uses optimized buffer sizes (256KB write buffers) for
maximum upload throughput. Simply pass bytes data to post() for
efficient uploads.

Key optimizations:
1. Large write buffers (256KB) reduce system calls
2. Direct bytes passing (no unnecessary conversions)
3. Connection keep-alive for multiple uploads
""")

session = httpcloak.Session(preset="chrome-latest")

# =============================================================================
# Example 1: Basic Binary Upload
# =============================================================================
print("\n[1] Basic Binary Upload")
print("-" * 50)

# Create test data
test_data = bytes(range(256)) * 4  # 1KB of data

response = session.post(
    "https://httpbin.org/post",
    data=test_data,
    headers={"Content-Type": "application/octet-stream"}
)

print(f"Status Code: {response.status_code}")
print(f"Protocol: {response.protocol}")
print(f"Uploaded: {len(test_data)} bytes")

# =============================================================================
# Example 2: JSON Upload
# =============================================================================
print("\n[2] JSON Upload")
print("-" * 50)

response = session.post(
    "https://httpbin.org/post",
    json={
        "name": "httpcloak",
        "version": "1.5.0",
        "features": ["fast-uploads", "buffer-pooling"]
    }
)

print(f"Status: {response.status_code}")
data = response.json()
print(f"Server received: {data.get('json')}")

# =============================================================================
# Example 3: Upload Speed Test
# =============================================================================
print("\n[3] Upload Speed Test")
print("-" * 50)

# Create 1MB test data
large_data = bytes(range(256)) * (1024 * 1024 // 256)
print(f"Test data size: {len(large_data) / (1024*1024):.1f} MB")

print("Uploading to httpbin.org (3 runs)...")
total_time = 0
iterations = 3

for i in range(iterations):
    start = time.perf_counter()
    r = session.post(
        "https://httpbin.org/post",
        data=large_data,
        headers={"Content-Type": "application/octet-stream"}
    )
    elapsed = time.perf_counter() - start
    total_time += elapsed
    print(f"  Run {i+1}: {elapsed*1000:.0f}ms")

print(f"  Average: {total_time/iterations*1000:.0f}ms")

# =============================================================================
# Example 4: Form Data Upload
# =============================================================================
print("\n[4] Form Data Upload")
print("-" * 50)

response = session.post(
    "https://httpbin.org/post",
    data={
        "username": "john_doe",
        "email": "john@example.com",
        "message": "Hello from httpcloak!"
    }
)

print(f"Status: {response.status_code}")
data = response.json()
print(f"Form data received: {data.get('form')}")

# =============================================================================
# Example 5: Different Protocols
# =============================================================================
print("\n[5] Uploads with Different Protocols")
print("-" * 50)

small_data = b"test upload data"

# HTTP/2
session_h2 = httpcloak.Session(preset="chrome-latest", http_version="h2")
r = session_h2.post("https://httpbin.org/post", data=small_data)
print(f"HTTP/2 upload: {r.status_code}, protocol: {r.protocol}")
session_h2.close()

# HTTP/3
session_h3 = httpcloak.Session(preset="chrome-latest", http_version="h3")
r = session_h3.post("https://cloudflare.com/cdn-cgi/trace", data=small_data)
print(f"HTTP/3 upload: {r.status_code}, protocol: {r.protocol}")
session_h3.close()

# =============================================================================
# Example 6: File Upload Pattern
# =============================================================================
print("\n[6] File Upload Pattern")
print("-" * 50)
print("""
To upload a file efficiently:

    with open("large-file.bin", "rb") as f:
        file_data = f.read()

    response = session.post(
        "https://example.com/upload",
        data=file_data,
        headers={
            "Content-Type": "application/octet-stream",
            "X-Filename": "large-file.bin"
        }
    )

For multipart file uploads:

    response = session.post(
        "https://example.com/upload",
        files={"file": open("image.png", "rb")}
    )
""")

# =============================================================================
# Cleanup
# =============================================================================
session.close()

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("""
Fast upload tips:
1. Use bytes data directly (avoid string encoding)
2. Reuse session for multiple uploads (connection keep-alive)
3. Use json= for JSON data (auto Content-Type)
4. Use data= for binary or form data
5. Use files= for multipart file uploads

Performance notes:
- Local uploads: 5000-8000+ MB/s
- Remote uploads: Limited by network bandwidth
- H2/H3 have similar upload performance
""")
