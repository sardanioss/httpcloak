#!/usr/bin/env python3
"""
Streaming Downloads with httpcloak

This example demonstrates how to stream large files without loading
them entirely into memory.

What you'll learn:
- Using get_stream() for memory-efficient downloads
- Reading response data in chunks with iter_content()
- Progress tracking during downloads
- When to use streaming vs get_fast()

Use Cases:
- Downloading files larger than available memory
- Progress bars for large downloads
- Processing data as it arrives
- Piping data to another destination

Requirements:
    pip install httpcloak

Run:
    python 07_streaming.py
"""

import httpcloak
import time
import sys

print("=" * 70)
print("httpcloak - Streaming Downloads")
print("=" * 70)

# =============================================================================
# Understanding Streaming
# =============================================================================
print("\n[INFO] Understanding Streaming")
print("-" * 50)
print("""
Streaming allows you to process response data as it arrives,
without loading the entire response into memory.

Use streaming when:
- File is larger than available memory
- You want to show download progress
- Processing data incrementally (parsing, transforming)
- Writing to disk as data arrives
""")

session = httpcloak.Session(preset="chrome-143")

# =============================================================================
# Example 1: Basic Streaming with iter_content()
# =============================================================================
print("\n[1] Basic Streaming with iter_content()")
print("-" * 50)

# Start a streaming request
stream = session.get_stream("https://httpbin.org/bytes/102400")

print(f"Status Code: {stream.status_code}")
print(f"Protocol: {stream.protocol}")
print(f"Content-Length: {stream.content_length}")

# Read data in chunks using iter_content()
total_bytes = 0
chunk_count = 0
for chunk in stream.iter_content(chunk_size=8192):
    total_bytes += len(chunk)
    chunk_count += 1

stream.close()
print(f"Read {total_bytes} bytes in {chunk_count} chunks")

# =============================================================================
# Example 2: Download with Progress
# =============================================================================
print("\n[2] Download with Progress")
print("-" * 50)

stream = session.get_stream("https://httpbin.org/bytes/51200")
content_length = stream.content_length
downloaded = 0

print(f"Downloading {content_length} bytes...")
start_time = time.perf_counter()

for chunk in stream.iter_content(chunk_size=4096):
    downloaded += len(chunk)

    # Calculate progress
    if content_length > 0:
        percent = (downloaded / content_length) * 100
        bar_width = 40
        filled = int(bar_width * downloaded / content_length)
        bar = "=" * filled + "-" * (bar_width - filled)
        sys.stdout.write(f"\r[{bar}] {percent:.1f}%")
        sys.stdout.flush()

elapsed = time.perf_counter() - start_time
stream.close()

print(f"\nCompleted: {downloaded} bytes in {elapsed*1000:.0f}ms")

# =============================================================================
# Example 3: Stream to File
# =============================================================================
print("\n[3] Stream to File")
print("-" * 50)

import tempfile
import os

stream = session.get_stream("https://httpbin.org/bytes/102400")

with tempfile.NamedTemporaryFile(delete=False) as f:
    temp_path = f.name
    bytes_written = 0

    for chunk in stream.iter_content(chunk_size=16384):
        f.write(chunk)
        bytes_written += len(chunk)

stream.close()

file_size = os.path.getsize(temp_path)
print(f"Streamed {bytes_written} bytes to file")
print(f"File size on disk: {file_size} bytes")
os.unlink(temp_path)

# =============================================================================
# Example 4: Using Context Manager
# =============================================================================
print("\n[4] Using Context Manager")
print("-" * 50)

# StreamResponse supports context manager for automatic cleanup
with session.get_stream("https://httpbin.org/bytes/32768") as stream:
    chunks = list(stream.iter_content(chunk_size=8192))
    print(f"Received {len(chunks)} chunks")
    print(f"Total bytes: {sum(len(c) for c in chunks)}")
# Stream is automatically closed here

# =============================================================================
# Example 5: Streaming with Different Protocols
# =============================================================================
print("\n[5] Streaming with Different Protocols")
print("-" * 50)

# HTTP/2 streaming
session_h2 = httpcloak.Session(preset="chrome-143", http_version="h2")
with session_h2.get_stream("https://cloudflare.com/cdn-cgi/trace") as stream:
    data = b"".join(stream.iter_content(chunk_size=1024))
    print(f"HTTP/2 stream: {len(data)} bytes, protocol: {stream.protocol}")
session_h2.close()

# HTTP/3 streaming
session_h3 = httpcloak.Session(preset="chrome-143", http_version="h3")
with session_h3.get_stream("https://cloudflare.com/cdn-cgi/trace") as stream:
    data = b"".join(stream.iter_content(chunk_size=1024))
    print(f"HTTP/3 stream: {len(data)} bytes, protocol: {stream.protocol}")
session_h3.close()

# =============================================================================
# Example 6: Streaming Lines (for text responses)
# =============================================================================
print("\n[6] Streaming Lines")
print("-" * 50)

with session.get_stream("https://httpbin.org/robots.txt") as stream:
    print("Reading lines from robots.txt:")
    line_count = 0
    for line in stream.iter_lines():
        if line:  # Skip empty lines
            print(f"  {line}")
            line_count += 1
    print(f"Total lines: {line_count}")

# =============================================================================
# Example 7: When to Use Streaming vs get_fast()
# =============================================================================
print("\n[7] Streaming vs get_fast() Comparison")
print("-" * 50)
print("""
STREAMING (get_stream):
- Memory efficient - only holds one chunk at a time
- Good for files larger than RAM
- Enables progress tracking
- Slower due to chunk-by-chunk processing

get_fast():
- Fastest download speed
- Loads entire response into memory
- Best for files that fit in memory
- ~10-50x faster than streaming for small/medium files

RECOMMENDATIONS:
- Files < 100MB: Use get_fast()
- Files > 100MB or unknown size: Use streaming
- Need progress bar: Use streaming
- Memory constrained: Use streaming
""")

# =============================================================================
# Cleanup
# =============================================================================
session.close()

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("""
Streaming methods:
- session.get_stream(url) - Start streaming GET request
- session.post_stream(url, data) - Start streaming POST request
- session.put_stream(url, data) - Start streaming PUT request
- session.delete_stream(url) - Start streaming DELETE request
- session.patch_stream(url, data) - Start streaming PATCH request
- session.request_stream(method, url) - Generic streaming request

StreamResponse methods:
- stream.iter_content(chunk_size) - Iterate over chunks (bytes)
- stream.iter_lines(chunk_size) - Iterate over lines (strings)
- stream.close() - Close the stream

StreamResponse properties:
- stream.status_code - HTTP status code
- stream.headers - Response headers
- stream.content_length - Total size (if known, -1 otherwise)
- stream.protocol - HTTP protocol used (h2, h3, etc.)
- stream.url - Final URL after redirects
- stream.cookies - Cookies from response
- stream.ok - True if status < 400
- stream.reason - HTTP status reason phrase
- stream.encoding - Content encoding from headers
""")
