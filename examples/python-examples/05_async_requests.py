#!/usr/bin/env python3
"""
Async Requests

This example demonstrates:
- Async GET and POST requests
- Concurrent requests with asyncio
"""

import asyncio
import httpcloak

async def main():
    print("=" * 60)
    print("Example 1: Basic Async Requests")
    print("-" * 60)

    session = httpcloak.Session(preset="chrome-latest")

    # Async GET
    r = await session.get_async("https://httpbin.org/get")
    print(f"Async GET - Status: {r.status_code}, Protocol: {r.protocol}")

    # Async POST
    r = await session.post_async(
        "https://httpbin.org/post",
        json={"async": True, "message": "Hello from async!"}
    )
    print(f"Async POST - Status: {r.status_code}")

    session.close()

    # Concurrent requests
    print("\n" + "=" * 60)
    print("Example 2: Concurrent Requests")
    print("-" * 60)

    session = httpcloak.Session(preset="chrome-latest")

    urls = [
        "https://httpbin.org/get",
        "https://httpbin.org/headers",
        "https://httpbin.org/user-agent",
        "https://httpbin.org/ip",
    ]

    # Create tasks for concurrent execution
    tasks = [session.get_async(url) for url in urls]

    # Wait for all requests to complete
    print("Fetching 4 URLs concurrently...")
    responses = await asyncio.gather(*tasks)

    for url, r in zip(urls, responses):
        endpoint = url.split("/")[-1]
        print(f"  {endpoint:15} - Status: {r.status_code}")

    session.close()

    # Sequential vs concurrent timing comparison
    print("\n" + "=" * 60)
    print("Example 3: Sequential vs Concurrent Timing")
    print("-" * 60)

    session = httpcloak.Session(preset="chrome-latest")
    test_urls = ["https://httpbin.org/delay/1"] * 3

    # Sequential
    import time
    start = time.time()
    for url in test_urls:
        await session.get_async(url)
    sequential_time = time.time() - start
    print(f"Sequential (3 requests): {sequential_time:.2f}s")

    # Concurrent
    start = time.time()
    tasks = [session.get_async(url) for url in test_urls]
    await asyncio.gather(*tasks)
    concurrent_time = time.time() - start
    print(f"Concurrent (3 requests): {concurrent_time:.2f}s")

    print(f"Speedup: {sequential_time / concurrent_time:.1f}x faster")

    session.close()

    print("\n" + "=" * 60)
    print("Async examples completed!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
