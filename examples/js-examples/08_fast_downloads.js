/**
 * High-Performance Downloads with httpcloak
 *
 * This example demonstrates the fastest way to download files using httpcloak.
 *
 * What you'll learn:
 * - Using getFast() for maximum download speed
 * - Buffer pooling and memory efficiency
 * - Releasing buffers back to pool
 * - When to use getFast() vs get()
 *
 * Performance comparison (100MB local file):
 * - get():     ~30-50 MB/s (async, creates new buffers)
 * - getFast(): ~2000+ MB/s (sync, uses SharedArrayBuffer pool)
 *
 * Requirements:
 *   npm install httpcloak
 *
 * Run:
 *   node 08_fast_downloads.js
 */

const httpcloak = require("httpcloak");

function main() {
  console.log("=".repeat(70));
  console.log("httpcloak - High-Performance Downloads with getFast()");
  console.log("=".repeat(70));

  // ===========================================================================
  // Understanding getFast()
  // ===========================================================================
  console.log("\n[INFO] Understanding getFast()");
  console.log("-".repeat(50));
  console.log(`
getFast() is optimized for maximum download speed by:
1. Using pre-allocated SharedArrayBuffer (256MB pool)
2. Synchronous execution (no async overhead)
3. Minimizing memory allocations

IMPORTANT: Call response.release() when done to return the buffer
to the pool for reuse. After release(), response.body is invalid.
`);

  // Create a session for multiple requests
  const session = new httpcloak.Session({ preset: "chrome-latest" });

  // ===========================================================================
  // Example 1: Basic getFast() Usage
  // ===========================================================================
  console.log("\n[1] Basic getFast() Usage");
  console.log("-".repeat(50));

  let response = session.getFast("https://httpbin.org/bytes/10240");

  console.log(`Status Code: ${response.statusCode}`);
  console.log(`Protocol: ${response.protocol}`);
  console.log(`Body Type: ${response.body.constructor.name}`);
  console.log(`Body Length: ${response.body.length} bytes`);

  // Access the data
  const first10Bytes = response.body.slice(0, 10);
  console.log(`First 10 bytes: ${first10Bytes.toString("hex")}`);

  // IMPORTANT: Release the buffer back to pool when done
  response.release();
  console.log("Buffer released to pool");

  // ===========================================================================
  // Example 2: Copy Data If You Need to Keep It
  // ===========================================================================
  console.log("\n[2] Copy Data If You Need to Keep It");
  console.log("-".repeat(50));

  response = session.getFast("https://httpbin.org/bytes/1024");

  // The buffer is only valid until release() or next getFast() reuses it
  // Copy it if you need to keep it
  const dataCopy = Buffer.from(response.body);
  console.log(`Copied ${dataCopy.length} bytes to keep after release`);

  // Now release - original buffer may be reused
  response.release();

  // dataCopy is still valid
  console.log(`dataCopy still valid: ${dataCopy.length} bytes`);

  // ===========================================================================
  // Example 3: Process In Place (Most Efficient)
  // ===========================================================================
  console.log("\n[3] Process In Place (Most Efficient)");
  console.log("-".repeat(50));

  response = session.getFast("https://httpbin.org/json");

  // Parse JSON directly from the buffer (zero-copy)
  const data = JSON.parse(response.body.toString());
  console.log(`Parsed JSON with keys: ${Object.keys(data).join(", ")}`);

  // Release after processing
  response.release();

  // ===========================================================================
  // Example 4: Download Speed Benchmark
  // ===========================================================================
  console.log("\n[4] Download Speed Benchmark");
  console.log("-".repeat(50));

  const testUrl = "https://httpbin.org/bytes/102400"; // 100KB

  // Warmup
  session.getFast(testUrl).release();

  // Test getFast() - synchronous
  const iterations = 10;
  let totalBytes = 0;
  let start = performance.now();

  for (let i = 0; i < iterations; i++) {
    const r = session.getFast(testUrl);
    totalBytes += r.body.length;
    r.release();
  }

  let elapsed = (performance.now() - start) / 1000;
  const speedFast = totalBytes / (1024 * 1024) / elapsed;
  console.log(`getFast(): ${iterations} requests, ${(totalBytes / 1024).toFixed(0)} KB`);
  console.log(`           Time: ${(elapsed * 1000).toFixed(0)}ms, Speed: ${speedFast.toFixed(1)} MB/s`);

  // ===========================================================================
  // Example 5: When to Use getFast() vs get()
  // ===========================================================================
  console.log("\n[5] When to Use getFast() vs get()");
  console.log("-".repeat(50));
  console.log(`
USE getFast() when:
- Downloading large files (>1MB)
- High-throughput scenarios (many sequential requests)
- Processing data immediately (JSON parsing, file writing)
- Memory efficiency is important
- Synchronous execution is acceptable

USE get() when:
- Making concurrent requests (async/await)
- You need promises/async patterns
- Thread safety is needed
- Simpler code is preferred
`);

  // ===========================================================================
  // Example 6: Writing to File
  // ===========================================================================
  console.log("\n[6] Writing Downloaded Data to File");
  console.log("-".repeat(50));

  const fs = require("fs");
  const os = require("os");
  const path = require("path");

  response = session.getFast("https://httpbin.org/bytes/10240");

  // Write directly from buffer to file (efficient)
  const tempPath = path.join(os.tmpdir(), "httpcloak_test.bin");
  fs.writeFileSync(tempPath, response.body);

  const fileSize = fs.statSync(tempPath).size;
  console.log(`Wrote ${fileSize} bytes to ${tempPath}`);

  response.release();
  fs.unlinkSync(tempPath);

  // ===========================================================================
  // Example 7: getFast() with Different Protocols
  // ===========================================================================
  console.log("\n[7] getFast() with Different Protocols");
  console.log("-".repeat(50));

  // Force HTTP/2
  const sessionH2 = new httpcloak.Session({ preset: "chrome-latest", httpVersion: "h2" });
  response = sessionH2.getFast("https://cloudflare.com/cdn-cgi/trace");
  console.log(`HTTP/2: ${response.body.length} bytes, protocol: ${response.protocol}`);
  response.release();
  sessionH2.close();

  // Force HTTP/3 (QUIC)
  const sessionH3 = new httpcloak.Session({ preset: "chrome-latest", httpVersion: "h3" });
  response = sessionH3.getFast("https://cloudflare.com/cdn-cgi/trace");
  console.log(`HTTP/3: ${response.body.length} bytes, protocol: ${response.protocol}`);
  response.release();
  sessionH3.close();

  // ===========================================================================
  // Cleanup
  // ===========================================================================
  session.close();

  console.log("\n" + "=".repeat(70));
  console.log("SUMMARY");
  console.log("=".repeat(70));
  console.log(`
getFast() provides maximum download performance by:
1. Using pre-allocated SharedArrayBuffer pool (256MB)
2. Synchronous execution (no async overhead)
3. Minimizing memory allocations

Remember:
- ALWAYS call response.release() when done
- Copy data with Buffer.from(response.body) if you need to keep it
- Buffer is reused after release()
- Use for high-throughput and large file scenarios
`);
}

main();
