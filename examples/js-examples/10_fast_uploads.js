/**
 * High-Performance Uploads with httpcloak
 *
 * This example demonstrates the fastest way to upload data using httpcloak.
 *
 * What you'll learn:
 * - Using postFast() for maximum upload speed
 * - Binary buffer handling for uploads
 * - When to use postFast() vs post()
 *
 * Performance (10MB local upload):
 * - post():     ~100-300 MB/s (converts to string)
 * - postFast(): ~1500-2000 MB/s (binary buffer)
 *
 * Requirements:
 *   npm install httpcloak
 *
 * Run:
 *   node 10_fast_uploads.js
 */

const httpcloak = require("httpcloak");
const fs = require("fs");

function main() {
  console.log("=".repeat(70));
  console.log("httpcloak - High-Performance Uploads with postFast()");
  console.log("=".repeat(70));

  // ===========================================================================
  // Understanding postFast()
  // ===========================================================================
  console.log("\n[INFO] Understanding postFast()");
  console.log("-".repeat(50));
  console.log(`
postFast() is optimized for maximum upload speed by:
1. Passing binary Buffer directly to native code (no string conversion)
2. Using response buffer pooling for the response
3. Minimizing FFI overhead

IMPORTANT: Call response.release() when done to return response
buffers to the pool.
`);

  const session = new httpcloak.Session({ preset: "chrome-latest" });

  // ===========================================================================
  // Example 1: Basic postFast() Usage
  // ===========================================================================
  console.log("\n[1] Basic postFast() Usage");
  console.log("-".repeat(50));

  // Create test data
  const testData = Buffer.alloc(1024);
  for (let i = 0; i < testData.length; i++) {
    testData[i] = i % 256;
  }

  const response = session.postFast("https://httpbin.org/post", {
    body: testData,
    headers: { "Content-Type": "application/octet-stream" }
  });

  console.log(`Status Code: ${response.statusCode}`);
  console.log(`Protocol: ${response.protocol}`);
  console.log(`Response size: ${response.body.length} bytes`);
  response.release();

  // ===========================================================================
  // Example 2: Upload JSON Data
  // ===========================================================================
  console.log("\n[2] Upload JSON Data");
  console.log("-".repeat(50));

  const jsonData = JSON.stringify({
    name: "httpcloak",
    version: "1.5.0",
    features: ["fast-uploads", "buffer-pooling"]
  });

  const jsonResponse = session.postFast("https://httpbin.org/post", {
    body: Buffer.from(jsonData),
    headers: { "Content-Type": "application/json" }
  });

  console.log(`Status: ${jsonResponse.statusCode}`);
  const responseData = JSON.parse(jsonResponse.body.toString());
  console.log(`Server received JSON: ${responseData.data}`);
  jsonResponse.release();

  // ===========================================================================
  // Example 3: Upload Speed Comparison
  // ===========================================================================
  console.log("\n[3] Upload Speed Comparison");
  console.log("-".repeat(50));

  // Create 1MB test data
  const largeData = Buffer.alloc(1024 * 1024);
  for (let i = 0; i < largeData.length; i++) {
    largeData[i] = i % 256;
  }

  // Test postFast()
  console.log("Testing postFast() with 1MB data to httpbin.org...");
  const iterations = 3;
  let totalTime = 0;

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    const r = session.postFast("https://httpbin.org/post", {
      body: largeData,
      headers: { "Content-Type": "application/octet-stream" }
    });
    const elapsed = performance.now() - start;
    totalTime += elapsed;
    console.log(`  Run ${i + 1}: ${elapsed.toFixed(0)}ms`);
    r.release();
  }

  console.log(`  Average: ${(totalTime / iterations).toFixed(0)}ms`);

  // ===========================================================================
  // Example 4: When to Use postFast() vs post()
  // ===========================================================================
  console.log("\n[4] When to Use postFast() vs post()");
  console.log("-".repeat(50));
  console.log(`
USE postFast() when:
- Uploading large binary data (>100KB)
- High-throughput scenarios (many uploads)
- Performance is critical
- You have data as a Buffer

USE post() when:
- Uploading JSON (use json: option)
- Uploading form data (use data: option)
- Uploading files with multipart (use files: option)
- Simpler async/await patterns needed
`);

  // ===========================================================================
  // Example 5: File Upload
  // ===========================================================================
  console.log("\n[5] File Upload Pattern");
  console.log("-".repeat(50));
  console.log(`
To upload a file efficiently:

  const fileData = fs.readFileSync("large-file.bin");
  const response = session.postFast("https://example.com/upload", {
    body: fileData,
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Filename": "large-file.bin"
    }
  });
  response.release();
`);

  // ===========================================================================
  // Example 6: Different Protocols
  // ===========================================================================
  console.log("\n[6] postFast() with Different Protocols");
  console.log("-".repeat(50));

  const smallData = Buffer.from("test upload data");

  // HTTP/2
  const sessionH2 = new httpcloak.Session({ preset: "chrome-latest", httpVersion: "h2" });
  let r = sessionH2.postFast("https://httpbin.org/post", { body: smallData });
  console.log(`HTTP/2 upload: ${r.statusCode}, protocol: ${r.protocol}`);
  r.release();
  sessionH2.close();

  // HTTP/3
  const sessionH3 = new httpcloak.Session({ preset: "chrome-latest", httpVersion: "h3" });
  r = sessionH3.postFast("https://cloudflare.com/cdn-cgi/trace", { body: smallData });
  console.log(`HTTP/3 upload: ${r.statusCode}, protocol: ${r.protocol}`);
  r.release();
  sessionH3.close();

  // ===========================================================================
  // Cleanup
  // ===========================================================================
  session.close();

  console.log("\n" + "=".repeat(70));
  console.log("SUMMARY");
  console.log("=".repeat(70));
  console.log(`
postFast() provides maximum upload performance by:
1. Passing binary Buffer directly (no string conversion)
2. Using response buffer pooling
3. Minimizing FFI overhead

Remember:
- Pass body as Buffer for best performance
- ALWAYS call response.release() when done
- Use for large uploads and high-throughput scenarios
`);
}

main();
