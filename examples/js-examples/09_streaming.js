/**
 * Streaming Downloads with httpcloak
 *
 * This example demonstrates how to stream large files without loading
 * them entirely into memory.
 *
 * What you'll learn:
 * - Using getStream() for memory-efficient downloads
 * - Reading response data in chunks
 * - Progress tracking during downloads
 * - Async iteration patterns
 *
 * Use Cases:
 * - Downloading files larger than available memory
 * - Progress bars for large downloads
 * - Processing data as it arrives
 * - Piping data to another destination
 *
 * Requirements:
 *   npm install httpcloak
 *
 * Run:
 *   node 09_streaming.js
 */

const httpcloak = require("httpcloak");
const fs = require("fs");
const os = require("os");
const path = require("path");

async function main() {
  console.log("=".repeat(70));
  console.log("httpcloak - Streaming Downloads");
  console.log("=".repeat(70));

  // ===========================================================================
  // Understanding Streaming
  // ===========================================================================
  console.log("\n[INFO] Understanding Streaming");
  console.log("-".repeat(50));
  console.log(`
Streaming allows you to process response data as it arrives,
without loading the entire response into memory.

Use streaming when:
- File is larger than available memory
- You want to show download progress
- Processing data incrementally (parsing, transforming)
- Writing to disk as data arrives
`);

  const session = new httpcloak.Session({ preset: "chrome-latest" });

  // ===========================================================================
  // Example 1: Basic Streaming
  // ===========================================================================
  console.log("\n[1] Basic Streaming");
  console.log("-".repeat(50));

  // Start a streaming request (synchronous)
  let stream = session.getStream("https://httpbin.org/bytes/102400");

  console.log(`Status Code: ${stream.statusCode}`);
  console.log(`Protocol: ${stream.protocol}`);
  console.log(`Content-Length: ${stream.contentLength}`);

  // Read data in chunks
  let totalBytes = 0;
  let chunkCount = 0;
  while (true) {
    const chunk = stream.readChunk(8192); // Read up to 8KB at a time
    if (!chunk) break;
    totalBytes += chunk.length;
    chunkCount++;
  }

  stream.close();
  console.log(`Read ${totalBytes} bytes in ${chunkCount} chunks`);

  // ===========================================================================
  // Example 2: Download with Progress
  // ===========================================================================
  console.log("\n[2] Download with Progress");
  console.log("-".repeat(50));

  stream = session.getStream("https://httpbin.org/bytes/51200");
  const contentLength = stream.contentLength;
  let downloaded = 0;

  console.log(`Downloading ${contentLength} bytes...`);
  const startTime = performance.now();

  while (true) {
    const chunk = stream.readChunk(4096);
    if (!chunk) break;
    downloaded += chunk.length;

    // Calculate progress
    if (contentLength > 0) {
      const percent = (downloaded / contentLength) * 100;
      const barWidth = 40;
      const filled = Math.floor((barWidth * downloaded) / contentLength);
      const bar = "=".repeat(filled) + "-".repeat(barWidth - filled);
      process.stdout.write(`\r[${bar}] ${percent.toFixed(1)}%`);
    }
  }

  const elapsed = performance.now() - startTime;
  stream.close();

  console.log(`\nCompleted: ${downloaded} bytes in ${elapsed.toFixed(0)}ms`);

  // ===========================================================================
  // Example 3: Stream to File
  // ===========================================================================
  console.log("\n[3] Stream to File");
  console.log("-".repeat(50));

  stream = session.getStream("https://httpbin.org/bytes/102400");

  const tempPath = path.join(os.tmpdir(), "httpcloak_stream_test.bin");
  const writeStream = fs.createWriteStream(tempPath);
  let bytesWritten = 0;

  while (true) {
    const chunk = stream.readChunk(16384);
    if (!chunk) break;
    writeStream.write(chunk);
    bytesWritten += chunk.length;
  }

  writeStream.end();
  stream.close();

  const fileSize = fs.statSync(tempPath).size;
  console.log(`Streamed ${bytesWritten} bytes to file`);
  console.log(`File size on disk: ${fileSize} bytes`);
  fs.unlinkSync(tempPath);

  // ===========================================================================
  // Example 4: Async Iterator Pattern
  // ===========================================================================
  console.log("\n[4] Async Iterator Pattern");
  console.log("-".repeat(50));

  stream = session.getStream("https://httpbin.org/bytes/32768");

  // Use async iterator for cleaner code
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }

  stream.close();

  console.log(`Received ${chunks.length} chunks`);
  console.log(`Total bytes: ${chunks.reduce((sum, c) => sum + c.length, 0)}`);

  // ===========================================================================
  // Example 5: Streaming with Different Protocols
  // ===========================================================================
  console.log("\n[5] Streaming with Different Protocols");
  console.log("-".repeat(50));

  // HTTP/2 streaming
  const sessionH2 = new httpcloak.Session({ preset: "chrome-latest", httpVersion: "h2" });
  stream = sessionH2.getStream("https://cloudflare.com/cdn-cgi/trace");
  let data = Buffer.alloc(0);
  while (true) {
    const chunk = stream.readChunk(1024);
    if (!chunk) break;
    data = Buffer.concat([data, chunk]);
  }
  console.log(`HTTP/2 stream: ${data.length} bytes, protocol: ${stream.protocol}`);
  stream.close();
  sessionH2.close();

  // HTTP/3 streaming
  const sessionH3 = new httpcloak.Session({ preset: "chrome-latest", httpVersion: "h3" });
  stream = sessionH3.getStream("https://cloudflare.com/cdn-cgi/trace");
  data = Buffer.alloc(0);
  while (true) {
    const chunk = stream.readChunk(1024);
    if (!chunk) break;
    data = Buffer.concat([data, chunk]);
  }
  console.log(`HTTP/3 stream: ${data.length} bytes, protocol: ${stream.protocol}`);
  stream.close();
  sessionH3.close();

  // ===========================================================================
  // Example 6: When to Use Streaming vs getFast()
  // ===========================================================================
  console.log("\n[6] Streaming vs getFast() Comparison");
  console.log("-".repeat(50));
  console.log(`
STREAMING (getStream):
- Memory efficient - only holds one chunk at a time
- Good for files larger than RAM
- Enables progress tracking
- Slower due to chunk-by-chunk processing

getFast():
- Fastest download speed
- Loads entire response into memory
- Best for files that fit in memory
- ~10-50x faster than streaming for small/medium files

RECOMMENDATIONS:
- Files < 100MB: Use getFast()
- Files > 100MB or unknown size: Use streaming
- Need progress bar: Use streaming
- Memory constrained: Use streaming
`);

  // ===========================================================================
  // Cleanup
  // ===========================================================================
  session.close();

  console.log("\n" + "=".repeat(70));
  console.log("SUMMARY");
  console.log("=".repeat(70));
  console.log(`
Streaming methods:
- getStream(url) - Start streaming GET request
- stream.readChunk(size) - Read up to 'size' bytes
- for await (const chunk of stream) - Async iteration
- stream.close() - Close the stream

Properties:
- stream.statusCode - HTTP status
- stream.headers - Response headers
- stream.contentLength - Total size (if known)
- stream.protocol - HTTP protocol used
`);
}

main().catch(console.error);
