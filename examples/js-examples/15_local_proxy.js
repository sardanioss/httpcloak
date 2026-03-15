/**
 * Example 15: LocalProxy - Local HTTP Proxy with TLS Fingerprinting
 *
 * This example shows how to use LocalProxy to transparently apply TLS
 * fingerprinting to any HTTP client. Perfect for integrating with:
 * - Undici
 * - Node.js fetch
 * - Axios
 * - Any HTTP client that supports proxy configuration
 *
 * Features:
 * - TLS-only mode: Pass headers through, only apply TLS fingerprint
 * - Per-request proxy rotation via Proxy-Authorization header
 * - High-performance streaming with no buffering
 */

const { LocalProxy, Session } = require("httpcloak");

async function basicLocalProxy() {
  console.log("=== Basic LocalProxy Usage ===\n");

  // Start a local proxy on an auto-selected port
  const proxy = new LocalProxy({
    preset: "chrome-latest",
    port: 0, // Auto-select available port
  });

  console.log(`Proxy started on port ${proxy.port}`);
  console.log(`Proxy URL: ${proxy.proxyUrl}`);
  console.log(`Is running: ${proxy.isRunning}`);

  // Get proxy statistics
  const stats = proxy.getStats();
  console.log("Stats:", stats);

  // Clean up
  proxy.close();
  console.log(`Proxy stopped: ${!proxy.isRunning}\n`);
}

async function tlsOnlyMode() {
  console.log("=== TLS-Only Mode ===\n");
  console.log(
    "TLS-only mode passes HTTP headers through unchanged while applying TLS fingerprinting."
  );
  console.log(
    "Perfect for Playwright/Puppeteer integration where browser headers are already authentic.\n"
  );

  // Start proxy in TLS-only mode
  const proxy = new LocalProxy({
    preset: "chrome-latest",
    tlsOnly: true, // Only apply TLS fingerprint, pass headers through
    port: 0,
  });

  console.log(`TLS-only proxy running on ${proxy.proxyUrl}`);

  // Use with httpcloak Session pointing to the local proxy
  const session = new Session({
    proxy: proxy.proxyUrl,
    preset: "chrome-latest",
  });

  try {
    // The session will connect through LocalProxy
    // LocalProxy applies TLS fingerprinting while passing headers through
    const response = await session.get("https://httpbin.org/headers");
    console.log("Response status:", response.statusCode);
    console.log("Protocol used:", response.protocol);

    const data = response.json();
    console.log("Headers received by server:", JSON.stringify(data, null, 2));
  } catch (error) {
    console.error("Request error:", error.message);
  } finally {
    session.close();
    proxy.close();
  }

  console.log();
}

async function perRequestProxyRotation() {
  console.log("=== Per-Request Proxy Rotation ===\n");
  console.log(
    "Use Proxy-Authorization header to rotate upstream proxies per-request."
  );
  console.log(
    "This works for BOTH HTTP and HTTPS requests (unlike X-Upstream-Proxy)."
  );
  console.log(
    "Perfect for proxy rotation with services like Bright Data.\n"
  );

  // Start local proxy without a default upstream proxy
  const proxy = new LocalProxy({
    preset: "chrome-latest",
    tlsOnly: true,
    port: 0,
  });

  console.log(`LocalProxy running on ${proxy.proxyUrl}`);
  console.log("Requests can specify different upstream proxies via header.\n");

  // Example of how to use with different upstream proxies per request
  // (These are example URLs - replace with real proxy URLs)
  const upstreamProxies = [
    "http://user:pass@proxy-1.example.com:8080",
    "http://user:pass@proxy-2.example.com:8080",
    "socks5://user:pass@socks-proxy.example.com:1080",
  ];

  console.log("Header format: Proxy-Authorization: HTTPCloak <proxy-url>");
  console.log("\nExample usage:");
  for (const upstreamProxy of upstreamProxies) {
    console.log(`  Proxy-Authorization: HTTPCloak ${upstreamProxy}`);
  }

  console.log(
    "\nThe header is automatically stripped before forwarding to the target."
  );
  console.log(
    "Note: X-Upstream-Proxy header still works for HTTP requests (legacy support)."
  );

  proxy.close();
  console.log();
}

async function withDefaultUpstreamProxy() {
  console.log("=== LocalProxy with Default Upstream Proxy ===\n");

  // Start proxy with a default upstream proxy
  // Replace with your actual proxy URL
  const proxy = new LocalProxy({
    preset: "chrome-latest",
    tlsOnly: true,
    tcpProxy: "http://user:pass@your-proxy.example.com:8080", // Default for HTTP/1.1, HTTP/2
    // udpProxy: 'socks5://user:pass@your-proxy.example.com:1080', // For HTTP/3
    port: 0,
  });

  console.log(`LocalProxy with default upstream running on ${proxy.proxyUrl}`);
  console.log("All requests will go through the configured upstream proxy.");
  console.log(
    "Individual requests can override with Proxy-Authorization header.\n"
  );

  proxy.close();
}

async function proxyStatistics() {
  console.log("=== Proxy Statistics ===\n");

  const proxy = new LocalProxy({
    preset: "chrome-latest",
    maxConnections: 1000,
    timeout: 30,
    port: 0,
  });

  // Make some requests through the proxy
  const session = new Session({
    proxy: proxy.proxyUrl,
    preset: "chrome-latest",
  });

  try {
    // Make a few requests
    await session.get("https://httpbin.org/get");
    await session.get("https://httpbin.org/ip");

    // Check statistics
    const stats = proxy.getStats();
    console.log("Proxy statistics:");
    console.log(`  Running: ${stats.running}`);
    console.log(`  Active connections: ${stats.active_connections}`);
    console.log(`  Total requests: ${stats.total_requests}`);
    console.log(`  Failed requests: ${stats.failed_requests}`);
  } catch (error) {
    console.error("Request error:", error.message);
  } finally {
    session.close();
    proxy.close();
  }

  console.log();
}

async function undiciIntegrationExample() {
  console.log("=== Undici Integration Example ===\n");
  console.log("Example code for integrating LocalProxy with Undici:\n");

  const code = `
const { LocalProxy } = require('httpcloak');
const { Agent, request } = require('undici');
const { ProxyAgent } = require('undici');

// Start LocalProxy with TLS-only mode
const proxy = new LocalProxy({
  preset: 'chrome-latest',
  tlsOnly: true,  // Pass headers through, only apply TLS fingerprint
  port: 8888
});

// Create Undici ProxyAgent pointing to LocalProxy
const agent = new ProxyAgent(proxy.proxyUrl);

// Make request through LocalProxy
// Headers from your application pass through unchanged
// TLS fingerprint is applied by LocalProxy
const { statusCode, headers, body } = await request('https://example.com', {
  dispatcher: agent,
  headers: {
    // Your custom headers pass through unchanged
    'User-Agent': 'Your-Custom-UA',
    'Accept': 'text/html',
    // Use Proxy-Authorization for per-request proxy rotation (works for HTTPS!)
    'Proxy-Authorization': 'HTTPCloak http://user:pass@rotating-proxy.brightdata.com:8080'
  }
});

console.log('Status:', statusCode);
const text = await body.text();
console.log('Body:', text);

// Clean up
proxy.close();
`;

  console.log(code);
}

async function main() {
  try {
    await basicLocalProxy();
    await tlsOnlyMode();
    await perRequestProxyRotation();
    await withDefaultUpstreamProxy();
    await proxyStatistics();
    await undiciIntegrationExample();

    console.log("=== Summary ===\n");
    console.log("LocalProxy Features:");
    console.log("  - Transparent TLS fingerprinting for any HTTP client");
    console.log("  - TLS-only mode for Playwright/Puppeteer integration");
    console.log(
      "  - Per-request proxy rotation via Proxy-Authorization header"
    );
    console.log("  - High-performance streaming (64KB buffers, ~3GB/s)");
    console.log("  - Connection statistics and monitoring");
  } catch (error) {
    console.error("Error:", error.message);
    process.exit(1);
  }
}

main();
