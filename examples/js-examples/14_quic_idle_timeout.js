/**
 * QUIC Idle Timeout Configuration
 *
 * This example demonstrates:
 * - Configuring QUIC idle timeout for HTTP/3 connections
 * - Preventing connection drops on long-lived idle connections
 * - When to use higher idle timeouts
 *
 * By default, QUIC connections have a 30-second idle timeout. If your application
 * keeps connections open for longer periods without activity (e.g., connection pooling,
 * long polling), you may need to increase this value.
 *
 * The keepalive is automatically set to half of the idle timeout to prevent
 * connection closure.
 *
 * Run: node 14_quic_idle_timeout.js
 */

const httpcloak = require("httpcloak");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  console.log("=".repeat(60));
  console.log("QUIC Idle Timeout Configuration Examples");
  console.log("=".repeat(60));

  // Example 1: Default QUIC idle timeout (30 seconds)
  console.log("\n[Example 1] Default QUIC Idle Timeout");
  console.log("-".repeat(50));

  let session = new httpcloak.Session({
    preset: "chrome-latest",
    httpVersion: "h3", // Force HTTP/3 to use QUIC
  });

  let response = await session.get("https://cloudflare.com");
  console.log(`Status: ${response.statusCode}`);
  console.log(`Protocol: ${response.protocol}`);
  console.log("Default idle timeout: 30 seconds");
  console.log("Default keepalive: 15 seconds (half of idle timeout)");

  session.close();

  // Example 2: Extended QUIC idle timeout for long-lived connections
  console.log("\n[Example 2] Extended QUIC Idle Timeout (2 minutes)");
  console.log("-".repeat(50));

  session = new httpcloak.Session({
    preset: "chrome-latest",
    httpVersion: "h3",
    quicIdleTimeout: 120, // 2 minutes
  });

  response = await session.get("https://cloudflare.com");
  console.log(`Status: ${response.statusCode}`);
  console.log(`Protocol: ${response.protocol}`);
  console.log("Custom idle timeout: 120 seconds");
  console.log("Custom keepalive: 60 seconds (half of idle timeout)");

  // Simulate idle period
  console.log("\nSimulating 5 second idle period...");
  await sleep(5000);

  // Connection should still be alive
  response = await session.get("https://cloudflare.com");
  console.log(
    `After idle - Status: ${response.statusCode}, Protocol: ${response.protocol}`
  );

  session.close();

  // Example 3: Very long idle timeout for persistent connections
  console.log("\n[Example 3] Very Long Idle Timeout (5 minutes)");
  console.log("-".repeat(50));

  session = new httpcloak.Session({
    preset: "chrome-latest",
    httpVersion: "h3",
    quicIdleTimeout: 300, // 5 minutes
  });

  response = await session.get("https://cloudflare.com");
  console.log(`Status: ${response.statusCode}`);
  console.log(`Protocol: ${response.protocol}`);
  console.log("Custom idle timeout: 300 seconds (5 minutes)");
  console.log("Custom keepalive: 150 seconds (2.5 minutes)");

  session.close();

  // Example 4: Combined with other session options
  console.log("\n[Example 4] Combined with Other Options");
  console.log("-".repeat(50));

  session = new httpcloak.Session({
    preset: "chrome-latest",
    httpVersion: "h3",
    quicIdleTimeout: 180, // 3 minutes
    timeout: 60, // Request timeout
    retry: 3, // Retry count
  });

  response = await session.get("https://cloudflare.com");
  console.log(`Status: ${response.statusCode}`);
  console.log(`Protocol: ${response.protocol}`);
  console.log("QUIC idle timeout: 180s, Request timeout: 60s, Retries: 3");

  session.close();

  // Usage guidance
  console.log("\n" + "=".repeat(60));
  console.log("When to Adjust QUIC Idle Timeout");
  console.log("=".repeat(60));

  console.log(`
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
`);

  console.log("=".repeat(60));
  console.log("QUIC idle timeout examples completed!");
  console.log("=".repeat(60));
}

main().catch(console.error);
