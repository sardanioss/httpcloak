/**
 * TLS-Only Mode with httpcloak
 *
 * TLS-only mode lets you use the browser's TLS fingerprint (JA3/JA4, Peetprint,
 * Akamai) while having full control over HTTP headers.
 *
 * What you'll learn:
 * - What TLS-only mode does vs normal mode
 * - When to use TLS-only mode
 * - How to set custom headers in TLS-only mode
 *
 * Requirements:
 *   npm install httpcloak
 *
 * Run:
 *   node 13_tls_only_mode.js
 */

const { Session } = require("httpcloak");

async function main() {
  // ============================================================
  // Example 1: Normal Mode (default behavior)
  // ============================================================
  // In normal mode, preset headers are automatically applied

  console.log("=".repeat(60));
  console.log("Example 1: Normal Mode (preset headers applied)");
  console.log("-".repeat(60));

  {
    const session = new Session({ preset: "chrome-latest" });
    try {
      const response = await session.get("https://httpbin.org/headers");
      const headers = response.json().headers || {};

      console.log("Headers sent to server:");
      for (const [key, value] of Object.entries(headers).sort()) {
        if (
          key.startsWith("Sec-") ||
          key.startsWith("Accept") ||
          key === "User-Agent" ||
          key === "Priority" ||
          key.startsWith("Upgrade")
        ) {
          const display = value.length > 60 ? value.slice(0, 60) + "..." : value;
          console.log(`  ${key}: ${display}`);
        }
      }

      console.log(`\nTotal headers: ${Object.keys(headers).length}`);
      console.log("Note: All Chrome preset headers are automatically included");
    } finally {
      session.close();
    }
  }

  // ============================================================
  // Example 2: TLS-Only Mode (no preset headers)
  // ============================================================
  // TLS fingerprint is applied, but HTTP headers are not

  console.log("\n" + "=".repeat(60));
  console.log("Example 2: TLS-Only Mode (custom headers only)");
  console.log("-".repeat(60));

  {
    const session = new Session({ preset: "chrome-latest", tlsOnly: true });
    try {
      // Only our custom headers will be sent
      const response = await session.get("https://httpbin.org/headers", {
        headers: {
          "User-Agent": "MyBot/1.0",
          "X-Custom-Header": "my-value",
        },
      });
      const headers = response.json().headers || {};

      console.log("Headers sent to server:");
      for (const [key, value] of Object.entries(headers).sort()) {
        console.log(`  ${key}: ${value}`);
      }

      console.log(`\nTotal headers: ${Object.keys(headers).length}`);
      console.log("Note: Only our custom headers + minimal required headers");
    } finally {
      session.close();
    }
  }

  // ============================================================
  // Example 3: TLS-Only for API Clients
  // ============================================================
  // Useful when you need TLS fingerprint but specific API headers

  console.log("\n" + "=".repeat(60));
  console.log("Example 3: TLS-Only for API Clients");
  console.log("-".repeat(60));

  {
    const session = new Session({ preset: "chrome-latest", tlsOnly: true });
    try {
      // API-style request with custom headers
      const response = await session.get("https://httpbin.org/headers", {
        headers: {
          Authorization: "Bearer my-api-token",
          "X-API-Key": "secret-key-123",
          "Content-Type": "application/json",
          Accept: "application/json",
        },
      });
      const headers = response.json().headers || {};

      console.log("API request headers:");
      for (const [key, value] of Object.entries(headers).sort()) {
        if (!key.startsWith("X-Amzn")) {
          // Skip AWS trace headers
          console.log(`  ${key}: ${value}`);
        }
      }

      console.log("\nNo Sec-Ch-Ua or browser-specific headers leaked!");
    } finally {
      session.close();
    }
  }

  // ============================================================
  // Example 4: Comparing Fingerprints
  // ============================================================
  // Both modes produce the same TLS fingerprint

  console.log("\n" + "=".repeat(60));
  console.log("Example 4: TLS Fingerprint Comparison");
  console.log("-".repeat(60));

  // Check TLS fingerprint in normal mode
  {
    const session = new Session({ preset: "chrome-latest" });
    try {
      const response = await session.get("https://tls.peet.ws/api/all");
      const data = response.json();
      const ja4 = data.tls?.ja4 || "N/A";
      console.log(`Normal mode JA4:   ${ja4}`);
    } finally {
      session.close();
    }
  }

  // Check TLS fingerprint in TLS-only mode
  {
    const session = new Session({ preset: "chrome-latest", tlsOnly: true });
    try {
      const response = await session.get("https://tls.peet.ws/api/all");
      const data = response.json();
      const ja4 = data.tls?.ja4 || "N/A";
      console.log(`TLS-only mode JA4: ${ja4}`);
    } finally {
      session.close();
    }
  }

  console.log("\nBoth have identical TLS fingerprints!");

  // ============================================================
  // Summary
  // ============================================================
  console.log("\n" + "=".repeat(60));
  console.log("Summary: When to use TLS-Only Mode");
  console.log("=".repeat(60));
  console.log(`
Use TLS-only mode when you need:

1. Full control over HTTP headers
   - API clients with specific header requirements
   - Custom User-Agent strings
   - No browser-specific headers (Sec-Ch-Ua, etc.)

2. TLS fingerprint without HTTP fingerprint
   - Pass TLS-based bot detection
   - But use your own HTTP header set

3. Minimal header footprint
   - Only send headers you explicitly set
   - Useful for testing or specific protocols

Normal mode is better when:
- You want to fully mimic a browser
- You need automatic browser headers
- You're accessing websites (not APIs)
`);
}

// Run the main function
main().catch(console.error);
