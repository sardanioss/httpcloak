/**
 * Custom JA3 & Akamai Fingerprinting with httpcloak
 *
 * Override the preset's TLS and HTTP/2 fingerprints with custom JA3 and Akamai
 * strings for fine-grained control over how your connections appear on the wire.
 *
 * What you'll learn:
 * - How to set a custom JA3 TLS fingerprint
 * - How to set a custom Akamai HTTP/2 fingerprint
 * - How to use extra fingerprint options (ALPN, signature algorithms, etc.)
 * - How to combine JA3 + Akamai for full fingerprint control
 * - How to verify your fingerprint against tls.peet.ws
 *
 * Requirements:
 *   npm install httpcloak
 *
 * Run:
 *   node 17_custom_fingerprint.js
 */

const { Session } = require("httpcloak");

// A real Chrome 131 JA3 string (different from the default preset)
const CHROME_131_JA3 =
  "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172" +
  "-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037,29-23-24,0";

// A real Chrome Akamai HTTP/2 fingerprint
const CHROME_AKAMAI = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";

async function main() {
  // ============================================================
  // Example 1: Custom JA3 Fingerprint
  // ============================================================
  // Override the TLS fingerprint with a specific JA3 string.
  // TLS-only mode is automatically enabled when JA3 is set.

  console.log("=".repeat(60));
  console.log("Example 1: Custom JA3 Fingerprint");
  console.log("-".repeat(60));

  {
    const session = new Session({ preset: "chrome-145", ja3: CHROME_131_JA3 });
    try {
      const response = await session.get("https://tls.peet.ws/api/tls");
      const data = response.json();

      console.log(`JA3 hash: ${data.ja3_hash || "N/A"}`);
      console.log(`JA3 text: ${(data.ja3 || "N/A").slice(0, 80)}...`);
      console.log("\nThe TLS fingerprint now matches the custom JA3 string,");
      console.log("not the chrome-145 preset.");
    } finally {
      session.close();
    }
  }

  // ============================================================
  // Example 2: Custom Akamai HTTP/2 Fingerprint
  // ============================================================
  // Override the HTTP/2 SETTINGS, WINDOW_UPDATE, PRIORITY, and
  // pseudo-header order with an Akamai fingerprint string.

  console.log("\n" + "=".repeat(60));
  console.log("Example 2: Custom Akamai HTTP/2 Fingerprint");
  console.log("-".repeat(60));

  {
    const session = new Session({
      preset: "chrome-145",
      akamai: CHROME_AKAMAI,
    });
    try {
      const response = await session.get("https://tls.peet.ws/api/all");
      const data = response.json();

      const akamiFp = data.http2?.akamai_fingerprint || "N/A";
      console.log(`Akamai fingerprint: ${akamiFp}`);
      console.log(`Expected:           ${CHROME_AKAMAI}`);
      console.log(`Match: ${akamiFp === CHROME_AKAMAI}`);
    } finally {
      session.close();
    }
  }

  // ============================================================
  // Example 3: JA3 + Akamai Combined
  // ============================================================
  // Full control over both TLS and HTTP/2 fingerprints.

  console.log("\n" + "=".repeat(60));
  console.log("Example 3: Combined JA3 + Akamai");
  console.log("-".repeat(60));

  {
    const session = new Session({
      preset: "chrome-145",
      ja3: CHROME_131_JA3,
      akamai: CHROME_AKAMAI,
    });
    try {
      const response = await session.get("https://tls.peet.ws/api/all");
      const data = response.json();

      const ja3Hash = data.tls?.ja3_hash || "N/A";
      const akamiFp = data.http2?.akamai_fingerprint || "N/A";
      console.log(`JA3 hash:    ${ja3Hash}`);
      console.log(`Akamai:      ${akamiFp}`);
      console.log("\nBoth TLS and HTTP/2 fingerprints are fully custom.");
    } finally {
      session.close();
    }
  }

  // ============================================================
  // Example 4: Extra Fingerprint Options
  // ============================================================
  // Fine-tune TLS extensions beyond what JA3 captures using extraFp.
  // Available options:
  //   - tls_signature_algorithms: list of signature algorithm names
  //   - tls_alpn: list of ALPN protocols
  //   - tls_cert_compression: list of cert compression algorithms
  //   - tls_permute_extensions: randomize TLS extension order

  console.log("\n" + "=".repeat(60));
  console.log("Example 4: Extra Fingerprint Options");
  console.log("-".repeat(60));

  {
    const session = new Session({
      preset: "chrome-145",
      ja3: CHROME_131_JA3,
      extraFp: {
        tls_alpn: ["h2", "http/1.1"],
        tls_cert_compression: ["brotli"],
        tls_permute_extensions: true,
      },
    });
    try {
      const response = await session.get("https://tls.peet.ws/api/tls");
      const data = response.json();

      console.log(`JA3 hash: ${data.ja3_hash || "N/A"}`);
      console.log(
        "Extensions are randomly permuted — JA3 hash will vary each run"
      );
      console.log("but cipher suites and curves remain the same.");
    } finally {
      session.close();
    }
  }

  // ============================================================
  // Summary
  // ============================================================
  console.log("\n" + "=".repeat(60));
  console.log("Summary: Custom Fingerprinting Options");
  console.log("=".repeat(60));
  console.log(`
JA3 fingerprint (ja3):
  - Overrides the TLS ClientHello fingerprint
  - Format: TLSVersion,Ciphers,Extensions,Curves,PointFormats
  - Automatically enables TLS-only mode (no preset HTTP headers)

Akamai fingerprint (akamai):
  - Overrides HTTP/2 SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order
  - Format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
  - Works alongside the preset's TLS fingerprint

Extra options (extraFp):
  - tls_alpn: ["h2", "http/1.1"]
  - tls_signature_algorithms: ["ecdsa_secp256r1_sha256", ...]
  - tls_cert_compression: ["brotli", "zlib", "zstd"]
  - tls_permute_extensions: true/false
  - Used in combination with ja3 to fine-tune the fingerprint
`);
}

main().catch(console.error);
