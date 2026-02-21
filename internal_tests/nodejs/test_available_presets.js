#!/usr/bin/env node
/**
 * Test availablePresets() returns dict with protocol support info.
 */

const path = require('path');

process.env.HTTPCLOAK_LIB_PATH = process.env.HTTPCLOAK_LIB_PATH ||
  path.join(__dirname, '..', '..', 'bindings', 'clib', 'libhttpcloak-linux-amd64.so');

const httpcloak = require(path.join(__dirname, '..', '..', 'bindings', 'nodejs'));

const EXPECTED_H3 = new Set([
  "chrome-143", "chrome-143-windows", "chrome-143-linux", "chrome-143-macos",
  "chrome-144", "chrome-144-windows", "chrome-144-linux", "chrome-144-macos",
  "chrome-145", "chrome-145-windows", "chrome-145-linux", "chrome-145-macos",
  "safari-18", "chrome-143-ios", "chrome-144-ios", "chrome-145-ios",
  "safari-18-ios", "chrome-143-android", "chrome-144-android", "chrome-145-android",
]);

const EXPECTED_NO_H3 = new Set(["chrome-133", "chrome-141", "firefox-133", "safari-17-ios"]);

const ALL_EXPECTED = new Set([...EXPECTED_H3, ...EXPECTED_NO_H3]);

function main() {
  console.log("=".repeat(60));
  console.log("Test: availablePresets() dict format");
  console.log("=".repeat(60));

  let passed = 0;
  let failed = 0;

  const presets = httpcloak.availablePresets();

  // 1. Return type is object (not array)
  const isObj = typeof presets === 'object' && !Array.isArray(presets) && presets !== null;
  console.log(`  [${isObj ? 'PASS' : 'FAIL'}] Return type is object: ${typeof presets}, isArray=${Array.isArray(presets)}`);
  if (isObj) passed++; else failed++;

  // 2. Has expected count
  const keys = Object.keys(presets);
  const countOk = keys.length === ALL_EXPECTED.size;
  console.log(`  [${countOk ? 'PASS' : 'FAIL'}] Preset count: ${keys.length} (expected ${ALL_EXPECTED.size})`);
  if (countOk) passed++; else failed++;

  // 3. All expected presets present
  const keysSet = new Set(keys);
  const missing = [...ALL_EXPECTED].filter(k => !keysSet.has(k));
  const extra = [...keysSet].filter(k => !ALL_EXPECTED.has(k));
  const allPresent = missing.length === 0 && extra.length === 0;
  console.log(`  [${allPresent ? 'PASS' : 'FAIL'}] All expected presets present`);
  if (missing.length > 0) console.log(`         Missing: ${missing.join(', ')}`);
  if (extra.length > 0) console.log(`         Extra: ${extra.join(', ')}`);
  if (allPresent) passed++; else failed++;

  // 4. Each preset has protocols array
  let allHaveProtocols = true;
  for (const [name, info] of Object.entries(presets)) {
    if (!info || !Array.isArray(info.protocols)) {
      console.log(`  [FAIL] ${name}: missing or invalid 'protocols', got ${JSON.stringify(info)}`);
      allHaveProtocols = false;
      break;
    }
  }
  console.log(`  [${allHaveProtocols ? 'PASS' : 'FAIL'}] All presets have 'protocols' array`);
  if (allHaveProtocols) passed++; else failed++;

  // 5. All presets have h1 and h2
  let allHaveH1H2 = true;
  for (const [name, info] of Object.entries(presets)) {
    const protos = info.protocols || [];
    if (!protos.includes('h1') || !protos.includes('h2')) {
      console.log(`  [FAIL] ${name}: missing h1/h2, has ${JSON.stringify(protos)}`);
      allHaveH1H2 = false;
    }
  }
  console.log(`  [${allHaveH1H2 ? 'PASS' : 'FAIL'}] All presets have h1 and h2`);
  if (allHaveH1H2) passed++; else failed++;

  // 6. H3-capable presets have h3
  let h3Correct = true;
  for (const name of EXPECTED_H3) {
    if (presets[name]) {
      const protos = presets[name].protocols || [];
      if (!protos.includes('h3')) {
        console.log(`  [FAIL] ${name}: should have h3 but has ${JSON.stringify(protos)}`);
        h3Correct = false;
      }
    }
  }
  console.log(`  [${h3Correct ? 'PASS' : 'FAIL'}] H3 presets have h3 protocol`);
  if (h3Correct) passed++; else failed++;

  // 7. Non-H3 presets don't have h3
  let noH3Correct = true;
  for (const name of EXPECTED_NO_H3) {
    if (presets[name]) {
      const protos = presets[name].protocols || [];
      if (protos.includes('h3')) {
        console.log(`  [FAIL] ${name}: should NOT have h3 but has ${JSON.stringify(protos)}`);
        noH3Correct = false;
      }
    }
  }
  console.log(`  [${noH3Correct ? 'PASS' : 'FAIL'}] Non-H3 presets don't have h3`);
  if (noH3Correct) passed++; else failed++;

  // Summary
  console.log();
  console.log("=".repeat(60));
  const total = passed + failed;
  console.log(`Result: ${passed}/${total} checks passed`);
  if (failed > 0) {
    console.log("FAILED");
    process.exit(1);
  } else {
    console.log("ALL PASSED");
  }
}

main();
