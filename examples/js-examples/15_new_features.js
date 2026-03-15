#!/usr/bin/env node
/**
 * New Features: Refresh, Local Address Binding, TLS Key Logging
 *
 * This example demonstrates:
 * - refresh() - simulate browser page refresh (close connections, keep TLS cache)
 * - Local Address Binding - bind to specific local IP (IPv4 or IPv6)
 * - TLS Key Logging - write TLS keys for Wireshark decryption
 */

const fs = require('fs');
const { Session } = require('httpcloak');

const TEST_URL = 'https://www.cloudflare.com/cdn-cgi/trace';

function parseTrace(body) {
    const result = {};
    for (const line of body.trim().split('\n')) {
        const idx = line.indexOf('=');
        if (idx !== -1) {
            result[line.slice(0, idx)] = line.slice(idx + 1);
        }
    }
    return result;
}

async function main() {
    // ==========================================================
    // Example 1: Refresh (Browser Page Refresh Simulation)
    // ==========================================================
    console.log('='.repeat(60));
    console.log('Example 1: Refresh (Browser Page Refresh)');
    console.log('-'.repeat(60));

    let session = new Session({
        preset: 'chrome-latest',
        timeout: 30
    });

    // Make initial request - establishes TLS session
    let resp = await session.get(TEST_URL);
    let trace = parseTrace(resp.text);
    console.log(`First request: Protocol=${resp.protocol}, IP=${trace.ip || 'N/A'}`);

    // Simulate browser refresh (F5)
    // This closes TCP/QUIC connections but keeps TLS session cache
    session.refresh();
    console.log('Called refresh() - connections closed, TLS cache kept');

    // Next request uses TLS resumption (faster handshake)
    resp = await session.get(TEST_URL);
    trace = parseTrace(resp.text);
    console.log(`After refresh: Protocol=${resp.protocol}, IP=${trace.ip || 'N/A'} (TLS resumption)`);

    session.close();

    // ==========================================================
    // Example 2: TLS Key Logging
    // ==========================================================
    console.log('\n' + '='.repeat(60));
    console.log('Example 2: TLS Key Logging');
    console.log('-'.repeat(60));

    const keylogPath = '/tmp/nodejs_keylog_example.txt';

    // Remove old keylog file
    if (fs.existsSync(keylogPath)) {
        fs.unlinkSync(keylogPath);
    }

    // Create session with key logging enabled
    session = new Session({
        preset: 'chrome-latest',
        timeout: 30,
        keyLogFile: keylogPath
    });

    // Make request - TLS keys written to file
    resp = await session.get(TEST_URL);
    console.log(`Request completed: Protocol=${resp.protocol}`);

    session.close();

    // Check if keylog file was created
    if (fs.existsSync(keylogPath)) {
        const stats = fs.statSync(keylogPath);
        console.log(`Key log file created: ${keylogPath} (${stats.size} bytes)`);
        console.log('Use in Wireshark: Edit -> Preferences -> Protocols -> TLS -> Pre-Master-Secret log filename');
    } else {
        console.log('Key log file not found');
    }

    // ==========================================================
    // Example 3: Local Address Binding
    // ==========================================================
    console.log('\n' + '='.repeat(60));
    console.log('Example 3: Local Address Binding');
    console.log('-'.repeat(60));

    console.log(`
Local address binding allows you to specify which local IP to use
for outgoing connections. This is essential for IPv6 rotation scenarios.

Usage:

// Bind to specific IPv6 address
const session = new Session({
    preset: 'chrome-latest',
    localAddress: '2001:db8::1'
});

// Bind to specific IPv4 address
const session = new Session({
    preset: 'chrome-latest',
    localAddress: '192.168.1.100'
});

Note: When local address is set, target IPs are filtered to match
the address family (IPv6 local -> only connects to IPv6 targets).

Example with your machine's IPs:
`);

    // This is a demonstration - replace with actual local IP
    // Uncomment to test with your real IPv6/IPv4:
    //
    // const session3 = new Session({
    //     preset: 'chrome-latest',
    //     localAddress: 'YOUR_LOCAL_IP_HERE',
    //     timeout: 30
    // });
    //
    // const resp3 = await session3.get('https://api.ipify.org');
    // console.log(`Server saw IP: ${resp3.text}`);
    // session3.close();

    console.log('\n' + '='.repeat(60));
    console.log('New features examples completed!');
    console.log('='.repeat(60));
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
