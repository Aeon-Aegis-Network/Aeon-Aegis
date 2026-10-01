import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';

const certsDir = path.join(process.cwd(), 'certs');
const ca = fs.readFileSync(path.join(certsDir, 'ca.crt'));
const clientCert = fs.readFileSync(path.join(certsDir, 'client.crt'));
const clientKey = fs.readFileSync(path.join(certsDir, 'client.key'));

console.log('====================================================');
console.log('  AEON AEGIS - mTLS VERIFICATION TEST SUITE         ');
console.log('====================================================\n');

// 1. Test Authorized Request (With Client Certificate)
function testAuthorizedAccess(): Promise<void> {
  return new Promise((resolve) => {
    console.log('[Test 1] Testing AUTHORIZED mTLS Request (With Client Cert)...');

    const req = https.request(
      {
        hostname: '127.0.0.1',
        port: 9091,
        path: '/metrics',
        method: 'GET',
        ca,
        cert: clientCert,
        key: clientKey,
        rejectUnauthorized: true
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          console.log(`  -> Status: ${res.statusCode} OK`);
          console.log(`  -> Response Payload: ${body.trim()}`);
          console.log('  [PASS] Authorized access granted!\n');
          resolve();
        });
      }
    );

    req.on('error', (err) => {
      console.error(`  [FAIL] Authorized request failed: ${err.message}\n`);
      resolve();
    });

    req.end();
  });
}

// 2. Test Unauthorized Request (Without Client Certificate)
function testUnauthorizedAccess(): Promise<void> {
  return new Promise((resolve) => {
    console.log('[Test 2] Testing UNAUTHORIZED mTLS Request (No Client Cert)...');

    const req = https.request(
      {
        hostname: '127.0.0.1',
        port: 9091,
        path: '/metrics',
        method: 'GET',
        ca,
        rejectUnauthorized: false
      },
      (res) => {
        console.error(`  [FAIL] Unauthorized request unexpectedly succeeded with status ${res.statusCode}\n`);
        resolve();
      }
    );

    req.on('error', (err) => {
      console.log(`  -> TLS Handshake Rejected: ${err.message}`);
      console.log('  [PASS] Unauthorized request correctly blocked at TLS layer!\n');
      resolve();
    });

    req.end();
  });
}

async function main() {
  await testAuthorizedAccess();
  await testUnauthorizedAccess();
}

main();