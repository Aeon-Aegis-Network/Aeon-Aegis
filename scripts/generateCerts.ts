import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Auto-detects OpenSSL binary across system PATH and standard Windows Git locations.
 */
function resolveOpenSSL(): string {
  try {
    execSync('openssl version', { stdio: 'ignore' });
    return 'openssl';
  } catch {
    if (process.platform === 'win32') {
      const winCandidates = [
        'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
        'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
        'C:\\Program Files (x86)\\Git\\usr\\bin\\openssl.exe',
        'C:\\Program Files (x86)\\Git\\mingw64\\bin\\openssl.exe',
        'C:\\ProgramData\\chocolatey\\bin\\openssl.exe',
        'C:\\msys64\\usr\\bin\\openssl.exe'
      ];

      for (const binaryPath of winCandidates) {
        if (fs.existsSync(binaryPath)) {
          return `"${binaryPath}"`;
        }
      }
    }
    throw new Error(
      'OpenSSL executable could not be found.\n' +
      'Please install OpenSSL or Git for Windows, or run: winget install OpenSSL.Light'
    );
  }
}

const certsDir = path.join(process.cwd(), 'certs');

if (!fs.existsSync(certsDir)) {
  fs.mkdirSync(certsDir, { recursive: true });
}

console.log('====================================================');
console.log('  AEON AEGIS - PKI CERTIFICATE GENERATION TOOL      ');
console.log('====================================================\n');

const openssl = resolveOpenSSL();
console.log(`Using OpenSSL binary: ${openssl}\n`);

// SAN extension config for OpenSSL server certificate
const sanConfigFile = path.join(certsDir, 'server_san.cnf');
const sanConfigContent = `
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Network
L = ZeroTrust
O = Aeon Aegis Network
OU = Relay Division
CN = relay.aeon-aegis.internal

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = relay.aeon-aegis.internal
IP.1 = 127.0.0.1
IP.2 = 10.0.0.1
`;

fs.writeFileSync(sanConfigFile, sanConfigContent.trim());

try {
  // 1. Generate Root CA (PrivateKey + Self-Signed Certificate)
  console.log('[1/3] Generating Root Certificate Authority (CA)...');
  execSync(
    `${openssl} req -x509 -newkey rsa:4096 -nodes -days 3650 ` +
    `-keyout "${path.join(certsDir, 'ca.key')}" ` +
    `-out "${path.join(certsDir, 'ca.crt')}" ` +
    `-subj "/C=US/O=Aeon Aegis/OU=Security CA/CN=AeonAegisRootCA"`,
    { stdio: 'inherit' }
  );

  // 2. Generate Relay Server Key + CSR + CA Signed Certificate
  console.log('\n[2/3] Generating Relay Server Certificate & SAN extensions...');
  execSync(
    `${openssl} req -newkey rsa:2048 -nodes ` +
    `-keyout "${path.join(certsDir, 'server.key')}" ` +
    `-out "${path.join(certsDir, 'server.csr')}" ` +
    `-config "${sanConfigFile}"`,
    { stdio: 'inherit' }
  );

  execSync(
    `${openssl} x509 -req -days 825 ` +
    `-in "${path.join(certsDir, 'server.csr')}" ` +
    `-CA "${path.join(certsDir, 'ca.crt')}" ` +
    `-CAkey "${path.join(certsDir, 'ca.key')}" ` +
    `-CAcreateserial ` +
    `-out "${path.join(certsDir, 'server.crt')}" ` +
    `-extfile "${sanConfigFile}" -extensions v3_req`,
    { stdio: 'inherit' }
  );

  // 3. Generate Client Key + CSR + CA Signed Certificate for mTLS
  console.log('\n[3/3] Generating Authenticated Client Certificate...');
  execSync(
    `${openssl} req -newkey rsa:2048 -nodes ` +
    `-keyout "${path.join(certsDir, 'client.key')}" ` +
    `-out "${path.join(certsDir, 'client.csr')}" ` +
    `-subj "/C=US/O=Aeon Aegis/OU=Client Node/CN=AeonAegisAuthorizedClient"`,
    { stdio: 'inherit' }
  );

  execSync(
    `${openssl} x509 -req -days 825 ` +
    `-in "${path.join(certsDir, 'client.csr')}" ` +
    `-CA "${path.join(certsDir, 'ca.crt')}" ` +
    `-CAkey "${path.join(certsDir, 'ca.key')}" ` +
    `-CAcreateserial ` +
    `-out "${path.join(certsDir, 'client.crt')}"`,
    { stdio: 'inherit' }
  );

  // Cleanup temporary CSRs and CNF files
  fs.unlinkSync(sanConfigFile);
  fs.unlinkSync(path.join(certsDir, 'server.csr'));
  fs.unlinkSync(path.join(certsDir, 'client.csr'));

  console.log('\n====================================================');
  console.log('SUCCESS: All PKI certificates generated successfully!');
  console.log(`Directory: ${certsDir}`);
  console.log('Files generated:');
  console.log('  ├── ca.crt & ca.key       (Root CA Certificate & Private Key)');
  console.log('  ├── server.crt & server.key (Relay Server Certificate & Key)');
  console.log('  └── client.crt & client.key (Client mTLS Certificate & Key)');
  console.log('====================================================');
} catch (error: any) {
  console.error('\nError generating PKI certificates:', error?.message);
  process.exit(1);
}