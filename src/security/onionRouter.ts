import crypto from 'node:crypto';

/**
 * ============================================================================
 * Aeon Aegis - Sphinx-Inspired Layered Onion Encryption Engine
 * ============================================================================
 */

export interface HopInfo {
  publicKey: Buffer;      // 32-byte X25519 Public Key of the relay node
  nextHopAddress: string;  // Multiaddr/IP string of the next node or validator
}

export interface UnwrappedLayer {
  nextHopAddress: string;
  isExit: boolean;
  innerPayload: Buffer;
}

const ALGORITHM = 'chacha20-poly1305';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;

/**
 * Derives a 256-bit symmetric key using ECDH shared secret and HKDF-SHA256.
 * Zeroizes the intermediate shared secret buffer immediately after derivation.
 */
function deriveSymmetricKey(privateKey: crypto.KeyObject, publicKeyBuffer: Buffer): Buffer {
  const peerPublicKey = crypto.createPublicKey({
    key: Buffer.concat([
      // DER Header for X25519 Public Key
      Buffer.from('302a300506032b656e032100', 'hex'),
      publicKeyBuffer
    ]),
    format: 'der',
    type: 'spki'
  });

  const sharedSecret = crypto.diffieHellman({
    privateKey,
    publicKey: peerPublicKey
  });

  const derived = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from('aeon-aegis-onion-v1'), KEY_LENGTH);
  
  // Defense-in-depth: Zeroize raw Diffie-Hellman secret immediately to prevent heap retention
  try {
    sharedSecret.fill(0);
  } catch {}

  return Buffer.from(derived);
}

/**
 * Wraps payload in multiple layers of encryption (from exit node back to entry node)
 */
export function wrapOnionCircuit(
  hops: HopInfo[],
  finalPayload: Buffer
): { entryPayload: Buffer; ephemeralPublicKeys: Buffer[] } {
  if (hops.length === 0) {
    throw new Error('Onion circuit requires at least one hop');
  }

  let currentPayload = finalPayload;
  const ephemeralPublicKeys: Buffer[] = [];

  // Wrap from back (Exit Node) to front (Entry Node)
  for (let i = hops.length - 1; i >= 0; i--) {
    const hop = hops[i];
    const isExit = i === hops.length - 1;

    // Generate ephemeral key pair for this layer
    const ephemeralKey = crypto.generateKeyPairSync('x25519');
    const ephemDer = ephemeralKey.publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const ephemPubKey = ephemDer.subarray(-32);
    ephemeralPublicKeys.unshift(ephemPubKey);

    const symmetricKey = deriveSymmetricKey(ephemeralKey.privateKey, hop.publicKey);
    const iv = crypto.randomBytes(IV_LENGTH);

    // Header payload contains routing target
    const headerObj = JSON.stringify({
      next: hop.nextHopAddress,
      exit: isExit
    });
    const headerBuf = Buffer.from(headerObj, 'utf8');
    const headerLenBuf = Buffer.alloc(2);
    headerLenBuf.writeUInt16BE(headerBuf.length, 0);

    // Combine header and payload before encrypting
    const plaintextToEncrypt = Buffer.concat([headerLenBuf, headerBuf, currentPayload]);

    const cipher = crypto.createCipheriv(ALGORITHM, symmetricKey, iv, { authTagLength: TAG_LENGTH });
    const encrypted = Buffer.concat([cipher.update(plaintextToEncrypt), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Defense-in-depth: Zeroize symmetric key buffer after cipher finalization
    symmetricKey.fill(0);

    // Construct layer buffer: [EphemPubKey(32)] [IV(12)] [AuthTag(16)] [Ciphertext]
    currentPayload = Buffer.concat([ephemPubKey, iv, tag, encrypted]);
  }

  return {
    entryPayload: currentPayload,
    ephemeralPublicKeys
  };
}

/**
 * Peels a single onion layer at a relay node using its static X25519 private key
 */
export function unwrapOnionLayer(
  nodePrivateKey: crypto.KeyObject,
  onionBuffer: Buffer
): UnwrappedLayer {
  const MIN_HEADER_SIZE = 32 + IV_LENGTH + TAG_LENGTH + 2;
  if (onionBuffer.length < MIN_HEADER_SIZE) {
    throw new Error('Invalid onion frame: Payload smaller than minimum header size');
  }

  // Extract frame metadata
  const ephemPubKey = onionBuffer.subarray(0, 32);
  const iv = onionBuffer.subarray(32, 32 + IV_LENGTH);
  const tag = onionBuffer.subarray(32 + IV_LENGTH, 32 + IV_LENGTH + TAG_LENGTH);
  const ciphertext = onionBuffer.subarray(32 + IV_LENGTH + TAG_LENGTH);

  // Derive symmetric decryption key
  const symmetricKey = deriveSymmetricKey(nodePrivateKey, ephemPubKey);

  const decipher = crypto.createDecipheriv(ALGORITHM, symmetricKey, iv, { authTagLength: TAG_LENGTH });
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  // Defense-in-depth: Zeroize symmetric key buffer
  symmetricKey.fill(0);

  // Read header length
  if (decrypted.length < 2) {
    throw new Error('Invalid onion plaintext: Truncated header length');
  }
  const headerLen = decrypted.readUInt16BE(0);
  if (decrypted.length < 2 + headerLen) {
    throw new Error('Invalid onion plaintext: Truncated header body');
  }

  const headerBuf = decrypted.subarray(2, 2 + headerLen);
  const innerPayload = decrypted.subarray(2 + headerLen);

  const headerObj = JSON.parse(headerBuf.toString('utf8'));

  return {
    nextHopAddress: headerObj.next,
    isExit: Boolean(headerObj.exit),
    innerPayload
  };
}