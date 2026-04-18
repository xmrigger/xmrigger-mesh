'use strict';
/**
 * crypto.js — session key exchange + AEAD encryption
 *
 * Key exchange : X25519 ECDH (Node.js built-in, no dependencies)
 * Encryption   : AES-256-GCM (ChaCha20 not in all Node ≥15 builds; GCM is universal)
 * Identity     : HKDF-SHA256 from user seed → stable keypair per node
 *
 * Wire format per message:
 *   [ 2B length ][ 12B nonce ][ NB ciphertext+tag ]
 *
 * @version  0.1.0
 * @released 2026-04-18
 * @license  LGPL-2.1
 */

const crypto = require('crypto');

const ALGO       = 'aes-256-gcm';
const TAG_LEN    = 16;
const NONCE_LEN  = 12;
const KEY_LEN    = 32;

// ── Identity key derivation ──────────────────────────────────────────────────

/**
 * Derive a stable X25519 keypair from an arbitrary seed buffer.
 * Uses HKDF-SHA256 so the mesh identity is unlinkable to the source seed.
 *
 * @param {Buffer|string} seed  Wallet seed or any secret
 * @param {string}        [label='xmrigger-mesh-v1']
 * @returns {{ privateKey: Buffer, publicKey: Buffer }}
 */
// TODO v0.2: Node.js crypto does not expose raw X25519 scalar import (v15-v22).
// Until then, seed is ignored and identity is ephemeral (regenerated on restart).
function deriveIdentity(seed, _label) {
  if (seed != null) {
    console.warn('[xmrigger-mesh] deriveIdentity: seed ignored — persistent identity not yet implemented (v0.2)');
  }
  return generateEphemeralKeypair();
}

/**
 * Generate an ephemeral X25519 keypair (per session).
 * @returns {{ privateKey: KeyObject, publicKey: Buffer }}
 */
function generateEphemeralKeypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' });
  return { privateKey, publicKey: pubRaw };
}

/**
 * Derive shared session key via X25519 ECDH.
 * @param {KeyObject} ourPrivateKey
 * @param {Buffer}    peerPublicKeyDer  SPKI DER
 * @returns {Buffer}  32-byte shared key
 */
function deriveSessionKey(ourPrivateKey, peerPublicKeyDer) {
  const peerPub = crypto.createPublicKey({ key: peerPublicKeyDer, format: 'der', type: 'spki' });
  const shared  = crypto.diffieHellman({ privateKey: ourPrivateKey, publicKey: peerPub });
  return crypto.createHash('sha256').update(shared).digest();
}

// ── AEAD encryption ──────────────────────────────────────────────────────────

/**
 * Encrypt plaintext with AES-256-GCM.
 * @param {Buffer} key        32-byte session key
 * @param {Buffer} plaintext
 * @returns {Buffer}  nonce(12) + ciphertext + tag(16)
 */
function encrypt(key, plaintext) {
  const nonce  = crypto.randomBytes(NONCE_LEN);
  const cipher = crypto.createCipheriv(ALGO, key, nonce, { authTagLength: TAG_LEN });
  const ct     = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]);
}

/**
 * Decrypt AES-256-GCM ciphertext.
 * @param {Buffer} key
 * @param {Buffer} buf  nonce(12) + ciphertext + tag(16)
 * @returns {Buffer|null}  plaintext or null on auth failure
 */
function decrypt(key, buf) {
  if (buf.length < NONCE_LEN + TAG_LEN) return null;
  try {
    const nonce  = buf.slice(0, NONCE_LEN);
    const tag    = buf.slice(buf.length - TAG_LEN);
    const ct     = buf.slice(NONCE_LEN, buf.length - TAG_LEN);
    const decipher = crypto.createDecipheriv(ALGO, key, nonce, { authTagLength: TAG_LEN });
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    return null;
  }
}

// ── Bucket padding ───────────────────────────────────────────────────────────

const BUCKETS = [256, 512, 1024, 2048];

/**
 * Pad plaintext to the next bucket size.
 * All messages on the wire are one of 4 fixed sizes — payload size is hidden.
 */
function pad(buf) {
  const target = BUCKETS.find(b => b >= buf.length) || BUCKETS[BUCKETS.length - 1];
  if (buf.length > BUCKETS[BUCKETS.length - 1]) {
    throw new Error(`Message too large: ${buf.length} bytes`);
  }
  const out = Buffer.alloc(target, 0);
  buf.copy(out);
  out.writeUInt16BE(buf.length, target - 2);  // store real length in last 2 bytes
  return out;
}

/**
 * Unpad to recover original plaintext.
 */
function unpad(buf) {
  const realLen = buf.readUInt16BE(buf.length - 2);
  return buf.slice(0, realLen);
}

module.exports = {
  generateEphemeralKeypair,
  deriveIdentity,
  deriveSessionKey,
  encrypt,
  decrypt,
  pad,
  unpad,
  NONCE_LEN,
  TAG_LEN,
};
