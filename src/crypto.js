'use strict';
/**
 * crypto.js — session key exchange + AEAD encryption
 *
 * Key exchange : X25519 ECDH (Node.js built-in, no dependencies)
 * Encryption   : AES-256-GCM with AAD = direction || seq (replay protection)
 * Identity     : HKDF-SHA256 from user seed → stable keypair per node
 *
 * Wire format per message:
 *   [ 12B nonce ][ 1B dir ][ 4B seq BE ][ NB ciphertext+tag ]
 *
 * The 5-byte AAD prefix (dir + seq) is also bound into the AES-GCM tag, so
 * any tampering invalidates the frame. Receivers track last seq per peer
 * direction and drop any frame with seq ≤ lastSeen — this stops replay,
 * including direction-cross replay where an attacker could otherwise echo
 * an A→B frame back to B as if it had come from A.
 *
 * @version  0.2.0
 * @license  LGPL-2.1
 */

const crypto = require('crypto');

const ALGO       = 'aes-256-gcm';
const TAG_LEN    = 16;
const NONCE_LEN  = 12;
const KEY_LEN    = 32;
const AAD_LEN    = 5;     // 1B direction + 4B seq BE
const HEADER_LEN = NONCE_LEN + AAD_LEN;

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
 * Encrypt plaintext with AES-256-GCM, binding direction and sequence number.
 * @param {Buffer} key        32-byte session key
 * @param {Buffer} plaintext
 * @param {number} dir        0 (initiator) or 1 (responder) — the *sender's* role
 * @param {number} seq        monotonic uint32 (per session per direction)
 * @returns {Buffer}  nonce(12) + dir(1) + seq(4) + ciphertext + tag(16)
 */
function encrypt(key, plaintext, dir, seq) {
  const nonce  = crypto.randomBytes(NONCE_LEN);
  const aad    = Buffer.alloc(AAD_LEN);
  aad.writeUInt8(dir & 0xff, 0);
  aad.writeUInt32BE(seq >>> 0, 1);
  const cipher = crypto.createCipheriv(ALGO, key, nonce, { authTagLength: TAG_LEN });
  cipher.setAAD(aad);
  const ct     = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return Buffer.concat([nonce, aad, ct, tag]);
}

/**
 * Decrypt AES-256-GCM ciphertext, returning plaintext + AAD fields.
 * Replay/direction enforcement is the caller's responsibility (the AAD is
 * authenticated, so the values returned here are trustworthy).
 * @param {Buffer} key
 * @param {Buffer} buf  nonce(12) + dir(1) + seq(4) + ciphertext + tag(16)
 * @returns {{plaintext: Buffer, dir: number, seq: number}|null}  null on auth failure
 */
function decrypt(key, buf) {
  if (buf.length < HEADER_LEN + TAG_LEN) return null;
  try {
    const nonce = buf.slice(0, NONCE_LEN);
    const aad   = buf.slice(NONCE_LEN, HEADER_LEN);
    const tag   = buf.slice(buf.length - TAG_LEN);
    const ct    = buf.slice(HEADER_LEN, buf.length - TAG_LEN);
    const decipher = crypto.createDecipheriv(ALGO, key, nonce, { authTagLength: TAG_LEN });
    decipher.setAuthTag(tag);
    decipher.setAAD(aad);
    const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
    return {
      plaintext,
      dir: aad.readUInt8(0),
      seq: aad.readUInt32BE(1),
    };
  } catch {
    return null;
  }
}

// ── Bucket padding ───────────────────────────────────────────────────────────

const BUCKETS = [256, 512, 1024, 2048];

/**
 * Pad plaintext to the next bucket size.
 * All messages on the wire are one of 4 fixed sizes — payload size is hidden.
 *
 * The trailing 2 bytes of the bucket carry the original length, so the
 * bucket selection has to leave room for them: we choose the smallest
 * bucket that fits `buf.length + 2`. Without the +2 reserve, a message
 * exactly equal to a bucket size would have its last 2 payload bytes
 * silently overwritten by the length field.
 */
const PAD_LEN_OVERHEAD = 2;
function pad(buf) {
  const required = buf.length + PAD_LEN_OVERHEAD;
  const target = BUCKETS.find(b => b >= required) || BUCKETS[BUCKETS.length - 1];
  if (required > BUCKETS[BUCKETS.length - 1]) {
    throw new Error(`Message too large: ${buf.length} bytes (max ${BUCKETS[BUCKETS.length - 1] - PAD_LEN_OVERHEAD})`);
  }
  const out = Buffer.alloc(target, 0);
  buf.copy(out);
  out.writeUInt16BE(buf.length, target - 2);
  return out;
}

/**
 * Unpad to recover original plaintext.
 * Returns null if the encoded length is inconsistent with the buffer
 * (corruption, tampering that survived AEAD only via a key-equal collision —
 * astronomically improbable but worth refusing rather than silently slicing).
 */
function unpad(buf) {
  if (buf.length < 2) return null;
  const realLen = buf.readUInt16BE(buf.length - 2);
  if (realLen > buf.length - 2) return null;
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
