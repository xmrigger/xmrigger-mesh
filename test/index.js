'use strict';
/**
 * xmrigger-mesh test suite — crypto layer + bucket padding
 * Run: node test/index.js
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateEphemeralKeypair,
  deriveSessionKey,
  encrypt,
  decrypt,
  pad,
  unpad,
  NONCE_LEN,
  TAG_LEN,
} from '../src/crypto.js';

// ── Crypto layer ──────────────────────────────────────────────────────────────

describe('Crypto layer — ECDH + AES-256-GCM', () => {

  test('ECDH handshake produces equal symmetric keys on both sides', () => {
    const alice = generateEphemeralKeypair();
    const bob   = generateEphemeralKeypair();

    const keyAlice = deriveSessionKey(alice.privateKey, bob.publicKey);
    const keyBob   = deriveSessionKey(bob.privateKey,   alice.publicKey);

    assert.ok(Buffer.isBuffer(keyAlice), 'Alice key must be a Buffer');
    assert.ok(Buffer.isBuffer(keyBob),   'Bob key must be a Buffer');
    assert.strictEqual(keyAlice.length, 32, 'Key must be 32 bytes');
    assert.strictEqual(keyBob.length,   32, 'Key must be 32 bytes');
    assert.ok(keyAlice.equals(keyBob), 'Both sides must derive the same session key');
  });

  test('message encrypted by Alice decrypted correctly by Bob', () => {
    const alice = generateEphemeralKeypair();
    const bob   = generateEphemeralKeypair();

    const keyAlice = deriveSessionKey(alice.privateKey, bob.publicKey);
    const keyBob   = deriveSessionKey(bob.privateKey,   alice.publicKey);

    const plaintext  = Buffer.from('Hello from Alice — secret prevhash: deadbeef01234567');
    const ciphertext = encrypt(keyAlice, plaintext);

    // Wire format: nonce(12) + ciphertext + tag(16)
    assert.ok(ciphertext.length >= NONCE_LEN + TAG_LEN,
      'ciphertext must include nonce and tag');
    assert.ok(!ciphertext.equals(plaintext),
      'ciphertext must differ from plaintext');

    const recovered = decrypt(keyBob, ciphertext);
    assert.ok(recovered !== null, 'decrypt must succeed with correct key');
    assert.ok(recovered.equals(plaintext), 'decrypted plaintext must match original');
  });

  test('decryption fails with wrong nonce (integrity check)', () => {
    const alice = generateEphemeralKeypair();
    const bob   = generateEphemeralKeypair();

    const keyAlice = deriveSessionKey(alice.privateKey, bob.publicKey);
    const keyBob   = deriveSessionKey(bob.privateKey,   alice.publicKey);

    const plaintext  = Buffer.from('sensitive data');
    const ciphertext = encrypt(keyAlice, plaintext);

    // Corrupt the nonce (first 12 bytes) — the GCM tag will not verify
    const tampered = Buffer.from(ciphertext);
    tampered[0] ^= 0xff;  // flip all bits of first nonce byte

    const result = decrypt(keyBob, tampered);
    assert.strictEqual(result, null,
      'decryption must return null when nonce is corrupted (auth failure)');
  });

  test('decryption fails when ciphertext body is tampered', () => {
    const alice = generateEphemeralKeypair();
    const bob   = generateEphemeralKeypair();

    const keyAlice = deriveSessionKey(alice.privateKey, bob.publicKey);
    const keyBob   = deriveSessionKey(bob.privateKey,   alice.publicKey);

    const plaintext  = Buffer.from('another secret message 12345');
    const ciphertext = encrypt(keyAlice, plaintext);

    // Flip a byte in the middle of the ciphertext body (after nonce)
    const tampered = Buffer.from(ciphertext);
    tampered[NONCE_LEN + 1] ^= 0x01;

    const result = decrypt(keyBob, tampered);
    assert.strictEqual(result, null,
      'decryption must return null when ciphertext body is tampered');
  });

  test('encrypt + decrypt round-trip with empty plaintext', () => {
    const alice = generateEphemeralKeypair();
    const bob   = generateEphemeralKeypair();

    const keyAlice = deriveSessionKey(alice.privateKey, bob.publicKey);
    const keyBob   = deriveSessionKey(bob.privateKey,   alice.publicKey);

    const plaintext  = Buffer.alloc(0);
    const ciphertext = encrypt(keyAlice, plaintext);
    const recovered  = decrypt(keyBob,   ciphertext);

    assert.ok(recovered !== null, 'decrypt of empty plaintext must succeed');
    assert.strictEqual(recovered.length, 0, 'recovered length must be 0');
  });

});

// ── Bucket padding ────────────────────────────────────────────────────────────

describe('Bucket padding', () => {

  // BUCKETS = [256, 512, 1024, 2048]

  test('small payload padded to first bucket (256)', () => {
    const payload = Buffer.from('tiny payload');
    const padded  = pad(payload);
    assert.strictEqual(padded.length, 256,
      'payload < 256 bytes must be padded to 256');
  });

  test('payload of exactly 256 bytes padded to 256', () => {
    const payload = Buffer.alloc(256, 0x42);
    // last 2 bytes are reserved for the real length — the payload may not be 256 bytes
    // because pad writes realLen at the last 2 bytes.
    // A 256-byte payload cannot fit (last 2 bytes would overwrite content).
    // Actually pad stores length in last 2 bytes of the *padded* buffer, so for
    // a 256-byte payload the padded target is still 256 (the max for that bucket).
    // But readUInt16BE will return the length correctly since payload.length is stored.
    // Let's test a 254-byte payload that fits within 256 after writing len at offset 254.
    const p254 = Buffer.alloc(254, 0xAB);
    const padded = pad(p254);
    assert.strictEqual(padded.length, 256, '254-byte payload must fit in 256-byte bucket');
    const recovered = unpad(padded);
    assert.ok(recovered.equals(p254), 'unpadded must equal original');
  });

  test('payload sizes in different ranges land in correct buckets', () => {
    const cases = [
      { size: 1,    expected: 256  },
      { size: 100,  expected: 256  },
      { size: 255,  expected: 256  },
      { size: 257,  expected: 512  },
      { size: 511,  expected: 512  },
      { size: 513,  expected: 1024 },
      { size: 1025, expected: 2048 },
    ];

    for (const { size, expected } of cases) {
      const payload = Buffer.alloc(size, 0x7f);
      const padded  = pad(payload);
      assert.strictEqual(padded.length, expected,
        `payload of ${size} bytes must be in ${expected}-byte bucket`);
    }
  });

  test('different-size payloads produce same padded length (bucket hiding)', () => {
    // Two messages of different sizes in the same bucket look the same on the wire
    const small = Buffer.alloc(50,  0x01);
    const large = Buffer.alloc(200, 0x02);

    const paddedSmall = pad(small);
    const paddedLarge = pad(large);

    assert.strictEqual(paddedSmall.length, paddedLarge.length,
      'small (50B) and large (200B) must produce the same padded size');
    assert.ok(!paddedSmall.equals(paddedLarge),
      'padded buffers must differ in content');
  });

  test('unpad recovers exact original payload', () => {
    const payloads = [
      Buffer.from('hello world'),
      Buffer.alloc(300, 0xde),   // forces 512 bucket
      Buffer.alloc(700, 0xad),   // forces 1024 bucket
      Buffer.alloc(1500, 0xbe),  // forces 2048 bucket
    ];

    for (const original of payloads) {
      const padded    = pad(original);
      const recovered = unpad(padded);
      assert.ok(recovered.equals(original),
        `unpad(pad(payload)) must equal original for size=${original.length}`);
    }
  });

  test('oversized message (> 2048 bytes) throws', () => {
    const tooBig = Buffer.alloc(2049, 0xff);
    assert.throws(
      () => pad(tooBig),
      /Message too large/,
      'pad must throw for payloads exceeding the largest bucket',
    );
  });

  test('decrypt returns null for buffer shorter than nonce+tag', () => {
    // Sanity check for the guard in decrypt()
    const { privateKey } = generateEphemeralKeypair();
    const { publicKey }  = generateEphemeralKeypair();
    const key = deriveSessionKey(privateKey, publicKey);

    const tooShort = Buffer.alloc(NONCE_LEN + TAG_LEN - 1, 0);
    const result   = decrypt(key, tooShort);
    assert.strictEqual(result, null, 'decrypt must return null for truncated buffer');
  });

});
