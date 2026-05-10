'use strict';
/**
 * session.js — encrypted peer session over a raw WebSocket
 *
 * Handshake (unencrypted JSON, single roundtrip):
 *   → HELLO  { version, pubkey: <spki-hex>, name? }
 *   ← HELLO  { version, pubkey: <spki-hex>, name? }
 *   Both sides derive shared key via X25519 ECDH.
 *   The peer's identifier (peerId) is derived locally from their ECDH
 *   public key, NOT from anything the peer claims. This forces proof-of-
 *   possession via the AEAD on the first encrypted frame and removes the
 *   prior peerId-squat attack surface.
 *
 *   All further frames: encrypt(pad(JSON)) with AES-256-GCM, AAD-bound to
 *   direction byte + monotonic uint32 sequence number per direction.
 *
 * Channel routing on receive:
 *   0x01–0xFF    open channels → 'message' event
 *   0x100–0x1FF  core system   → silently dropped (send blocked, receive discarded)
 *   0x200–0xFFFF extensions    → 'message' event (node decides if handler exists)
 *
 * @version  0.2.0
 * @license  LGPL-2.1
 */

const crypto = require('crypto');
const { EventEmitter }  = require('events');
const { generateEphemeralKeypair, deriveSessionKey, encrypt, decrypt, pad, unpad } = require('./crypto');
const { isCoreSystemType, typeName } = require('./types');

const PROTOCOL_VERSION = 1;
const HANDSHAKE_TIMEOUT_MS = 10_000;
const MAX_HELLO_LEN = 4096;     // pre-handshake DoS cap

// Derive a stable, locally-chosen peer identifier from the peer's ECDH pubkey.
// SHA-256 truncated to 16 bytes (32 hex chars). Identical pubkey → identical
// peerId; different pubkey → different peerId. Since each session uses an
// ephemeral keypair, peerId rotates per session — but is unforgeable for the
// duration of that session because only the holder of the matching private
// key can complete the AEAD on the first encrypted frame.
function peerIdFromPubkey(pubDer) {
  return crypto.createHash('sha256').update(pubDer).digest().slice(0, 16).toString('hex');
}

class Session extends EventEmitter {
  /**
   * @param {object} opts
   * @param {WebSocket}  opts.ws
   * @param {boolean}    opts.isInitiator
   * @param {Buffer}     opts.nodeId        Our node public identity (32B)
   */
  constructor({ ws, isInitiator, nodeId }) {
    super();
    this.ws          = ws;
    this.isInitiator = isInitiator;
    this.nodeId      = nodeId;     // local human-friendly id (still emitted in HELLO)

    this._key         = null;   // session key after handshake
    this._ready       = false;
    this._peerId      = null;   // hex string, derived from peer pubkey

    // AAD-bound replay protection: monotonic seq per direction.
    // dir = 0 means "frame sent by initiator", dir = 1 means "by responder".
    this._myDir       = isInitiator ? 0 : 1;
    this._peerDir     = isInitiator ? 1 : 0;
    this._seqOut      = 0;
    this._lastSeqIn   = -1;       // sentinel: nothing received yet

    const { privateKey, publicKey } = generateEphemeralKeypair();
    this._ephPriv = privateKey;
    this._ephPub  = publicKey;   // SPKI DER Buffer

    ws.on('message', (data) => this._onRaw(data));
    ws.on('close',   ()     => {
      // Cancel handshake watchdog so it doesn't fire on a torn-down session
      if (this._hsTimeout) { clearTimeout(this._hsTimeout); this._hsTimeout = null; }
      this.emit('close');
    });
    ws.on('error',   (e)    => this.emit('error', e));

    this._hsTimeout = setTimeout(() => {
      this._hsTimeout = null;
      if (!this._ready) {
        this.emit('error', new Error('Handshake timeout'));
        this._close();
      }
    }, HANDSHAKE_TIMEOUT_MS);

    if (isInitiator) this._sendHello();
  }

  get peerId() { return this._peerId; }
  get ready()  { return this._ready;  }

  // ── Send ──────────────────────────────────────────────────────────────────

  send(typeId, payload) {
    if (!this._ready) return false;
    if (isCoreSystemType(typeId)) return false;
    const plain = pad(Buffer.from(JSON.stringify({ t: typeId, d: payload })));
    // seq monotone per direction; uint32 wrap-around (~4.3B frames) is
    // beyond any realistic single-session lifetime, but if we did get
    // there the next ++ would still encode > 0 and remain monotone in
    // the tracking window. Defensive: refuse to send past 2^32-1.
    if (this._seqOut >= 0xffffffff) return false;
    const frame = encrypt(this._key, plain, this._myDir, this._seqOut);
    try {
      this.ws.send(frame);
      this._seqOut++;
      return true;
    } catch {
      return false;
    }
  }

  // ── Receive ───────────────────────────────────────────────────────────────

  _onRaw(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);

    if (!this._ready) {
      this._onHandshake(buf);
      return;
    }

    const result = decrypt(this._key, buf);
    if (!result) return;  // auth failure — drop silently

    // Direction binding: a frame must carry the *peer's* direction byte.
    // Without this check, an attacker on path could echo an A→B frame
    // back to B as if it had come from A (same key inside one session).
    if (result.dir !== this._peerDir) return;

    // Sequence binding: monotonic, drop replays/reorders.
    if (result.seq <= this._lastSeqIn) return;
    this._lastSeqIn = result.seq;

    const unpadded = unpad(result.plaintext);
    if (!unpadded) return;

    let msg;
    try { msg = JSON.parse(unpadded.toString()); } catch { return; }

    const { t: typeId, d: payload } = msg;

    if (isCoreSystemType(typeId)) return;  // 0x100–0x1FF: silently drop

    this.emit('message', { typeId, payload, peerId: this._peerId });
  }

  _onHandshake(buf) {
    // Full handshake body wrapped in try/catch — every call into Node crypto
    // can throw on malformed input (bad hex, bad SPKI structure), and the
    // pre-2026 implementation let those throws escape into the WebSocket
    // 'message' event handler, crashing the process. A single peer with a
    // garbage HELLO could DoS the whole node.
    try {
      if (buf.length > MAX_HELLO_LEN) {
        this._close(); return;
      }
      let hello;
      try { hello = JSON.parse(buf.toString('utf8')); } catch { this._close(); return; }

      if (hello.version !== PROTOCOL_VERSION || typeof hello.pubkey !== 'string') {
        this._close(); return;
      }

      const peerPubDer = Buffer.from(hello.pubkey, 'hex');
      // 32-byte X25519 key wrapped in SPKI DER is 44 bytes. A quick sanity
      // check rejects truncation/corruption from bad hex without paying for
      // the createPublicKey throw cycle.
      if (peerPubDer.length < 32 || peerPubDer.length > 100) {
        this._close(); return;
      }

      this._key    = deriveSessionKey(this._ephPriv, peerPubDer);
      this._peerId = peerIdFromPubkey(peerPubDer);
      this._ready  = true;
      if (this._hsTimeout) { clearTimeout(this._hsTimeout); this._hsTimeout = null; }

      if (!this.isInitiator) this._sendHello();

      this.emit('ready', { peerId: this._peerId });
    } catch (e) {
      // Any crypto failure (bad SPKI, ECDH compute error, …) tears down
      // the session cleanly instead of crashing the host process.
      this._close();
    }
  }

  _sendHello() {
    const hello = JSON.stringify({
      version: PROTOCOL_VERSION,
      pubkey:  this._ephPub.toString('hex'),
      // nodeId kept in the wire format for backward observability/debug —
      // it's NOT used by the receiver to derive peerId anymore.
      nodeId:  this.nodeId.toString('hex'),
    });
    try { this.ws.send(hello); } catch {}
  }

  _close() {
    try { this.ws.terminate(); } catch {}
  }
}

module.exports = { Session };
