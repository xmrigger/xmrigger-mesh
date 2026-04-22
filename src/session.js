'use strict';
/**
 * session.js — encrypted peer session over a raw WebSocket
 *
 * Handshake (unencrypted, then all subsequent traffic is encrypted):
 *   → HELLO  { version: 1, pubkey: <spki-hex>, nodeId: <hex> }
 *   ← HELLO  { version: 1, pubkey: <spki-hex>, nodeId: <hex> }
 *   Both sides derive shared key via X25519 ECDH.
 *   All further frames: encrypt(pad(JSON)) with AES-256-GCM.
 *
 * Channel routing on receive:
 *   0x01–0xFF    open channels → 'message' event
 *   0x100–0x1FF  core system   → silently dropped (send blocked, receive discarded)
 *   0x200–0xFFFF extensions    → 'message' event (node decides if handler exists)
 *
 * @version  0.1.0
 * @released 2026-04-18
 * @license  LGPL-2.1
 */

const { EventEmitter }  = require('events');
const { generateEphemeralKeypair, deriveSessionKey, encrypt, decrypt, pad, unpad } = require('./crypto');
const { isCoreSystemType, typeName } = require('./types');

const PROTOCOL_VERSION = 1;
const HANDSHAKE_TIMEOUT_MS = 10_000;

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
    this.nodeId      = nodeId;

    this._key         = null;   // session key after handshake
    this._ready       = false;
    this._peerId      = null;   // peer nodeId hex

    const { privateKey, publicKey } = generateEphemeralKeypair();
    this._ephPriv = privateKey;
    this._ephPub  = publicKey;   // SPKI DER Buffer

    ws.on('message', (data) => this._onRaw(data));
    ws.on('close',   ()     => this.emit('close'));
    ws.on('error',   (e)    => this.emit('error', e));

    this._hsTimeout = setTimeout(() => {
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
    const frame = encrypt(this._key, plain);
    try {
      this.ws.send(frame);
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

    const plain = decrypt(this._key, buf);
    if (!plain) return;  // auth failure — drop silently

    let msg;
    try { msg = JSON.parse(unpad(plain).toString()); } catch { return; }

    const { t: typeId, d: payload } = msg;

    if (isCoreSystemType(typeId)) return;  // 0x100–0x1FF: silently drop

    this.emit('message', { typeId, payload, peerId: this._peerId });
  }

  _onHandshake(buf) {
    let hello;
    try { hello = JSON.parse(buf.toString()); } catch { this._close(); return; }

    if (hello.version !== PROTOCOL_VERSION || !hello.pubkey || !hello.nodeId) {
      this._close(); return;
    }

    const peerPubDer = Buffer.from(hello.pubkey, 'hex');
    this._key    = deriveSessionKey(this._ephPriv, peerPubDer);
    this._peerId = hello.nodeId;
    this._ready  = true;
    clearTimeout(this._hsTimeout);

    if (!this.isInitiator) this._sendHello();

    this.emit('ready', { peerId: this._peerId });
  }

  _sendHello() {
    const hello = JSON.stringify({
      version: PROTOCOL_VERSION,
      pubkey:  this._ephPub.toString('hex'),
      nodeId:  this.nodeId.toString('hex'),
    });
    try { this.ws.send(hello); } catch {}
  }

  _close() {
    try { this.ws.terminate(); } catch {}
  }
}

module.exports = { Session };
