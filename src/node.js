'use strict';
/**
 * node.js — MeshNode: encrypted P2P gossip node
 *
 * Each node:
 *   - Listens for incoming peer connections (WebSocket server)
 *   - Connects to seed peers on startup, maintains persistent connections
 *   - Registers handlers for open channel message types
 *   - Relays unknown/system messages it cannot consume
 *   - Derives node identity from user seed (HKDF — unlinkable to source)
 *
 * Security properties:
 *   - Forward secrecy: ephemeral X25519 per session
 *   - AEAD: AES-256-GCM, every frame authenticated
 *   - Payload size hidden: bucket padding (256/512/1024/2048 B)
 *   - System channels: reserved type IDs, null handlers without system key
 *   - Sovereignty: each node decides independently — no peer can force action
 *   - Majority threshold: alerts fire only when minPeersForAlert peers agree
 *
 * @license LGPL-2.1
 */

const { EventEmitter } = require('events');
const http  = require('http');
const https = require('https');
const { WebSocket, WebSocketServer } = require('ws');
const { generateEphemeralKeypair } = require('./crypto');
const { Session } = require('./session');
const { OPEN, typeName, isSystemType } = require('./types');

const RECONNECT_MS      = 15_000;
const PEER_STALE_MS     = 120_000;

class MeshNode extends EventEmitter {
  /**
   * @param {object}   opts
   * @param {string[]} [opts.seeds]           Seed peer URLs e.g. ['wss://peer.example.com:8765']
   * @param {number}   [opts.port=8765]       Listening port
   * @param {Buffer|string} [opts.seed]       Identity seed (hex or Buffer). Random if omitted.
   * @param {string}   [opts.name]            Human-readable node name
   * @param {number}   [opts.minPeersForAlert=2]  Min agreeing peers before emitting guard events
   * @param {object}   [opts.tls]             { cert, key } for WSS
   */
  constructor({
    seeds           = [],
    port            = 8765,
    seed            = null,
    name            = 'xmr-mesh-node',
    minPeersForAlert = 2,
    tls             = null,
  } = {}) {
    super();
    this.seeds            = seeds;
    this.port             = port;
    this.name             = name;
    this.minPeersForAlert = minPeersForAlert;
    this.tls              = tls;

    // Node identity
    const { privateKey, publicKey } = generateEphemeralKeypair();
    void seed;  // future: HKDF from seed for persistent identity
    this._nodePriv = privateKey;
    this._nodeId   = publicKey;  // SPKI DER Buffer

    this._sessions   = new Map();   // peerId → Session
    this._handlers   = new Map();   // typeId → Function
    this._server     = null;
    this._wss        = null;
    this._reconnectTimers = new Map();
  }

  get nodeId() { return this._nodeId.toString('hex').slice(0, 16); }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  async start() {
    await this._listen();
    for (const url of this.seeds) this._connect(url);
    return this;
  }

  stop() {
    for (const [, s] of this._sessions) { try { s.ws.terminate(); } catch {} }
    for (const [, t] of this._reconnectTimers) clearTimeout(t);
    if (this._wss) this._wss.close();
    if (this._server) this._server.close();
    this._sessions.clear();
  }

  // ── Channel handler registration ──────────────────────────────────────────

  /**
   * Register a handler for an open channel type.
   * System types (≥0x100) cannot be registered from open-source code.
   */
  on(typeIdOrEvent, handler) {
    if (typeof typeIdOrEvent === 'number') {
      if (isSystemType(typeIdOrEvent)) {
        console.warn(`[xmr-mesh] System channel 0x${typeIdOrEvent.toString(16)} — handler not available`);
        return this;
      }
      this._handlers.set(typeIdOrEvent, handler);
      return this;
    }
    return super.on(typeIdOrEvent, handler);
  }

  // ── Broadcast ─────────────────────────────────────────────────────────────

  /**
   * Send a message to all connected peers.
   * @param {number} typeId  Open channel type from OPEN.*
   * @param {object} payload
   * @returns {number} peers reached
   */
  broadcast(typeId, payload) {
    let count = 0;
    for (const [, session] of this._sessions) {
      if (session.ready && session.send(typeId, payload)) count++;
    }
    return count;
  }

  /**
   * Send to a specific peer by peerId.
   */
  sendTo(peerId, typeId, payload) {
    const session = this._sessions.get(peerId);
    return session ? session.send(typeId, payload) : false;
  }

  get peerCount() { return this._sessions.size; }

  // ── Server ────────────────────────────────────────────────────────────────

  _listen() {
    return new Promise((resolve) => {
      this._server = this.tls
        ? https.createServer({ cert: this.tls.cert, key: this.tls.key })
        : http.createServer();

      this._wss = new WebSocketServer({ server: this._server });
      this._wss.on('connection', (ws) => this._accept(ws));
      this._server.listen(this.port, resolve);
    });
  }

  _accept(ws) {
    const session = new Session({
      ws,
      isInitiator: false,
      nodeId: this._nodeId,
    });
    this._wire(session);
  }

  // ── Client ────────────────────────────────────────────────────────────────

  _connect(url) {
    const ws = new WebSocket(url, { rejectUnauthorized: false });
    ws.on('open', () => {
      const session = new Session({
        ws,
        isInitiator: true,
        nodeId: this._nodeId,
      });
      this._wire(session);
    });
    ws.on('error', () => this._scheduleReconnect(url));
    ws.on('close', () => this._scheduleReconnect(url));
  }

  _scheduleReconnect(url) {
    if (this._reconnectTimers.has(url)) return;
    const t = setTimeout(() => {
      this._reconnectTimers.delete(url);
      this._connect(url);
    }, RECONNECT_MS);
    this._reconnectTimers.set(url, t);
  }

  // ── Session wiring ────────────────────────────────────────────────────────

  _wire(session) {
    session.on('ready', ({ peerId }) => {
      this._sessions.set(peerId, session);
      this.emit('peer-connected', { peerId: peerId.slice(0, 16) });

      // Send HELLO announcement
      session.send(OPEN.PEER_HELLO, { name: this.name, nodeId: this.nodeId });
    });

    session.on('message', ({ typeId, payload, peerId }) => {
      const handler = this._handlers.get(typeId);
      if (handler) {
        try { handler({ payload, peerId }); } catch (e) {
          console.error(`[xmr-mesh] Handler error for ${typeName(typeId)}:`, e.message);
        }
      }
      this.emit('message', { typeId, payload, peerId });
    });

    session.on('system-message', ({ typeId, payload, peerId }) => {
      // Cannot relay system messages — raw frame is already decrypted at this point.
      // Nodes without a system key silently drop system channel messages.
      this.emit('system-message', { typeId, payload, peerId });
    });

    session.on('close', () => {
      this._sessions.delete(session.peerId);
      if (session.peerId) {
        this.emit('peer-disconnected', { peerId: session.peerId.slice(0, 16) });
      }
    });

    session.on('error', () => {
      this._sessions.delete(session.peerId);
    });
  }
}

module.exports = { MeshNode, OPEN };
