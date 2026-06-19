'use strict';
/**
 * limits.js — per-peer rate limiting + strike/quarantine/ban escalation
 *
 * Defense layers (cheap → expensive in defender CPU):
 *   1. Frame size cap per channel band       → strike if exceeded
 *   2. Token bucket per channel band         → strike if exhausted
 *   3. Global byte budget per peer           → strike if exhausted
 *   4. Reserved-band frame received          → strike (policy violation)
 *   5. Strike escalation                     → soft quarantine
 *   6. Soft quarantine threshold             → hard quarantine + kill session
 *   7. Hard quarantine repetition            → persistent ban (IP/nodeId)
 *
 * Channel bands (from types.js):
 *   OPEN     : 0x01–0xFF   — public, anyone can use
 *   RESERVED : 0x100–0x1FF — core system reserved range (hard-blocked locally)
 *   EXTENSION: 0x200+      — subclass extensions
 *
 * Token bucket semantics: capacity C, refill R tokens/sec. A frame
 * consumes 1 token. Below capacity → pass. Empty → strike + drop.
 *
 * @version  0.1.0
 * @license  LGPL-2.1
 */

const { BanList } = require('./bans');

const PROFILES = {
  strict: {
    perPeer:    { frameCap: 30, frameRefill: 6,  byteCap: 32_768, byteRefill: 6_144  },
    open:       { frameCap: 4,  frameRefill: 1,  frameSize: 2_048 },
    reserved:   { frameCap: 20, frameRefill: 4,  frameSize: 8_192 },
    extension:  { frameCap: 2,  frameRefill: 0.5, frameSize: 4_096 },
    priority:   [0x10, 0x11],  // PREVHASH_ANNOUNCE, GUARD_ALERT (never rate-dropped)
    strikes: {
      windowMs: 60_000,
      softThreshold: 3,
      hardThreshold: 6,
      softMs:  300_000,   // 5 min silence
      hardMs:  3_600_000, // 1h quarantine
    },
    ban: {
      hardQuarantinesIn24h: 3,
      durationMs: 30 * 24 * 3600 * 1000,
    },
  },
  default: {
    perPeer:    { frameCap: 60, frameRefill: 12, byteCap: 65_536, byteRefill: 12_288 },
    open:       { frameCap: 8,  frameRefill: 2,  frameSize: 4_096 },
    reserved:   { frameCap: 50, frameRefill: 10, frameSize: 16_384 },
    extension:  { frameCap: 5,  frameRefill: 1,  frameSize: 8_192 },
    priority:   [0x10, 0x11],
    strikes: {
      windowMs: 60_000,
      softThreshold: 3,
      hardThreshold: 6,
      softMs:  300_000,
      hardMs:  3_600_000,
    },
    ban: {
      hardQuarantinesIn24h: 3,
      durationMs: 30 * 24 * 3600 * 1000,
    },
  },
  generous: {
    perPeer:    { frameCap: 200, frameRefill: 40, byteCap: 524_288, byteRefill: 65_536 },
    open:       { frameCap: 20, frameRefill: 5,  frameSize: 8_192 },
    reserved:   { frameCap: 150, frameRefill: 30, frameSize: 65_536 },
    extension:  { frameCap: 30, frameRefill: 6,  frameSize: 32_768 },
    priority:   [0x10, 0x11],
    strikes: {
      windowMs: 60_000,
      softThreshold: 8,
      hardThreshold: 16,
      softMs:  120_000,
      hardMs:  1_800_000,
    },
    ban: {
      hardQuarantinesIn24h: 4,
      durationMs: 7 * 24 * 3600 * 1000,
    },
  },
};

function bandOf(typeId) {
  if (typeId >= 0x100 && typeId <= 0x1FF) return 'reserved';
  if (typeId >= 0x200) return 'extension';
  return 'open';
}

class TokenBucket {
  constructor(capacity, refillPerSec) {
    this.capacity = capacity;
    this.refill   = refillPerSec;
    this.tokens   = capacity;
    this.last     = Date.now();
  }
  _refill(now) {
    const dt = (now - this.last) / 1000;
    if (dt <= 0) return;
    this.tokens = Math.min(this.capacity, this.tokens + dt * this.refill);
    this.last = now;
  }
  take(n = 1, now = Date.now()) {
    this._refill(now);
    if (this.tokens >= n) { this.tokens -= n; return true; }
    return false;
  }
}

/**
 * Per-peer state (token buckets + strike ring + quarantine timestamp).
 */
class PeerState {
  constructor(profile) {
    this.profile = profile;
    this.perPeerFrames = new TokenBucket(profile.perPeer.frameCap, profile.perPeer.frameRefill);
    this.perPeerBytes  = new TokenBucket(profile.perPeer.byteCap,  profile.perPeer.byteRefill);
    this.bandBuckets = {
      open:      new TokenBucket(profile.open.frameCap,      profile.open.frameRefill),
      reserved:  new TokenBucket(profile.reserved.frameCap,  profile.reserved.frameRefill),
      extension: new TokenBucket(profile.extension.frameCap, profile.extension.frameRefill),
    };
    this.strikes = [];          // array of strike timestamps (ms)
    this.softUntil = 0;         // soft quarantine expiry
    this.hardUntil = 0;         // hard quarantine expiry
    this.hardHistory = [];      // timestamps of hard-quarantine entries
  }

  _pruneStrikes(now) {
    const cutoff = now - this.profile.strikes.windowMs;
    while (this.strikes.length && this.strikes[0] < cutoff) this.strikes.shift();
    const dayCutoff = now - 24 * 3600 * 1000;
    while (this.hardHistory.length && this.hardHistory[0] < dayCutoff) this.hardHistory.shift();
  }
}

/**
 * Verdict returned by check():
 *   { allow: true }                                 → frame passes
 *   { allow: false, reason, escalate? }            → frame dropped
 *
 * escalate values:
 *   'soft'  → peer silenced for softMs (sessione vive, frame ignorati)
 *   'hard'  → kill session, add to ban for hardMs
 *   'ban'   → persist long-term ban (IP + nodeId)
 */
class PeerLimiter {
  /**
   * @param {object}  [opts]
   * @param {string}  [opts.profile='default']
   * @param {object}  [opts.override]              partial override of profile values
   * @param {BanList} [opts.banList]               injected (tests/shared)
   * @param {Function} [opts.now=Date.now]
   */
  constructor({ profile = 'default', override = null, banList = null, now = Date.now } = {}) {
    const base = PROFILES[profile];
    if (!base) throw new Error(`[xmrigger-mesh/limits] unknown profile: ${profile}`);
    this.profileName = profile;
    this.profile  = override ? deepMerge(base, override) : base;
    this.banList  = banList || new BanList();
    this._peers   = new Map();   // peerId → PeerState (ephemeral, cleared on disconnect)
    // hardHistory tracked by IP — survives session forget() so an attacker
    // can't bypass ban escalation by reconnecting with a fresh peerId.
    this._hardByIp = new Map();   // ip → number[] (timestamps)
    this._now     = now;
  }

  _stateFor(peerId) {
    let s = this._peers.get(peerId);
    if (!s) { s = new PeerState(this.profile); this._peers.set(peerId, s); }
    return s;
  }

  /**
   * Drop the peer state. Call when session closes.
   */
  forget(peerId) { this._peers.delete(peerId); }

  /**
   * Check an inbound frame against all limits.
   * @param {object} ctx
   * @param {string} ctx.peerId
   * @param {number} ctx.typeId
   * @param {number} ctx.frameSize
   * @param {string} [ctx.ip]       remote address (for ban scope)
   * @param {string} [ctx.nodeId]   advertised nodeId (for ban scope)
   * @returns {{allow:boolean, reason?:string, escalate?:string, banKeys?:string[]}}
   */
  check({ peerId, typeId, frameSize, ip, nodeId }) {
    const now = this._now();
    const s = this._stateFor(peerId);
    s._pruneStrikes(now);
    this._pruneHardHistory(ip, now);

    // Hard quarantine already in effect → drop + escalate so caller kills
    if (s.hardUntil > now) {
      return { allow: false, reason: 'hard-quarantine', escalate: 'hard' };
    }

    const band = bandOf(typeId);
    const isPriority = this.profile.priority.includes(typeId);

    // Soft quarantine: drop the frame, but KEEP accumulating strikes so an
    // attacker who insists is escalated to hard. This is the "punitive" path.
    if (s.softUntil > now) {
      return this._strike(s, now, 'soft-quarantine-insist', { ip, nodeId });
    }

    // Layer 4: reserved band probed = policy violation
    if (band === 'reserved') {
      return this._strike(s, now, 'reserved-band-violation', { ip, nodeId });
    }

    // Layer 1: frame size cap
    const sizeCap = this.profile[band].frameSize;
    if (frameSize > sizeCap) {
      return this._strike(s, now, 'frame-too-large', { ip, nodeId });
    }

    // Priority lane bypass for OPEN tempo-sensitive (PREVHASH/GUARD)
    // — still counted against per-peer byte budget, never rate-dropped.
    if (!isPriority) {
      if (!s.bandBuckets[band].take(1, now)) {
        return this._strike(s, now, `band-${band}-exhausted`, { ip, nodeId });
      }
      if (!s.perPeerFrames.take(1, now)) {
        return this._strike(s, now, 'peer-frames-exhausted', { ip, nodeId });
      }
    }

    // Layer 3: per-peer byte budget (always enforced, priority included)
    if (!s.perPeerBytes.take(frameSize, now)) {
      return this._strike(s, now, 'peer-bytes-exhausted', { ip, nodeId });
    }

    return { allow: true };
  }

  _pruneHardHistory(ip, now) {
    if (!ip) return;
    const arr = this._hardByIp.get(ip);
    if (!arr) return;
    const cutoff = now - 24 * 3600_000;
    while (arr.length && arr[0] < cutoff) arr.shift();
    if (arr.length === 0) this._hardByIp.delete(ip);
  }

  _strike(s, now, reason, { ip, nodeId }) {
    s.strikes.push(now);
    const n = s.strikes.length;
    const cfg = this.profile.strikes;

    if (n >= cfg.hardThreshold && s.hardUntil <= now) {
      s.hardUntil = now + cfg.hardMs;
      // Track hard quarantines BY IP — survives session forget(), so an
      // attacker reconnecting with a fresh peerId still accumulates toward
      // the persistent ban threshold.
      if (ip) {
        let arr = this._hardByIp.get(ip);
        if (!arr) { arr = []; this._hardByIp.set(ip, arr); }
        arr.push(now);
        const banKeys = [];
        if (arr.length >= this.profile.ban.hardQuarantinesIn24h) {
          const ttl = this.profile.ban.durationMs;
          this.banList.add(ip, ttl, `repeated-hard-quarantine:${reason}`);
          banKeys.push(ip);
          if (nodeId) { this.banList.add(nodeId, ttl, `repeated-hard-quarantine:${reason}`); banKeys.push(nodeId); }
          return { allow: false, reason, escalate: 'ban', banKeys };
        }
      }
      // Short IP ban for hardMs so reconnect attempts bounce immediately
      if (ip) this.banList.add(ip, cfg.hardMs, `hard-quarantine:${reason}`);
      // Mirror on the peer state for compatibility/inspection
      s.hardHistory.push(now);
      return { allow: false, reason, escalate: 'hard', banKeys: ip ? [ip] : [] };
    }

    if (n >= cfg.softThreshold && s.softUntil <= now) {
      s.softUntil = now + cfg.softMs;
      return { allow: false, reason, escalate: 'soft' };
    }

    return { allow: false, reason };
  }

  /**
   * Inspection helper for tests / admin UI.
   */
  snapshot(peerId) {
    const s = this._peers.get(peerId);
    if (!s) return null;
    return {
      strikes: s.strikes.length,
      softUntil: s.softUntil,
      hardUntil: s.hardUntil,
      hardIn24h: s.hardHistory.length,
      tokens: {
        peerFrames: Math.floor(s.perPeerFrames.tokens),
        peerBytes:  Math.floor(s.perPeerBytes.tokens),
        open:       Math.floor(s.bandBuckets.open.tokens),
        reserved:   Math.floor(s.bandBuckets.reserved.tokens),
        extension:  Math.floor(s.bandBuckets.extension.tokens),
      },
    };
  }
}

function deepMerge(a, b) {
  if (b === null || typeof b !== 'object') return b;
  const out = Array.isArray(a) ? [...a] : { ...a };
  for (const k of Object.keys(b)) {
    out[k] = (k in a && typeof a[k] === 'object' && !Array.isArray(a[k]))
      ? deepMerge(a[k], b[k])
      : b[k];
  }
  return out;
}

module.exports = { PeerLimiter, BanList, PROFILES, bandOf, TokenBucket };
