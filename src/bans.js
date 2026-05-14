'use strict';
/**
 * bans.js — persistent IP/nodeId ban list with TTL
 *
 * Ban is keyed on remote IP (primary, infrastructure-level) and optionally
 * on nodeId (advertised in HELLO, persistent per-node once HKDF-from-seed
 * lands). peerId is intentionally NOT used: it rotates per session because
 * it derives from the ephemeral ECDH pubkey, so banning it would be a
 * single-session no-op.
 *
 * Storage: ~/.xmrigger-mesh/bans.json, mode 0600. Atomic write via temp+rename.
 * In-memory cache reloaded on start, refreshed on add/remove.
 *
 * @version  0.1.0
 * @license  LGPL-2.1
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const DEFAULT_DIR  = path.join(os.homedir(), '.xmrigger-mesh');
const DEFAULT_FILE = 'bans.json';

class BanList {
  /**
   * @param {object} [opts]
   * @param {string} [opts.dir]   Override storage dir (tests use tmpdir).
   * @param {string} [opts.file]  Override filename.
   * @param {boolean} [opts.persistent=true]  If false, in-memory only.
   */
  constructor({ dir = DEFAULT_DIR, file = DEFAULT_FILE, persistent = true } = {}) {
    this._dir   = dir;
    this._path  = path.join(dir, file);
    this._persistent = persistent;
    /** @type {Map<string, number>} key → expiresAt epoch ms */
    this._bans  = new Map();
    if (persistent) this._load();
  }

  _load() {
    try {
      const raw = fs.readFileSync(this._path, 'utf8');
      const obj = JSON.parse(raw);
      const now = Date.now();
      for (const [k, exp] of Object.entries(obj.bans || {})) {
        if (typeof exp === 'number' && exp > now) this._bans.set(k, exp);
      }
    } catch { /* missing file or unreadable: fresh start */ }
  }

  _save() {
    if (!this._persistent) return;
    try {
      fs.mkdirSync(this._dir, { recursive: true, mode: 0o700 });
      const obj = { version: 1, bans: Object.fromEntries(this._bans) };
      const tmp = this._path + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { mode: 0o600 });
      fs.renameSync(tmp, this._path);
    } catch (e) {
      // Non-fatal: persistence failure shouldn't take down the node.
      // The ban still applies in-memory for this process lifetime.
    }
  }

  _purgeExpired(now = Date.now()) {
    let dirty = false;
    for (const [k, exp] of this._bans) {
      if (exp <= now) { this._bans.delete(k); dirty = true; }
    }
    if (dirty) this._save();
  }

  /**
   * @param {string} key       IP or nodeId
   * @param {number} ttlMs     ban duration
   * @param {string} [reason]  free-text, not persisted (audit log responsibility)
   */
  add(key, ttlMs, reason = '') {
    if (!key) return;
    const expiresAt = Date.now() + ttlMs;
    const current = this._bans.get(key) || 0;
    if (expiresAt > current) {
      this._bans.set(key, expiresAt);
      this._save();
    }
    return { key, expiresAt, reason };
  }

  isBanned(key) {
    if (!key) return false;
    const exp = this._bans.get(key);
    if (!exp) return false;
    if (exp <= Date.now()) {
      this._bans.delete(key);
      this._save();
      return false;
    }
    return true;
  }

  remove(key) {
    if (this._bans.delete(key)) this._save();
  }

  list() {
    this._purgeExpired();
    return Array.from(this._bans.entries()).map(([key, exp]) => ({
      key, expiresAt: exp, remainingMs: exp - Date.now(),
    }));
  }

  clear() {
    this._bans.clear();
    this._save();
  }
}

module.exports = { BanList };
