'use strict';
/**
 * types.js — channel type registry
 *
 * Open channels   (0x01–0xFF):   implemented here, usable by anyone.
 * Core system     (0x100–0x1FF): hard-blocked. Registering a handler throws.
 *                                 Received frames are silently dropped.
 * Extension range (0x200–0xFFFF): usable by subclasses that override
 *                                 supportsExtendedChannels() → true.
 *
 * @version  0.1.0
 * @released 2026-04-18
 * @license  LGPL-2.1
 */

const OPEN = {
  PEER_HELLO:         0x01,  // node introduction on connect
  PEER_BYE:           0x02,  // graceful disconnect
  PREVHASH_ANNOUNCE:  0x10,  // pool prevhash broadcast (selfish mining detection)
  GUARD_ALERT:        0x11,  // hashrate concentration alert from peer
};

// Reverse map: numeric id → name (for logging)
const ID_TO_NAME = {};
for (const [k, v] of Object.entries(OPEN)) ID_TO_NAME[v] = k;

function typeName(id) {
  return ID_TO_NAME[id] || `0x${id.toString(16)}`;
}

// 0x100–0x1FF: hard-blocked. Received frames are silently dropped.
// Handler registration and sending are rejected unconditionally.
function isCoreSystemType(id) {
  return id >= 0x100 && id <= 0x1FF;
}

// 0x200–0xFFFF: open extension range, accessible via supportsExtendedChannels().
function isExtensionType(id) {
  return id >= 0x200;
}

module.exports = { OPEN, typeName, isCoreSystemType, isExtensionType };
