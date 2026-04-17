'use strict';
/**
 * types.js — channel type registry
 *
 * Open channels (0x01–0xFF): implemented here, usable by anyone.
 * System channels (0x100+):  reserved — not usable in this distribution.
 *                             Nodes that receive a system message emit it as
 *                             a 'system-message' event and silently discard it.
 *
 * @license LGPL-2.1
 */

const OPEN = {
  PEER_HELLO:         0x01,  // node introduction on connect
  PEER_BYE:           0x02,  // graceful disconnect
  PREVHASH_ANNOUNCE:  0x10,  // pool prevhash broadcast (selfish mining detection)
  GUARD_ALERT:        0x11,  // hashrate concentration alert from peer
};

// System channels — reserved, not usable in this distribution.
// A node without a system key receives these messages, emits the event,
// and discards them. It cannot generate or relay system messages.
const SYSTEM = {
  // 0x100–0x1FF  — reserved
};

// Reverse map: numeric id → name (for logging)
const ID_TO_NAME = {};
for (const [k, v] of Object.entries(OPEN))   ID_TO_NAME[v] = k;
for (const [k, v] of Object.entries(SYSTEM)) ID_TO_NAME[v] = k;

function typeName(id) {
  return ID_TO_NAME[id] || `0x${id.toString(16)}`;
}

function isSystemType(id) {
  return id >= 0x100;
}

module.exports = { OPEN, SYSTEM, typeName, isSystemType };
