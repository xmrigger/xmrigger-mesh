'use strict';
/**
 * index.js — xmrigger-mesh public API
 *
 * @version  0.1.0
 * @released 2026-04-18
 * @license  LGPL-2.1
 */
// xmrigger-mesh public API: exports MeshNode, OPEN channel types, and crypto primitives.
module.exports = {
  ...require('./src/node'),
  ...require('./src/types'),
  ...require('./src/crypto'),
};
