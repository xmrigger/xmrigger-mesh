# xmrigger-mesh

Encrypted P2P transport that connects xmrigger-proxy instances. Gossip mesh over WebSocket with X25519 ECDH + AES-256-GCM, payloads bucket-padded to fixed sizes to hide content length. The channel through which proxies exchange prevhash values in real time to detect selfish mining. One dependency: `ws`.

Part of the [xmrigger suite](https://github.com/xmrigger): `xmrigger` · `xmrigger-mesh` · `xmrigger-proxy`

---

## What it does

Connects a set of proxy nodes over encrypted WebSocket sessions. Each node
can broadcast typed messages to its peers. Nodes that receive messages they
do not handle forward them silently.

It is not a DHT, not a routing protocol, not a mixnet. It is a simple
gossip mesh with one hop of relay.

---

## Encryption

Each session uses an ephemeral X25519 key exchange. All frames are encrypted
with AES-256-GCM and padded to fixed bucket sizes (256 / 512 / 1024 / 2048 B)
to hide payload length.

Node identity is ephemeral — a new keypair is generated on each start.
Persistent identity from a seed is not implemented yet (v0.2 roadmap).

---

## Channel types

```js
const { OPEN } = require('xmrigger-mesh');

OPEN.PREVHASH_ANNOUNCE  // pool prevhash broadcast
OPEN.GUARD_ALERT        // hashrate concentration hint from peer
OPEN.PEER_HELLO         // node introduction
OPEN.PEER_BYE           // graceful disconnect
```

System channels (0x100+) are reserved as extension points for downstream
implementations. Standard nodes receive and decrypt these frames but discard
them silently — they have no effect on mesh behaviour.

---

## Quick start

```bash
git clone https://github.com/xmrigger/xmrigger-mesh
cd xmrigger-mesh
npm install
node poc/demo.js   # two nodes, real encryption, prevhash detection
```

---

## Usage

```js
const { MeshNode, OPEN } = require('xmrigger-mesh');

const node = new MeshNode({
  port:  8765,
  seeds: ['wss://peer.example.com:8765'],
  name:  'my-proxy',
  minPeersForAlert: 2,
});

await node.start();

// register a handler for an open channel
node.on(OPEN.PREVHASH_ANNOUNCE, ({ payload, peerId }) => {
  console.log(`peer ${peerId} reports prevhash ${payload.prevhash}`);
});

// broadcast to all connected peers
node.broadcast(OPEN.PREVHASH_ANNOUNCE, { prevhash: '...', pool: 'pool.example.com' });

// peer receives and calls:
node.on(OPEN.PREVHASH_ANNOUNCE, ({ payload, peerId }) => {
  monitor.onPeerAnnounce(peerId, payload.prevhash);
});
```

---

## Tests

```bash
npm test
# or: node test/index.js
```

12 tests — no external dependencies, no network calls.

Covers: X25519 ECDH key exchange, AES-256-GCM encrypt/decrypt, tamper
detection, bucket padding and unpadding.

---

## Known limitations

- **No peer authentication.** Any node can join the mesh. A Sybil attacker
  with multiple nodes could attempt to influence detection. Mitigated by
  `minPeersForAlert` but not eliminated.

- **No persistent identity.** Node keypair is regenerated on every restart.
  Peers cannot verify they are talking to the same node as before.

- **Single-hop relay only.** Messages are forwarded once. There is no
  multi-hop routing or path anonymisation.

- **Seed nodes are trusted for discovery.** A compromised seed node can
  partition the network. Use multiple seeds from independent operators.

- **Mesh port should not be exposed to the internet** without additional
  access control. Bind to a trusted interface or use a firewall rule.

- **No channel fairness or rate limiting.** All channel types share the same
  WebSocket connection with no priority ordering. A node sending high-frequency
  messages on extended or system channels can delay delivery of time-sensitive
  frames (`PREVHASH_ANNOUNCE`, `GUARD_ALERT`). Until addressed, implementations
  adding channels beyond the core protocol are responsible for self-limiting
  their traffic to preserve detection latency.

---

## Architecture direction — multi-connection per peer

The correct solution to channel fairness is **connection separation by channel
group**, not priority queuing on a shared connection:

```
peer A ←— conn[0] CORE ————→ peer B   [0x01 0x02 0x10 0x11]  protected
peer A ←— conn[1] OPEN ext ——→ peer B  [0x03..0xFF]           rate-limited
peer A ←— conn[2] SYSTEM ————→ peer B  [0x100+]               rate-limited
```

Each connection is an independent WebSocket with its own ECDH handshake and
session key. A flood on `conn[1]` or `conn[2]` never reaches `conn[0]`.
Rate limit per non-core connection is determined by the node operator or
auto-derived from available bandwidth divided by active connection count.
`conn[0]` is always exempt from rate calculations.

**Current state:** single connection per peer, static. Channel-to-connection
mapping and per-connection rate limits are not yet implemented.

**Hardening required before production use of extended/system channels:**
- Dynamic negotiation of connection slots in the handshake
- Per-connection token-bucket rate limiting (operator-configurable, with a
  sensible default, e.g. 20 frames/s)
- Automatic floor guarantee for `conn[0]` regardless of other connection load

Until this is implemented, any high-frequency use of non-core channels on a
shared connection risks degrading selfish mining detection for all peers.

---

## Related

| Repo | Role |
|------|------|
| [xmrigger](https://github.com/xmrigger/xmrigger) | Detection library that uses this mesh as its federation transport |
| [xmrigger-proxy](https://github.com/xmrigger/xmrigger-proxy) | Full Stratum proxy — wires xmrigger guards + mesh together for XMRig |

---

## Project

`xmrigger-mesh` is part of the [TNZX project](https://github.com/tnzx-project).
Released under [LGPL-2.1](LICENSE).
