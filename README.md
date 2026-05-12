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

## Scope and design intent

xmrigger-mesh was designed and validated for a single class of use case:
**federation between independent `xmrigger-proxy` operators**, so that they
can exchange timing-sensitive mining signals (most importantly prevhash
announcements and hashrate concentration alerts) and collectively detect
selfish-mining behaviour that no isolated proxy would notice on its own.

That intent shapes every concrete choice in this codebase:

- four open channels (`PEER_HELLO`, `PEER_BYE`, `PREVHASH_ANNOUNCE`,
  `GUARD_ALERT`) covering only the federation handshake and the two
  detection signals
- single-hop relay, no routing, no DHT
- fixed-size bucket padding sized for short signal frames (≤ 2 KB), not
  for application payloads
- bandwidth budget per peer designed for ones-of-frames-per-second, not
  ones-of-megabits-per-second
- handler registration in the `0x100–0x1FF` range is blocked at API level
  precisely because that range is not part of the validated scope of this
  library

### Non-goals

The following uses are **explicitly outside the scope** for which the
protocol, the threat model, and the implementation were designed:

- marketplaces, listings directories, or service-discovery services
- anonymous or pseudonymous messaging between end users
- file transfer or any form of bulk data routing
- general-purpose pub/sub for application traffic
- identity bridging across separate networks
- coordination channels for software not directly related to the
  anti-selfish-mining federation it was built to support

The cryptographic primitives in this library (X25519, AES-256-GCM,
ChaCha20-Poly1305 in derivatives) are standard and can in principle be
used to build other things. Forks that do so operate **outside the scope
this library was validated for**; the authors do not endorse, support,
or take responsibility for such derivative uses, and the security
analysis published here does not extend to them.

### Hard-blocked range

Channel IDs `0x100`–`0x1FF` are reserved at the API level and silently
dropped on receive (see `types.js`). This is a **scope marker, not a
security boundary**: a fork that removes the check can deliver those
frames to its own handlers. Operators integrating xmrigger-mesh should
not rely on the reserved range as an authorisation mechanism for
cross-organisation traffic. Cross-organisation, authenticated traffic
belongs on a separate transport with its own access control.

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

The channel ID space above `0xFF` is split into two ranges:

- **`0x100`–`0x1FF` (core system):** hard-blocked. Registering a handler throws.
  Received frames are silently dropped — not relayed, not emitted.
- **`0x200`–`0xFFFF` (extension range):** open for use by subclasses that
  override `supportsExtendedChannels()`. See [EXTENDING.md](EXTENDING.md).

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

## Why client miners do not use WebSocket

xmrigger-mesh is a **proxy-to-proxy** transport. The WebSocket connections
it establishes are between `xmrigger-proxy` instances — not between miners
and pools.

The miner-to-proxy leg is plain Stratum TCP on port 3333. This is intentional.

A miner that opens an additional WebSocket connection to a relay service is
immediately distinguishable from one that does not. That connection:

- reveals the miner's IP to the relay operator
- is visible to ISPs and network monitors as a non-mining connection
- can be blocked or throttled independently of the mining connection
- associates the miner's identity with the relay network

The mining Stratum stream itself carries all the bandwidth that a miner
legitimately generates. Any additional signalling a miner needs — protocol
extensions, coordination messages, application payloads — can be embedded
inside that stream without opening new connections.

Embedding produces a traffic profile **statistically indistinguishable from
stock XMRig**. There is no new port, no new TLS handshake, no new IP endpoint
to observe or block. The only observable fact is that the miner mines.

xmrigger-proxy can carry extension payloads between proxies via the mesh
(system channel frames, which standard nodes relay without inspecting).
From a miner's perspective the connection count stays at one.

---

## Architecture direction — multi-connection per peer

The correct solution to channel fairness is **connection separation by channel
group**, not priority queuing on a shared connection:

```
peer A ←— conn[0] CORE ————→ peer B   [0x01 0x02 0x10 0x11]  protected
peer A ←— conn[1] OPEN ext ——→ peer B  [0x03..0xFF]           rate-limited
peer A ←— conn[2] EXT ——————→ peer B  [0x200+]               rate-limited
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

Released under [LGPL-2.1](LICENSE).
