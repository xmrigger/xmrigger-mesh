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

System channels (0x100+) are reserved. Nodes without a system key receive
them but cannot send or consume them.

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

---

## Related

| Repo | Role |
|------|------|
| [xmrigger](https://github.com/xmrigger/xmrigger) | Detection library that uses this mesh as its federation transport |
| [xmrigger-proxy](https://github.com/xmrigger/xmrigger-proxy) | Full Stratum proxy — wires xmrigger guards + mesh together for XMRig |

---

## License

[LGPL-2.1](LICENSE)
