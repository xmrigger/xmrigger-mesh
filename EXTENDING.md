# Extending xmrigger-mesh

xmrigger-mesh defines three categories of channel type IDs:

| Range | Name | Behaviour |
|-------|------|-----------|
| `0x01`–`0xFF` | Open channels | Any node can register handlers |
| `0x100`–`0x1FF` | Reserved | **Hard-blocked.** Send throws. Received frames are silently dropped. |
| `0x200`–`0xFFFF` | Extension range | Usable by subclasses that override `supportsExtendedChannels()` |

---

## Why 0x100–0x1FF is hard-blocked

This is a deliberate design choice, not a limitation.

An operator who runs an xmrigger-mesh node should be able to verify, by reading
this source code, exactly what their node does and does not do. That guarantee
breaks if the node silently relays frames for protocols it does not know about.

With frames dropped in this range:

- **Auditable scope.** The node's behaviour is fully described by this codebase.
  No external party can use a standard node as relay infrastructure for a private
  protocol without the operator's knowledge.
- **No accidental participation.** Operators are not unknowingly carrying traffic
  for protocols they never agreed to run.
- **Minimal attack surface.** Code that is not loaded cannot have bugs.
  A node with no handler for a channel type cannot be exploited through that channel.

If a downstream implementation needs to carry its own protocol over a mesh, it
must operate its own nodes — nodes it controls, configures, and is accountable
for. Standard OSS nodes are not available as free infrastructure for private
protocols.

---

## Extension range: 0x200–0xFFFF

The extension range is open to any subclass. Pick IDs in this range for your
application-specific channels.

### Enabling extension channels

Override `supportsExtendedChannels()` to return `true`:

```js
const { MeshNode, OPEN } = require('xmrigger-mesh');

const MY_CHANNEL = 0x200;

class ExtendedNode extends MeshNode {
  supportsExtendedChannels() { return true; }
}

const node = new ExtendedNode({
  port:  8765,
  seeds: ['wss://peer.example.com:8765'],
  name:  'my-extended-node',
});

await node.start();

node.on(MY_CHANNEL, ({ payload, peerId }) => {
  console.log(`received on 0x${MY_CHANNEL.toString(16)} from ${peerId}:`, payload);
});

node.broadcast(MY_CHANNEL, { key: 'value' });
```

Without the override, `node.on(0x200, ...)` logs a warning and does nothing:

```
[xmrigger-mesh] Extension channel 0x200 requires supportsExtendedChannels() — handler ignored.
```

### What standard nodes do with extension frames

A standard node that receives a frame in the extension range (0x200+) but has no
registered handler for that type ID will:

1. Decrypt and authenticate the frame normally.
2. Find no handler in its map.
3. Emit a generic `'message'` event (for observability).
4. Take no further action — the frame is not re-relayed.

If your extension protocol needs multi-hop delivery, every intermediate node must
be an `ExtendedNode` that explicitly re-broadcasts received frames.

---

## Assigning type IDs

There is no central registry. Pick IDs in the `0x200`–`0xFFFF` range that are
meaningful to your application and document them alongside your subclass.

Do not use `0x100`–`0x1FF`. Any call to `node.on()`, `node.broadcast()`, or
`node.sendTo()` with a type ID in that range throws unconditionally:

```
Error: [xmrigger-mesh] Channel 0x101 is in the reserved range (0x100–0x1FF)
       and cannot be registered in this distribution.
```

---

## Traffic and latency considerations

All channels currently share a single WebSocket connection per peer. A
high-frequency extension channel can delay delivery of time-sensitive frames
(`PREVHASH_ANNOUNCE`, `GUARD_ALERT`). If your channel carries frequent messages,
self-limit your send rate to avoid degrading selfish mining detection latency.

A future multi-connection architecture (see README — Architecture direction) will
eliminate this constraint by isolating channel groups onto separate connections.

---

## Full example: two extended nodes exchanging custom frames

```js
'use strict';
const { MeshNode, OPEN } = require('xmrigger-mesh');

const MY_CHANNEL = 0x200;

class ExtendedNode extends MeshNode {
  supportsExtendedChannels() { return true; }
}

async function main() {
  const nodeA = new ExtendedNode({ port: 8765, name: 'node-a' });
  const nodeB = new ExtendedNode({
    port:  8766,
    seeds: ['ws://127.0.0.1:8765'],
    name:  'node-b',
  });

  nodeA.on(MY_CHANNEL, ({ payload, peerId }) => {
    console.log(`node-a received from ${peerId}:`, payload);
  });

  nodeB.on(MY_CHANNEL, ({ payload, peerId }) => {
    console.log(`node-b received from ${peerId}:`, payload);
  });

  await nodeA.start();
  await nodeB.start();

  await new Promise(r => setTimeout(r, 500));  // wait for handshake

  nodeA.broadcast(MY_CHANNEL, { hello: 'from node-a' });
  nodeB.broadcast(MY_CHANNEL, { hello: 'from node-b' });
}

main();
```

---

## See also

- `src/node.js` — `MeshNode` base class, `supportsExtendedChannels()` hook
- `src/types.js` — `isCoreSystemType()`, `isExtensionType()`, open-channel constants
- `README.md` — Architecture direction for multi-connection channel isolation
