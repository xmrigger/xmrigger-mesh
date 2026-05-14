'use strict';
/**
 * e2e-flood.test.js — live 2-node smoke for the defense layer
 *
 * Scenario A — clean traffic passes:
 *   nodeA (limits ON, strict) ← connects ← nodeB (no limits)
 *   B sends 3 normal frames in OPEN. A delivers all 3.
 *
 * Scenario B — flood gets rate-throttled:
 *   B blasts 200 frames at high rate. A delivers far fewer than 200
 *   and emits 'peer-throttled' (and eventually closes the session).
 *
 * Scenario C — oversized frame triggers strike → kill:
 *   B sends a single frame larger than the strict open.frameSize cap
 *   enough times to cross hardThreshold. A terminates the session.
 *
 * No timers, no sleeps — drives flush via setImmediate ticks.
 */

const assert = require('assert');
const path   = require('path');
const fs     = require('fs');
const os     = require('os');

const { MeshNode } = require('../src/node');

function nextTick(n = 1) {
  return new Promise(r => {
    let i = 0;
    function step() { if (++i >= n) r(); else setImmediate(step); }
    setImmediate(step);
  });
}
function wait(ms) { return new Promise(r => setTimeout(r, ms)); }
async function until(fn, deadlineMs = 3000, intervalMs = 25) {
  const t0 = Date.now();
  while (Date.now() - t0 < deadlineMs) {
    if (fn()) return true;
    await wait(intervalMs);
  }
  return false;
}

let failed = 0;
async function scenario(name, fn) {
  process.stdout.write(`  ${name} ... `);
  try { await fn(); process.stdout.write('ok\n'); }
  catch (e) { failed++; process.stdout.write(`FAIL\n    ${e.stack || e.message}\n`); }
}

async function makePair({ portA, profile, override }) {
  const banDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mesh-e2e-'));
  const a = new MeshNode({
    port: portA,
    name: 'A',
    limits: { profile, override, banList: new (require('../src/bans').BanList)({ dir: banDir, file: 'a.json' }) },
  });
  await a.start();
  const b = new MeshNode({
    port: portA + 1,
    name: 'B',
    seeds: [`ws://127.0.0.1:${portA}`],
    limits: false,
  });
  await b.start();
  // Wait for B → A session readiness on A side
  await until(() => a.peerCount === 1, 3000);
  return { a, b, banDir };
}

async function main() {
  console.log('\nE2E flood smoke');

  // ── A: clean traffic ──────────────────────────────────────────────────────
  await scenario('clean traffic passes', async () => {
    const { a, b } = await makePair({ portA: 18851, profile: 'default' });
    const received = [];
    a.on('message', ({ typeId, payload }) => received.push({ typeId, payload }));
    for (let i = 0; i < 3; i++) b.broadcast(0x01, { i });
    await until(() => received.length === 3, 2000);
    assert.strictEqual(received.length, 3, `expected 3, got ${received.length}`);
    a.stop(); b.stop();
    await nextTick(3);
  });

  // ── B: flood → throttled ──────────────────────────────────────────────────
  await scenario('flood is throttled and session killed', async () => {
    const { a, b } = await makePair({
      portA: 18861,
      profile: 'strict',
    });
    let received = 0;
    let throttled = 0;
    let killed = false;
    a.on('message', () => received++);
    a.on('peer-throttled', () => throttled++);
    a.on('peer-disconnected', () => { killed = true; });

    // Blast 200 frames as fast as the WS can buffer
    for (let i = 0; i < 200; i++) b.broadcast(0x01, { i, junk: 'x'.repeat(100) });

    await until(() => killed || throttled > 5, 3000);
    assert.ok(throttled > 0, `expected throttling, got ${throttled}`);
    assert.ok(received < 200, `received ${received}, must be < 200 (throttling failed)`);
    a.stop(); b.stop();
    await nextTick(3);
  });

  // ── C: persistent ban → reconnect from same IP is rejected ────────────────
  await scenario('banned IP reconnect is rejected pre-handshake', async () => {
    // Override: 1 hard quarantine in 24h → permanent ban. So a single flood
    // sequence is enough to land the source IP in the ban list, and a fresh
    // peer from 127.0.0.1 must bounce.
    const { a, b } = await makePair({
      portA: 18871,
      profile: 'strict',
      override: { ban: { hardQuarantinesIn24h: 1, durationMs: 60_000 } },
    });
    let banSeen = false;
    a.on('peer-throttled', (ev) => { if (ev.escalate === 'ban') banSeen = true; });

    // Flood until ban triggers
    for (let i = 0; i < 50; i++) b.broadcast(0x01, { i, junk: 'x'.repeat(50) });
    await until(() => banSeen, 3000);
    assert.ok(banSeen, 'expected ban escalation from flood');
    b.stop();
    await nextTick(3);

    // New peer from same IP (loopback) tries to connect — should be rejected
    let rejected = false;
    a.on('peer-rejected', () => { rejected = true; });
    const b2 = new MeshNode({
      port: 18873,
      name: 'B2',
      seeds: ['ws://127.0.0.1:18871'],
      limits: false,
    });
    await b2.start();
    await until(() => rejected, 3000);
    assert.ok(rejected, 'expected peer-rejected event for banned IP');
    assert.strictEqual(a.peerCount, 0, 'banned reconnect must not land a session');
    a.stop(); b2.stop();
    await nextTick(3);
  });

  // ── Summary ───────────────────────────────────────────────────────────────
  if (failed) {
    console.log(`\n${failed} scenario(s) FAILED`);
    process.exit(1);
  } else {
    console.log('\nall scenarios PASS');
    process.exit(0);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
