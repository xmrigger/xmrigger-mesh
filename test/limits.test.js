'use strict';
/**
 * limits.test.js — unit tests for PeerLimiter, TokenBucket, BanList
 *
 * Deterministic: the limiter accepts an injected `now` function so we can
 * step time forward without setTimeout/sleep.
 */

const assert = require('assert');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');

const { PeerLimiter, BanList, PROFILES, bandOf, TokenBucket } = require('../src/limits');

let tests = 0, passed = 0, failed = 0;
function it(name, fn) {
  tests++;
  try { fn(); passed++; console.log(`  ok   ${name}`); }
  catch (e) { failed++; console.log(`  FAIL ${name}: ${e.message}`); }
}
function group(name, fn) { console.log(`\n${name}`); fn(); }

// ── TokenBucket ─────────────────────────────────────────────────────────────
group('TokenBucket', () => {
  it('starts at capacity', () => {
    const b = new TokenBucket(10, 1);
    assert.strictEqual(b.tokens, 10);
  });
  it('take consumes tokens', () => {
    const b = new TokenBucket(5, 1);
    assert.ok(b.take(3));
    assert.strictEqual(Math.floor(b.tokens), 2);
  });
  it('take refuses when empty', () => {
    const b = new TokenBucket(2, 0);
    b.take(2);
    assert.ok(!b.take(1));
  });
  it('refills over time', () => {
    const b = new TokenBucket(10, 5);   // 5 tokens/sec
    const t0 = 1_000_000;
    b.last = t0; b.tokens = 0;
    assert.ok(!b.take(1, t0));
    assert.ok(b.take(1, t0 + 1000));     // 5 tokens after 1s
  });
  it('caps refill at capacity', () => {
    const b = new TokenBucket(3, 100);
    b.last = 0; b.tokens = 0;
    b.take(0, 1_000_000);                // huge gap
    assert.ok(b.tokens <= 3);
  });
});

// ── bandOf ──────────────────────────────────────────────────────────────────
group('bandOf', () => {
  it('open range', () => {
    assert.strictEqual(bandOf(0x01), 'open');
    assert.strictEqual(bandOf(0xFF), 'open');
  });
  it('reserved range', () => {
    assert.strictEqual(bandOf(0x100), 'reserved');
    assert.strictEqual(bandOf(0x1FF), 'reserved');
  });
  it('extension range', () => {
    assert.strictEqual(bandOf(0x200), 'extension');
    assert.strictEqual(bandOf(0xFFFF), 'extension');
  });
});

// ── BanList ─────────────────────────────────────────────────────────────────
group('BanList', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mesh-bans-'));

  it('adds and queries ban', () => {
    const bl = new BanList({ dir: tmpDir, file: 'a.json' });
    bl.add('1.2.3.4', 60_000);
    assert.ok(bl.isBanned('1.2.3.4'));
    assert.ok(!bl.isBanned('1.2.3.5'));
  });

  it('expires after ttl', () => {
    const bl = new BanList({ dir: tmpDir, file: 'b.json' });
    bl.add('5.6.7.8', 1);                // 1ms ttl
    const start = Date.now();
    while (Date.now() - start < 10) { /* spin briefly */ }
    assert.ok(!bl.isBanned('5.6.7.8'));
  });

  it('persists across instances', () => {
    const file = 'c.json';
    const bl1 = new BanList({ dir: tmpDir, file });
    bl1.add('9.9.9.9', 3600_000);
    const bl2 = new BanList({ dir: tmpDir, file });
    assert.ok(bl2.isBanned('9.9.9.9'));
  });

  it('persistent=false stays in-memory', () => {
    const bl1 = new BanList({ dir: tmpDir, file: 'd.json', persistent: false });
    bl1.add('7.7.7.7', 3600_000);
    assert.ok(bl1.isBanned('7.7.7.7'));
    const bl2 = new BanList({ dir: tmpDir, file: 'd.json', persistent: false });
    assert.ok(!bl2.isBanned('7.7.7.7'));   // fresh memory
  });

  it('extends ban when adding longer', () => {
    const bl = new BanList({ dir: tmpDir, file: 'e.json' });
    bl.add('8.8.8.8', 1000);
    bl.add('8.8.8.8', 60_000);
    const list = bl.list();
    const entry = list.find(x => x.key === '8.8.8.8');
    assert.ok(entry.remainingMs > 50_000);
  });
});

// ── PeerLimiter: basic pass / drop ──────────────────────────────────────────
group('PeerLimiter — happy path', () => {
  const banDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mesh-lim-'));
  function fakeNow() { return fakeNow._t; }  fakeNow._t = 1_000_000;

  it('allows in-budget frames', () => {
    fakeNow._t = 1_000_000;
    const l = new PeerLimiter({
      banList: new BanList({ dir: banDir, file: 'h1.json' }),
      now: fakeNow,
    });
    const v = l.check({ peerId: 'p1', typeId: 0x01, frameSize: 200 });
    assert.ok(v.allow);
  });

  it('priority lane (PREVHASH 0x10) bypasses band bucket', () => {
    fakeNow._t = 2_000_000;
    const l = new PeerLimiter({
      banList: new BanList({ dir: banDir, file: 'h2.json' }),
      now: fakeNow,
    });
    // Drain OPEN band bucket
    for (let i = 0; i < PROFILES.default.open.frameCap; i++) {
      assert.ok(l.check({ peerId: 'p2', typeId: 0x01, frameSize: 100 }).allow);
    }
    // Non-priority OPEN should be strike now
    const v1 = l.check({ peerId: 'p2', typeId: 0x01, frameSize: 100 });
    assert.ok(!v1.allow);
    // Priority OPEN (PREVHASH) still flows (peer state already striked once,
    // so we need a fresh peer to isolate the priority path)
    fakeNow._t = 3_000_000;
    const v2 = l.check({ peerId: 'p3', typeId: 0x10, frameSize: 100 });
    assert.ok(v2.allow);
    // Drain OPEN band for p3 then verify priority still passes
    for (let i = 0; i < PROFILES.default.open.frameCap + 5; i++) {
      l.check({ peerId: 'p3', typeId: 0x10, frameSize: 100 });
    }
    const v3 = l.check({ peerId: 'p3', typeId: 0x10, frameSize: 100 });
    assert.ok(v3.allow, 'priority must still pass after open-band drain');
  });
});

// ── PeerLimiter: escalation ladder ──────────────────────────────────────────
group('PeerLimiter — escalation', () => {
  const banDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mesh-esc-'));
  function fakeNow() { return fakeNow._t; }

  it('3 strikes → soft quarantine', () => {
    fakeNow._t = 10_000_000;
    const l = new PeerLimiter({
      banList: new BanList({ dir: banDir, file: 's1.json' }),
      now: fakeNow,
    });
    // Force strikes by frame-too-large on OPEN
    const bigFrame = PROFILES.default.open.frameSize + 1;
    let escalations = [];
    for (let i = 0; i < 4; i++) {
      const v = l.check({ peerId: 'attk', typeId: 0x01, frameSize: bigFrame, ip: '10.0.0.1' });
      if (v.escalate) escalations.push(v.escalate);
    }
    assert.ok(escalations.includes('soft'), `expected soft, got ${JSON.stringify(escalations)}`);
  });

  it('6 strikes → hard quarantine + IP ban for hardMs', () => {
    fakeNow._t = 20_000_000;
    const banList = new BanList({ dir: banDir, file: 's2.json' });
    const l = new PeerLimiter({ banList, now: fakeNow });
    const bigFrame = PROFILES.default.open.frameSize + 1;
    let hard = false;
    for (let i = 0; i < 7; i++) {
      const v = l.check({ peerId: 'attk2', typeId: 0x01, frameSize: bigFrame, ip: '10.0.0.2' });
      if (v.escalate === 'hard') hard = true;
    }
    assert.ok(hard, 'expected hard escalation');
    assert.ok(banList.isBanned('10.0.0.2'), 'IP must be in ban list after hard');
  });

  it('reserved-band probe = immediate strike', () => {
    fakeNow._t = 30_000_000;
    const l = new PeerLimiter({
      banList: new BanList({ dir: banDir, file: 's3.json' }),
      now: fakeNow,
    });
    const v = l.check({ peerId: 'sneak', typeId: 0x140, frameSize: 100, ip: '10.0.0.3' });
    assert.ok(!v.allow);
    assert.strictEqual(v.reason, 'reserved-band-violation');
  });

  it('3 hard quarantines in 24h → persistent ban (30d)', () => {
    fakeNow._t = 40_000_000;
    const banList = new BanList({ dir: banDir, file: 's4.json' });
    const l = new PeerLimiter({ banList, now: fakeNow });
    const ip = '10.0.0.4';
    const bigFrame = PROFILES.default.open.frameSize + 1;

    function flood() {
      for (let i = 0; i < 7; i++) {
        l.check({ peerId: 'attk-flood', typeId: 0x01, frameSize: bigFrame, ip });
      }
    }

    // First hard quarantine
    flood();
    let snap = l.snapshot('attk-flood');
    assert.strictEqual(snap.hardIn24h, 1);

    // Reset peer (simulate reconnect with fresh peerId) and time-skip 2h
    l.forget('attk-flood');
    fakeNow._t += 2 * 3600_000;
    flood();
    l.forget('attk-flood');
    fakeNow._t += 2 * 3600_000;

    // 3rd hard within 24h → ban trigger
    let banTriggered = false;
    for (let i = 0; i < 7; i++) {
      const v = l.check({ peerId: 'attk-flood', typeId: 0x01, frameSize: bigFrame, ip });
      if (v.escalate === 'ban') banTriggered = true;
    }
    assert.ok(banTriggered, 'expected ban escalation on 3rd hard quarantine');
    // Verify persistent ban remaining ms is in 30-day ballpark
    const entry = banList.list().find(x => x.key === ip);
    assert.ok(entry, 'IP must be in ban list');
    assert.ok(entry.remainingMs > 25 * 24 * 3600_000, `expected ~30d ban, got ${entry.remainingMs}ms`);
  });
});

// ── PeerLimiter — soft quarantine eventually clears ─────────────────────────
group('PeerLimiter — recovery', () => {
  const banDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mesh-rec-'));
  function fakeNow() { return fakeNow._t; }

  it('soft quarantine expires after softMs', () => {
    fakeNow._t = 50_000_000;
    const l = new PeerLimiter({
      banList: new BanList({ dir: banDir, file: 'r1.json' }),
      now: fakeNow,
    });
    const bigFrame = PROFILES.default.open.frameSize + 1;
    // 3 strikes → soft
    for (let i = 0; i < 3; i++) {
      l.check({ peerId: 'p', typeId: 0x01, frameSize: bigFrame, ip: '10.0.0.10' });
    }
    let v = l.check({ peerId: 'p', typeId: 0x01, frameSize: 100 });
    assert.ok(!v.allow);  // still in soft
    // Skip past strike window AND soft window
    fakeNow._t += PROFILES.default.strikes.softMs + 1000;
    v = l.check({ peerId: 'p', typeId: 0x01, frameSize: 100 });
    assert.ok(v.allow, 'expected frame to pass after soft expiry');
  });
});

// ── Summary ─────────────────────────────────────────────────────────────────
console.log(`\n────────────────────────────────────`);
console.log(`tests: ${tests}  passed: ${passed}  failed: ${failed}`);
process.exit(failed === 0 ? 0 : 1);
