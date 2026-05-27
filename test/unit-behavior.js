// test/unit-behavior.js
//
// Tests the JOIN endpoint chain (sign → verify → jti check → cookie issuance)
// using hand-rolled stubs for req/res. No express, no ws, no npm install.
// Catches logic errors in the endpoint flow that are hard to spot by reading.

'use strict';

const crypto = require('crypto');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  PASS  ${name}`); }
  catch (e) { failed++; console.log(`  FAIL  ${name}\n        ${e.message}`); }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || 'assert failed'); }
function eq(a, b, msg) { if (a !== b) throw new Error(`${msg || 'eq'}: ${JSON.stringify(a)} !== ${JSON.stringify(b)}`); }

// ============================================================================
// Reimplement the join endpoint logic locally so we can drive it with stubs.
// Mirrors /api/join from server.js. ANY drift from server.js will cause this
// test to lie — that's an acceptable trade for being able to run it here.
// ============================================================================

const SECRET = crypto.randomBytes(32);
const JOIN_TOKEN_TTL_MS = 6 * 60 * 60 * 1000;
const VOTER_COOKIE_NAME = 'dups_voter';
const CSRF_HEADER = 'x-dups-origin';
const CSRF_VALUE = 'same-site';

function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function b64urlDecode(s) { s = s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; return Buffer.from(s,'base64'); }
function hmac(input) { return b64url(crypto.createHmac('sha256', SECRET).update(input).digest()); }
function sign(payload) {
  const body = b64url(JSON.stringify({ ...payload, iat: Date.now() }));
  return `${body}.${hmac(body)}`;
}
function verify(token, maxAgeMs) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expected = hmac(body);
  if (sig.length !== expected.length) return null;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff !== 0) return null;
  try {
    const parsed = JSON.parse(b64urlDecode(body).toString('utf8'));
    if (maxAgeMs && (Date.now() - parsed.iat) > maxAgeMs) return null;
    return parsed;
  } catch { return null; }
}
function ipHash(ip) {
  return crypto.createHash('sha256').update(ip + SECRET).digest('hex').slice(0, 12);
}

// Session state — manipulated by tests
function freshSession() {
  return {
    id: 'sess1',
    locked: false,
    joinedVoters: {},     // vid → {ipHash, jti}
    redeemedJtis: {},     // jti → vid or '__invalidated'
    currentQrJti: null,
  };
}

// Stub express req/res
function makeReq({ body = {}, cookies = {}, headers = {}, ip = '127.0.0.1' } = {}) {
  const lowerHeaders = {};
  for (const k of Object.keys(headers)) lowerHeaders[k.toLowerCase()] = headers[k];
  return { body, cookies, headers: lowerHeaders, ip };
}
function makeRes() {
  return {
    statusCode: 200,
    body: null,
    cookies: {},
    status(c) { this.statusCode = c; return this; },
    json(o) { this.body = o; return this; },
    cookie(name, value /*, opts*/) { this.cookies[name] = value; return this; },
  };
}

// The join endpoint logic itself, lifted from server.js
function readVoterCookie(req) {
  const t = req.cookies[VOTER_COOKIE_NAME];
  if (!t) return null;
  const p = verify(t, JOIN_TOKEN_TTL_MS);
  return p && p.kind === 'voter' ? p : null;
}

function joinHandler(session, req, res) {
  // CSRF
  if ((req.headers[CSRF_HEADER] || '').toLowerCase() !== CSRF_VALUE) {
    return res.status(403).json({ error: 'csrf' });
  }
  const { joinToken } = req.body || {};
  if (!joinToken) return res.status(400).json({ error: 'no_token' });
  const parsed = verify(joinToken, JOIN_TOKEN_TTL_MS);
  if (!parsed || parsed.kind !== 'join') return res.status(400).json({ error: 'bad_token' });
  if (parsed.sid !== session.id)         return res.status(400).json({ error: 'stale_session' });
  if (session.locked)                    return res.status(403).json({ error: 'locked' });

  const existing = readVoterCookie(req);
  if (existing && existing.sid === session.id && session.joinedVoters[existing.vid]) {
    return res.json({ ok: true, voterId: existing.vid });
  }

  const ip  = req.ip;
  const ipH = ipHash(ip);

  if (parsed.jti && session.redeemedJtis[parsed.jti]) {
    const redeemerVid = session.redeemedJtis[parsed.jti];
    const isOriginal = existing && existing.vid === redeemerVid && redeemerVid !== '__invalidated';
    if (!isOriginal) {
      return res.status(409).json({ error: 'token_used' });
    }
  }

  const vid = crypto.randomBytes(8).toString('hex');
  const voterTok = sign({ kind: 'voter', sid: session.id, vid, jti: parsed.jti });
  res.cookie(VOTER_COOKIE_NAME, voterTok);
  session.joinedVoters[vid] = { joinedAt: Date.now(), ipHash: ipH, jti: parsed.jti };
  if (parsed.jti) session.redeemedJtis[parsed.jti] = vid;
  return res.json({ ok: true, voterId: vid });
}

// Helpers
function mintJoin(session, jti = 'jti1') {
  session.currentQrJti = jti;
  return sign({ kind: 'join', sid: session.id, jti });
}
function withCsrf(headers = {}) { return { ...headers, [CSRF_HEADER]: CSRF_VALUE }; }

// ============================================================================
// Tests
// ============================================================================

console.log('\n[1] CSRF guard');

test('POST with no CSRF header → 403 csrf', () => {
  const s = freshSession();
  const res = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: 'whatever' } }), res);
  eq(res.statusCode, 403);
  eq(res.body.error, 'csrf');
});

test('POST with wrong CSRF value → 403 csrf', () => {
  const s = freshSession();
  const res = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: 'whatever' }, headers: { 'X-DUPS-Origin': 'cross-site' } }), res);
  eq(res.statusCode, 403);
});

test('Uppercase CSRF value accepted (case-insensitive compare)', () => {
  const s = freshSession();
  const tok = mintJoin(s);
  const res = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: tok }, headers: { 'X-DUPS-Origin': 'SAME-SITE' } }), res);
  eq(res.statusCode, 200);
});

console.log('\n[2] Token validation');

test('Missing joinToken → 400 no_token', () => {
  const s = freshSession();
  const res = makeRes();
  joinHandler(s, makeReq({ body: {}, headers: withCsrf() }), res);
  eq(res.statusCode, 400);
  eq(res.body.error, 'no_token');
});

test('Tampered signature → 400 bad_token', () => {
  const s = freshSession();
  const tok = mintJoin(s);
  const tampered = tok.slice(0, -2) + 'XX';
  const res = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: tampered }, headers: withCsrf() }), res);
  eq(res.statusCode, 400);
  eq(res.body.error, 'bad_token');
});

test('Wrong kind (admin-signed posing as join) → 400 bad_token', () => {
  const s = freshSession();
  const adminToken = sign({ kind: 'admin', sid: s.id, aid: 'x' });
  const res = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: adminToken }, headers: withCsrf() }), res);
  eq(res.statusCode, 400);
  eq(res.body.error, 'bad_token');
});

test('Stale session id → 400 stale_session', () => {
  const s = freshSession();
  const tok = sign({ kind: 'join', sid: 'otherSession', jti: 'a' });
  const res = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: tok }, headers: withCsrf() }), res);
  eq(res.statusCode, 400);
  eq(res.body.error, 'stale_session');
});

test('Locked room → 403 locked', () => {
  const s = freshSession();
  s.locked = true;
  const tok = mintJoin(s);
  const res = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: tok }, headers: withCsrf() }), res);
  eq(res.statusCode, 403);
  eq(res.body.error, 'locked');
});

console.log('\n[3] First-time join issues cookie + records jti');

test('Successful join issues voter cookie', () => {
  const s = freshSession();
  const tok = mintJoin(s);
  const res = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: tok }, headers: withCsrf() }), res);
  eq(res.statusCode, 200);
  assert(typeof res.body.voterId === 'string' && res.body.voterId.length === 16);
  assert(typeof res.cookies[VOTER_COOKIE_NAME] === 'string', 'cookie not issued');
});

test('Successful join records jti in redeemedJtis', () => {
  const s = freshSession();
  const tok = mintJoin(s, 'jti-test-1');
  joinHandler(s, makeReq({ body: { joinToken: tok }, headers: withCsrf() }), makeRes());
  assert(s.redeemedJtis['jti-test-1'], 'jti not recorded');
  assert(/^[0-9a-f]{16}$/.test(s.redeemedJtis['jti-test-1']), 'jti should map to vid');
});

test('Successful join adds voter to joinedVoters with ipHash', () => {
  const s = freshSession();
  const tok = mintJoin(s);
  const res = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: tok }, headers: withCsrf(), ip: '198.51.100.42' }), res);
  const vid = res.body.voterId;
  assert(s.joinedVoters[vid], 'voter not added');
  eq(s.joinedVoters[vid].ipHash, ipHash('198.51.100.42'));
});

console.log('\n[4] Single-redemption jti enforcement');

test('Same token from a new IP without cookie → 409 token_used', () => {
  const s = freshSession();
  const tok = mintJoin(s);
  joinHandler(s, makeReq({ body: { joinToken: tok }, headers: withCsrf(), ip: '10.0.0.1' }), makeRes());
  const res2 = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: tok }, headers: withCsrf(), ip: '10.0.0.2' }), res2);
  eq(res2.statusCode, 409);
  eq(res2.body.error, 'token_used');
});

test('Same token from same cookie → idempotent 200, same vid', () => {
  const s = freshSession();
  const tok = mintJoin(s);
  const res1 = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: tok }, headers: withCsrf() }), res1);
  const vid1 = res1.body.voterId;
  const voterCookie = res1.cookies[VOTER_COOKIE_NAME];

  const res2 = makeRes();
  joinHandler(s, makeReq({
    body: { joinToken: tok },
    cookies: { [VOTER_COOKIE_NAME]: voterCookie },
    headers: withCsrf(),
  }), res2);
  eq(res2.statusCode, 200);
  eq(res2.body.voterId, vid1, 'should return same vid');
});

test('Different cookie attempting same token → 409 token_used', () => {
  const s = freshSession();
  const tok = mintJoin(s);
  // First voter joins
  joinHandler(s, makeReq({ body: { joinToken: tok }, headers: withCsrf() }), makeRes());
  // Second voter forges a cookie with a different vid (signed with same secret)
  const otherCookie = sign({ kind: 'voter', sid: s.id, vid: 'forged_vid_xxx_', jti: 'jti1' });
  const res = makeRes();
  joinHandler(s, makeReq({
    body: { joinToken: tok },
    cookies: { [VOTER_COOKIE_NAME]: otherCookie },
    headers: withCsrf(),
  }), res);
  eq(res.statusCode, 409);
  eq(res.body.error, 'token_used');
});

console.log('\n[5] Sentinel: rotated jti rejected for everyone');

test('Sentinel __invalidated rejects no-cookie attacker', () => {
  const s = freshSession();
  s.redeemedJtis['rotated-jti'] = '__invalidated';
  const tok = sign({ kind: 'join', sid: s.id, jti: 'rotated-jti' });
  const res = makeRes();
  joinHandler(s, makeReq({ body: { joinToken: tok }, headers: withCsrf() }), res);
  eq(res.statusCode, 409);
});

test('Sentinel __invalidated rejects even a "matching" forged cookie', () => {
  // Defense-in-depth: even if attacker somehow gets cookie with vid='__invalidated'
  const s = freshSession();
  s.redeemedJtis['rotated-jti'] = '__invalidated';
  const tok = sign({ kind: 'join', sid: s.id, jti: 'rotated-jti' });
  // Also mark joinedVoters['__invalidated'] so the existing-voter short-circuit
  // wouldn't fire first
  s.joinedVoters['__invalidated'] = { joinedAt: Date.now(), ipHash: 'h', jti: 'rotated-jti' };
  const forgedCookie = sign({ kind: 'voter', sid: s.id, vid: '__invalidated', jti: 'rotated-jti' });
  const res = makeRes();
  joinHandler(s, makeReq({
    body: { joinToken: tok },
    cookies: { [VOTER_COOKIE_NAME]: forgedCookie },
    headers: withCsrf(),
  }), res);
  // The existing-voter short-circuit DOES fire first because joinedVoters
  // has the vid. That's actually expected behavior — the cookie holder IS
  // an active voter. But verify the FALLBACK case where the vid isn't in
  // joinedVoters: the sentinel still rejects.
  // → This test verifies the existing-voter check happens first
  eq(res.statusCode, 200);

  // Now the more interesting case: rotated jti, attacker has cookie with
  // vid='__invalidated' BUT no joinedVoters entry. Sentinel should reject.
  delete s.joinedVoters['__invalidated'];
  const res2 = makeRes();
  joinHandler(s, makeReq({
    body: { joinToken: tok },
    cookies: { [VOTER_COOKIE_NAME]: forgedCookie },
    headers: withCsrf(),
  }), res2);
  eq(res2.statusCode, 409, 'sentinel should reject even with __invalidated cookie');
});

console.log('\n[6] Existing-voter idempotency precedence');

test('Voter rejoining from a totally different token → still returns same vid', () => {
  // If a voter already has a valid cookie, they don't actually need to scan
  // any QR; any join attempt is idempotent for them. This tests the
  // short-circuit precedence.
  const s = freshSession();
  // Manually add a voter
  s.joinedVoters['existing_vid_aaaa'] = { joinedAt: Date.now(), ipHash: 'h', jti: 'old-jti' };
  const cookie = sign({ kind: 'voter', sid: s.id, vid: 'existing_vid_aaaa', jti: 'old-jti' });

  // Use a totally fresh, unrelated join token
  const freshTok = sign({ kind: 'join', sid: s.id, jti: 'totally-different' });
  const res = makeRes();
  joinHandler(s, makeReq({
    body: { joinToken: freshTok },
    cookies: { [VOTER_COOKIE_NAME]: cookie },
    headers: withCsrf(),
  }), res);
  eq(res.statusCode, 200);
  eq(res.body.voterId, 'existing_vid_aaaa');
  // Importantly, the fresh token's jti was NOT consumed (existing-voter
  // short-circuit fires before the redeemedJtis check)
  assert(!s.redeemedJtis['totally-different'],
    'unused jti should not be marked redeemed when existing voter rejoins');
});

console.log('\n[7] Cookie isolation across deployments');

test('Voter cookie signed by another secret → ignored, fresh voter issued', () => {
  const s = freshSession();
  const tok = mintJoin(s);
  // Cookie signed with a different secret
  const otherSecret = crypto.randomBytes(32);
  const body = b64url(JSON.stringify({ kind: 'voter', sid: s.id, vid: 'aaaa', iat: Date.now() }));
  const sig = b64url(crypto.createHmac('sha256', otherSecret).update(body).digest());
  const foreignCookie = `${body}.${sig}`;

  const res = makeRes();
  joinHandler(s, makeReq({
    body: { joinToken: tok },
    cookies: { [VOTER_COOKIE_NAME]: foreignCookie },
    headers: withCsrf(),
  }), res);
  // The foreign cookie fails verify(), so readVoterCookie returns null.
  // A fresh voter is minted instead.
  eq(res.statusCode, 200);
  assert(res.body.voterId !== 'aaaa', `should mint fresh vid, not honor foreign cookie's vid=aaaa`);
  assert(typeof res.cookies[VOTER_COOKIE_NAME] === 'string', 'new cookie should be issued');
});

console.log('\n=== Behavior test summary ===');
console.log(`  Total:  ${passed + failed}`);
console.log(`  Passed: ${passed}`);
console.log(`  Failed: ${failed}`);
process.exit(failed ? 1 : 0);
