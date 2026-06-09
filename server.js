// server.js — DUPS Photo Contest voting (hardened v4 — public-internet model)
// Run: npm install && npm start
'use strict';

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { WebSocketServer } = require('ws');
const QRCode = require('qrcode');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT          = parseInt(process.env.PORT || '3000', 10);
const DATA_DIR      = process.env.DUPS_DATA_DIR || path.join(__dirname, 'data');
const STATE_FILE    = path.join(DATA_DIR, 'state.json');
const ARCHIVE_FILE  = path.join(DATA_DIR, 'archive.json');
const DEV_MODE      = process.env.DEV_MODE === '1';

function parseTrustProxy(s) {
  if (s === undefined || s === null || s === '') return 'loopback';
  const trimmed = String(s).trim();
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (/^\d+$/.test(trimmed)) return parseInt(trimmed, 10);
  return trimmed;
}
const TRUST_PROXY = parseTrustProxy(process.env.TRUST_PROXY);

let PUBLIC_URL_STR = process.env.PUBLIC_URL || '';
let PUBLIC_URL = null;
if (PUBLIC_URL_STR) {
  try {
    PUBLIC_URL = new URL(PUBLIC_URL_STR);
    PUBLIC_URL_STR = PUBLIC_URL.origin;
  } catch (e) {
    console.error(`[boot] PUBLIC_URL is not a valid URL: ${PUBLIC_URL_STR}`);
    process.exit(1);
  }
}
const IS_PUBLIC_HTTPS = !!(PUBLIC_URL && PUBLIC_URL.protocol === 'https:');

const MAX_PHOTO_COUNT          = 500;
const MAX_WS_PAYLOAD_BYTES     = 4 * 1024;
const MAX_CONNECTIONS_PER_IP   = 8;
const MSG_RATE_BURST           = 30;
const MSG_RATE_PER_SEC         = 10;
const HEARTBEAT_INTERVAL_MS    = 30_000;
const HEARTBEAT_TIMEOUT_MS     = 60_000;
const JOIN_TOKEN_TTL_MS        = 6 * 60 * 60 * 1000;

const VOTER_COOKIE_NAME = 'dups_voter';
const ADMIN_COOKIE_NAME = 'dups_admin';
const CSRF_HEADER = 'x-dups-origin';
const CSRF_VALUE  = 'same-site';

let SERVER_SECRET = null;

// ---------------------------------------------------------------------------
// Signed tokens
// ---------------------------------------------------------------------------
function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}
function hmac(input) {
  return b64url(crypto.createHmac('sha256', SERVER_SECRET).update(input).digest());
}
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

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const session = {
  id: null,
  adminTokenId: null,
  photoCount: null,
  votingOpen: false,
  votingClosed: false,
  locked: false,
  roundNumber: 1,           // increments with each new round
  votes: {},                // vid -> { photoNumber, updatedAt, ipHash }
  joinedVoters: {},         // vid -> { joinedAt, ipHash, jti }
  redeemedJtis: {},
  currentQrJti: null,
  results: null,
  createdAt: null,
};

const archive = [];
const clients = new Map();
const ipConnections = new Map();

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------
function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}
function loadSecret() {
  const secretPath = path.join(DATA_DIR, 'secret');
  ensureDataDir();
  if (fs.existsSync(secretPath)) {
    SERVER_SECRET = fs.readFileSync(secretPath);
  } else {
    SERVER_SECRET = crypto.randomBytes(32);
    fs.writeFileSync(secretPath, SERVER_SECRET, { mode: 0o600 });
  }
}

let persistTimer = null;
function persistSoon() {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    try {
      const tmp = STATE_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(session));
      fs.renameSync(tmp, STATE_FILE);
      const tmpA = ARCHIVE_FILE + '.tmp';
      fs.writeFileSync(tmpA, JSON.stringify(archive));
      fs.renameSync(tmpA, ARCHIVE_FILE);
    } catch (e) {
      console.error('[persist] failed:', e.message);
    }
  }, 200);
}

function loadPersisted() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const data = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
      Object.assign(session, { redeemedJtis: {}, currentQrJti: null, roundNumber: 1 }, data);
      delete session.joinsByIpHash;
      console.log(`[boot] restored session ${session.id || '(none)'}`);
    }
    if (fs.existsSync(ARCHIVE_FILE)) {
      const a = JSON.parse(fs.readFileSync(ARCHIVE_FILE, 'utf8'));
      if (Array.isArray(a)) archive.push(...a);
    }
  } catch (e) {
    console.error('[boot] could not restore state:', e.message);
  }
  if (!session.id) freshSession();
}

function freshSession() {
    session.id = crypto.randomBytes(4).toString('hex');
    session.adminTokenId = null;
    session.photoCount = null;
    session.votingOpen = false;
    session.votingClosed = false;
    session.locked = false;
    session.roundNumber = 1;
    session.votes = {};
    session.joinedVoters = {};
    session.redeemedJtis = {};
    session.currentQrJti = null;
    session.results = null;
    session.createdAt = new Date().toISOString();
    // Delete persisted state so browser reconnects get a clean slate
    try { if (fs.existsSync(STATE_FILE)) fs.unlinkSync(STATE_FILE); } catch { }
    persistSoon();
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
function log(event, fields = {}) {
  console.log(JSON.stringify({ t: new Date().toISOString(), event, ...fields }));
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------
function clientIp(req) {
  const ip = (req.ip || (req.socket && req.socket.remoteAddress) || 'unknown');
  return String(ip).replace(/^::ffff:/, '');
}
function ipHash(ip) {
  return crypto.createHash('sha256').update(ip + (SERVER_SECRET || '')).digest('hex').slice(0, 12);
}
function isOriginAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  let parsed;
  try { parsed = new URL(origin); } catch { return false; }
  if (PUBLIC_URL) return parsed.origin === PUBLIC_URL.origin;
  const devHosts = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
  return devHosts.has(parsed.hostname) || devHosts.has(parsed.host);
}
function isHttps(req) {
  if (IS_PUBLIC_HTTPS) return true;
  if (req.secure || req.protocol === 'https') return true;
  return (req.headers['x-forwarded-proto'] || '').toLowerCase() === 'https';
}
function setSignedCookie(res, name, value, req) {
  res.cookie(name, value, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isHttps(req),
    maxAge: JOIN_TOKEN_TTL_MS,
    path: '/',
  });
}
function clearSignedCookie(res, name, req) {
  res.clearCookie(name, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isHttps(req),
    path: '/',
  });
}

// ---------------------------------------------------------------------------
// HTTP setup
// ---------------------------------------------------------------------------
const app = express();
app.set('trust proxy', TRUST_PROXY);
const server = http.createServer(app);

app.use(cookieParser());
app.use(express.json({ limit: '8kb' }));

function buildConnectSrc() {
  if (PUBLIC_URL) {
    const wsOrigin = PUBLIC_URL.origin.replace(/^http/, 'ws');
    return `'self' ${wsOrigin}`;
  }
  return "'self' ws: wss:";
}
const CSP_CONNECT_SRC = buildConnectSrc();

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (IS_PUBLIC_HTTPS) {
    res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  }
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "img-src 'self' data: https://dups.club https://*.dups.club https://i0.wp.com https://fonts.gstatic.com; " +
    "font-src 'self' https://fonts.gstatic.com data:; " +
    "script-src 'self'; " +
    "style-src 'self' https://fonts.googleapis.com; " +
    `connect-src ${CSP_CONNECT_SRC} https://tinyurl.com; ` +
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
  );
  next();
});

function requireCsrfHeader(req, res, next) {
  if ((req.headers[CSRF_HEADER] || '').toLowerCase() !== CSRF_VALUE) {
    return res.status(403).json({ error: 'csrf' });
  }
  next();
}

app.use(express.static(path.join(__dirname, 'public')));

// --- API: QR (admin only)
app.get('/api/qr', requireAdmin, async (req, res) => {
  try {
    if (!session.currentQrJti) {
      session.currentQrJti = crypto.randomBytes(8).toString('hex');
      persistSoon();
    }
    const joinToken = sign({ kind: 'join', sid: session.id, jti: session.currentQrJti });
    const url = buildVoterUrl(req, joinToken);
    const dataUrl = await QRCode.toDataURL(url, { width: 360, margin: 1, errorCorrectionLevel: 'M' });
    res.json({ url, dataUrl, sessionId: session.id, jti: session.currentQrJti });
  } catch (e) {
    log('qr_error', { err: e.message });
    res.status(500).json({ error: 'qr_failed' });
  }
});

function buildVoterUrl(req, joinToken) {
  let base;
  if (PUBLIC_URL) {
    const p = PUBLIC_URL.pathname.replace(/\/+$/, '');
    base = `${PUBLIC_URL.origin}${p}/`;
  } else {
    const proto = isHttps(req) ? 'https' : 'http';
    const host = req.headers.host || `localhost:${PORT}`;
    base = `${proto}://${host}/`;
  }
  return `${base}?j=${encodeURIComponent(joinToken)}`;
}

// --- API: voter join
app.post('/api/join', requireCsrfHeader, (req, res) => {
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

  const ip  = clientIp(req);
  const ipH = ipHash(ip);

  // Only block if QR was explicitly rotated/invalidated
  if (parsed.jti && session.redeemedJtis[parsed.jti] === '__invalidated') {
    log('voter_join_jti_rotated', { jti: parsed.jti, ipHash: ipH });
    return res.status(409).json({ error: 'token_used', message: 'This QR code has been replaced. Please scan the new QR code.' });
  }

  const vid = crypto.randomBytes(8).toString('hex');
  const voterTok = sign({ kind: 'voter', sid: session.id, vid, jti: parsed.jti });
  setSignedCookie(res, VOTER_COOKIE_NAME, voterTok, req);
  session.joinedVoters[vid] = { joinedAt: Date.now(), ipHash: ipH, jti: parsed.jti };
  persistSoon();
  log('voter_joined', { vid, jti: parsed.jti, ipHash: ipH });
  res.json({ ok: true, voterId: vid });
});

// --- API: admin claim
app.post('/api/admin/claim', requireCsrfHeader, (req, res) => {
  const existing = readAdminCookie(req);
  if (existing && existing.sid === session.id && existing.aid === session.adminTokenId) {
    return res.json({ ok: true, adminId: existing.aid });
  }
  if (session.adminTokenId) {
    return res.status(409).json({ error: 'taken' });
  }
  const aid = crypto.randomBytes(8).toString('hex');
  const tok = sign({ kind: 'admin', sid: session.id, aid });
  session.adminTokenId = aid;
  setSignedCookie(res, ADMIN_COOKIE_NAME, tok, req);
  persistSoon();
  log('admin_claimed', { aid, ip: clientIp(req) });
  res.json({ ok: true, adminId: aid });
});

// --- API: admin archive download
app.get('/api/admin/archive', requireAdmin, (req, res) => {
  res.json({ archive });
});

// --- API: public session state
app.get('/api/session', (req, res) => {
  res.json(buildPublicState(identifyFromCookies(req)));
});

// --- API: clear cookies on reset
app.post('/api/clear-cookies', requireCsrfHeader, (req, res) => {
  clearSignedCookie(res, VOTER_COOKIE_NAME, req);
  clearSignedCookie(res, ADMIN_COOKIE_NAME, req);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------
function readVoterCookie(req) {
  const t = req.cookies && req.cookies[VOTER_COOKIE_NAME];
  if (!t) return null;
  const p = verify(t, JOIN_TOKEN_TTL_MS);
  return p && p.kind === 'voter' ? p : null;
}
function readAdminCookie(req) {
  const t = req.cookies && req.cookies[ADMIN_COOKIE_NAME];
  if (!t) return null;
  const p = verify(t, JOIN_TOKEN_TTL_MS);
  return p && p.kind === 'admin' ? p : null;
}
function requireAdmin(req, res, next) {
  const a = readAdminCookie(req);
  if (!a || a.sid !== session.id || a.aid !== session.adminTokenId) {
    return res.status(403).json({ error: 'not_admin' });
  }
  req.admin = a;
  next();
}
function identifyFromCookies(req) {
  const a = readAdminCookie(req);
  if (a && a.sid === session.id && a.aid === session.adminTokenId) return { role: 'admin', aid: a.aid };
  const v = readVoterCookie(req);
  if (v && v.sid === session.id && session.joinedVoters[v.vid]) {
    const my = session.votes[v.vid];
    return { role: 'voter', vid: v.vid, hasVote: !!my, myVote: my ? my.photoNumber : null };
  }
  return { role: null };
}
function buildPublicState(you) {
  const activeVoters = [...clients.values()].filter(c => c.role === 'voter').length;
  return {
    sessionId: session.id,
    adminTaken: !!session.adminTokenId,
    photoCount: session.photoCount,
    votingOpen: session.votingOpen,
    votingClosed: session.votingClosed,
    locked: session.locked,
    roundNumber: session.roundNumber,
    joinedVoterCount: Object.keys(session.joinedVoters).length,
    activeVoterCount: activeVoters,
    voteCount: Object.keys(session.votes).length,
    results: session.votingClosed ? session.results : null,
    you: you || { role: null },
  };
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------
const wss = new WebSocketServer({
  noServer: true,
  maxPayload: MAX_WS_PAYLOAD_BYTES,
  perMessageDeflate: false,
});

server.on('upgrade', (req, socket, head) => {
  const ip = (req.socket && req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
  if (!isOriginAllowed(req)) {
    log('ws_reject', { reason: 'origin', origin: req.headers.origin, ip });
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  const existing = ipConnections.get(ip);
  if (existing && existing.size >= MAX_CONNECTIONS_PER_IP) {
    log('ws_reject', { reason: 'ip_cap', ip });
    socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

const heartbeatTimer = setInterval(() => {
  const now = Date.now();
  for (const [ws, meta] of clients.entries()) {
    if (now - meta.lastSeen > HEARTBEAT_TIMEOUT_MS) {
      log('ws_kill_stale', { ip: meta.ip });
      try { ws.terminate(); } catch {}
      continue;
    }
    try { ws.ping(); } catch {}
  }
}, HEARTBEAT_INTERVAL_MS);

wss.on('connection', (ws, req) => {
  const ip = (req.socket && req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
  const cookies = parseCookieHeader(req.headers.cookie || '');
  const adminCookie = cookies[ADMIN_COOKIE_NAME] ? verify(cookies[ADMIN_COOKIE_NAME], JOIN_TOKEN_TTL_MS) : null;
  const voterCookie = cookies[VOTER_COOKIE_NAME] ? verify(cookies[VOTER_COOKIE_NAME], JOIN_TOKEN_TTL_MS) : null;

  let role = null, vid = null, aid = null;
  if (adminCookie && adminCookie.sid === session.id && adminCookie.aid === session.adminTokenId) {
    role = 'admin'; aid = adminCookie.aid;
  } else if (voterCookie && voterCookie.sid === session.id && session.joinedVoters[voterCookie.vid]) {
    role = 'voter'; vid = voterCookie.vid;
  }

  const meta = {
    ip, role, aid, vid,
    lastSeen: Date.now(),
    bucket: { tokens: MSG_RATE_BURST, last: Date.now() },
  };
  clients.set(ws, meta);
  if (!ipConnections.has(ip)) ipConnections.set(ip, new Set());
  ipConnections.get(ip).add(ws);

  ws.on('pong', () => { meta.lastSeen = Date.now(); });
  sendTo(ws, { type: 'hello', state: stateForClient(meta) });

  ws.on('message', (raw) => {
    meta.lastSeen = Date.now();
    if (!takeToken(meta.bucket)) {
      log('ws_rate_limit', { ip });
      sendTo(ws, { type: 'error', message: 'Slow down.' });
      return;
    }
    let msg;
    try { msg = JSON.parse(raw.toString('utf8')); }
    catch { return; }
    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;
    handleMessage(ws, meta, msg);
  });

  ws.on('close', () => {
    clients.delete(ws);
    const set = ipConnections.get(ip);
    if (set) { set.delete(ws); if (set.size === 0) ipConnections.delete(ip); }
  });
  ws.on('error', (e) => log('ws_error', { ip, err: e.message }));
});

function parseCookieHeader(str) {
  const out = {};
  for (const part of str.split(/;\s*/)) {
    const i = part.indexOf('=');
    if (i > 0) {
      const k = part.slice(0, i);
      const v = part.slice(i + 1);
      try { out[k] = decodeURIComponent(v); } catch { out[k] = v; }
    }
  }
  return out;
}

function takeToken(bucket) {
  const now = Date.now();
  const elapsedSec = (now - bucket.last) / 1000;
  bucket.tokens = Math.min(MSG_RATE_BURST, bucket.tokens + elapsedSec * MSG_RATE_PER_SEC);
  bucket.last = now;
  if (bucket.tokens < 1) return false;
  bucket.tokens -= 1;
  return true;
}

function sendTo(ws, msg) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(msg));
}
function broadcast(msg, filter = null) {
  const payload = JSON.stringify(msg);
  for (const [ws, meta] of clients.entries()) {
    if (ws.readyState !== ws.OPEN) continue;
    if (filter && !filter(meta)) continue;
    ws.send(payload);
  }
}
function stateForClient(meta) {
  let you = { role: meta.role };
  if (meta.role === 'voter' && meta.vid) {
    const my = session.votes[meta.vid];
    you = { role: 'voter', vid: meta.vid, hasVote: !!my, myVote: my ? my.photoNumber : null };
  } else if (meta.role === 'admin') {
    you = { role: 'admin' };
  }
  return buildPublicState(you);
}
function broadcastState() {
  for (const [ws, meta] of clients.entries()) {
    if (ws.readyState !== ws.OPEN) continue;
    ws.send(JSON.stringify({ type: 'state', state: stateForClient(meta) }));
  }
}

// ---------------------------------------------------------------------------
// Message handlers
// ---------------------------------------------------------------------------
function isPositiveInteger(v, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (typeof v !== 'number') return false;
  if (!Number.isInteger(v)) return false;
  return v >= min && v <= max;
}

function handleMessage(ws, meta, msg) {
  switch (msg.type) {

    case 'set-photo-count': {
      if (meta.role !== 'admin') return reject(ws, 'not_admin');
      if (session.votingClosed) return reject(ws, 'voting_closed');
      const x = typeof msg.photoCount === 'number' ? msg.photoCount : Number(msg.photoCount);
      if (!isPositiveInteger(x, { min: 1, max: MAX_PHOTO_COUNT })) {
        return reject(ws, `Photo count must be an integer between 1 and ${MAX_PHOTO_COUNT}.`);
      }
      const hasVotes = Object.keys(session.votes).length > 0;
      if (session.votingOpen && hasVotes && !msg.confirmReset) {
        return sendTo(ws, {
          type: 'confirm-needed',
          action: 'change-photo-count',
          message: `${Object.keys(session.votes).length} votes already cast. Changing the count will clear them.`,
        });
      }
      session.photoCount = x;
      session.votingOpen = true;
      session.votingClosed = false;
      session.results = null;
      if (hasVotes && msg.confirmReset) session.votes = {};
      persistSoon();
      log('photo_count_set', { x, aid: meta.aid, round: session.roundNumber });
      broadcastState();
      sendTo(ws, { type: 'photo-count-set', photoCount: x });
      return;
    }

    case 'submit-vote': {
      if (meta.role !== 'voter' || !meta.vid) return reject(ws, 'not_voter');
      if (!session.joinedVoters[meta.vid])    return reject(ws, 'voter_unknown');
      if (!session.votingOpen || session.votingClosed) return reject(ws, 'voting_not_open');
      const n = typeof msg.photoNumber === 'number' ? msg.photoNumber : Number(msg.photoNumber);
      if (!isPositiveInteger(n, { min: 1, max: session.photoCount })) {
        return reject(ws, `Vote must be an integer between 1 and ${session.photoCount}.`);
      }
      const recordIpHash = session.joinedVoters[meta.vid] && session.joinedVoters[meta.vid].ipHash;
      session.votes[meta.vid] = { photoNumber: n, updatedAt: Date.now(), ipHash: recordIpHash };
      persistSoon();
      log('vote_recorded', { vid: meta.vid, n, round: session.roundNumber });
      sendTo(ws, { type: 'vote-recorded', photoNumber: n });
      broadcastState();
      return;
    }

    case 'close-voting': {
      if (meta.role !== 'admin') return reject(ws, 'not_admin');
      if (!session.votingOpen || session.votingClosed) return;
      session.votingOpen = false;
      session.votingClosed = true;
      session.results = computeResults();
      persistSoon();
      log('voting_closed', { totalVotes: session.results.totalVotes, aid: meta.aid, round: session.roundNumber });
      broadcastState();
      broadcast({ type: 'voting-closed' }, m => m.role === 'voter');
      sendTo(ws, { type: 'results', results: session.results });
      return;
    }

    case 'next-round': {
      // Admin starts a new round — voters stay connected, QR stays the same
      if (meta.role !== 'admin') return reject(ws, 'not_admin');
      // Archive the current round results
      if (Object.keys(session.votes).length > 0 || session.results) {
        archive.push({
          archivedAt: new Date().toISOString(),
          sessionId: session.id,
          roundNumber: session.roundNumber,
          photoCount: session.photoCount,
          votes: session.votes,
          results: session.results,
        });
      }
      // Increment round, clear votes and photo count, keep voters and admin
      session.roundNumber = (session.roundNumber || 1) + 1;
      session.photoCount = null;
      session.votingOpen = false;
      session.votingClosed = false;
      session.votes = {};
      session.results = null;
      persistSoon();
      log('next_round', { roundNumber: session.roundNumber, aid: meta.aid });
      broadcastState();
      // Tell voters to go to waiting screen
      broadcast({ type: 'next-round', roundNumber: session.roundNumber }, m => m.role === 'voter');
      sendTo(ws, { type: 'next-round', roundNumber: session.roundNumber });
      return;
    }

    case 'rotate-qr': {
      if (meta.role !== 'admin') return reject(ws, 'not_admin');
      const prev = session.currentQrJti;
      if (prev && !session.redeemedJtis[prev]) {
        session.redeemedJtis[prev] = '__invalidated';
      }
      session.currentQrJti = crypto.randomBytes(8).toString('hex');
      persistSoon();
      log('qr_rotated', { aid: meta.aid, invalidated: prev });
      sendTo(ws, { type: 'qr-rotated' });
      return;
    }

    case 'lock-room': {
      if (meta.role !== 'admin') return reject(ws, 'not_admin');
      session.locked = !!msg.locked;
      persistSoon();
      log('room_locked', { locked: session.locked, aid: meta.aid });
      broadcastState();
      return;
    }

    case 'reset-session': {
      // Master reset — clears everything including cookies and roles
      if (meta.role !== 'admin') return reject(ws, 'not_admin');
      if (Object.keys(session.votes).length > 0 || session.results) {
        archive.push({
          archivedAt: new Date().toISOString(),
          sessionId: session.id,
          roundNumber: session.roundNumber,
          photoCount: session.photoCount,
          votes: session.votes,
          results: session.results,
        });
      }
      log('session_reset', { previousSessionId: session.id });
      freshSession();
      broadcast({ type: 'reset' });
      for (const [w] of clients.entries()) {
        try { w.close(4000, 'session_reset'); } catch {}
      }
      return;
    }

    case 'heartbeat':
      sendTo(ws, { type: 'heartbeat-ack' });
      return;
  }
}

function reject(ws, message) {
  sendTo(ws, { type: 'error', message: typeof message === 'string' ? message : 'rejected' });
}

function computeResults() {
  const tally = {};
  for (let i = 1; i <= session.photoCount; i++) tally[i] = 0;
  let total = 0;
  const ipVoteCounts = {};
  for (const v of Object.values(session.votes)) {
    if (!Number.isInteger(v.photoNumber)) continue;
    if (v.photoNumber < 1 || v.photoNumber > session.photoCount) continue;
    tally[v.photoNumber]++;
    total++;
    if (v.ipHash) ipVoteCounts[v.ipHash] = (ipVoteCounts[v.ipHash] || 0) + 1;
  }
  const clusters = Object.entries(ipVoteCounts)
    .filter(([, c]) => c > 1)
    .map(([ipH, c]) => ({ ipHash: ipH, count: c }));
  const sorted = Object.entries(tally)
    .map(([photo, count]) => ({ photo: Number(photo), count }))
    .sort((a, b) => b.count - a.count || a.photo - b.photo);
  return { sorted, totalVotes: total, clusters };
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
loadSecret();
loadPersisted();

server.listen(PORT, '0.0.0.0', () => {
  console.log('\nDUPS Photo Contest server (hardened v4 — public-internet model)');
  console.log(`  Listening:  http://0.0.0.0:${PORT}`);
  console.log(`  Data dir:   ${DATA_DIR}`);
  console.log(`  Trust:      ${TRUST_PROXY}`);
  if (PUBLIC_URL) {
    console.log(`  Public URL: ${PUBLIC_URL.origin}    <-- voters reach this`);
    if (!IS_PUBLIC_HTTPS && !DEV_MODE) {
      console.warn('\n  WARNING: PUBLIC_URL is plain http. Voter cookies will NOT be Secure');
      console.warn('  and traffic can be inspected. Strongly recommend running behind TLS.');
      console.warn('  Set DEV_MODE=1 to silence this warning during local development.\n');
    }
  } else {
    console.log('  Public URL: (none — running in DEV mode against this host)');
    console.log('  Set PUBLIC_URL=https://your.domain.com before production use.');
  }
  console.log('');
  log('boot', { port: PORT, sessionId: session.id, publicUrl: PUBLIC_URL && PUBLIC_URL.origin });
});

function shutdown() {
  console.log('\nShutting down...');
  clearInterval(heartbeatTimer);
  try { fs.writeFileSync(STATE_FILE, JSON.stringify(session)); } catch {}
  try { fs.writeFileSync(ARCHIVE_FILE, JSON.stringify(archive)); } catch {}
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
