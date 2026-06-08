// server.js — DUPS Photo Contest voting (hardened v4 — public-internet model)
// Run: npm install && npm start
//
// Threat model & mitigations: see REDTEAM.md (rounds 1, 2, 3).
//
// Single-file Node server. No external services. Persists to ./data/state.json
// so a crash/restart doesn't lose the in-progress vote.
//
// v4 is built for PUBLIC-INTERNET deployment, not LAN. The admin runs this
// behind a reverse proxy (nginx/Caddy/Cloudflare/Render/Fly/Railway/etc.)
// with TLS and points voters at a public URL. The QR code encodes that
// public URL.
//
// Required config:
//   PUBLIC_URL   - canonical URL voters reach (e.g. https://vote.dups.club)
//                  Drives the QR target AND the Origin allow-list.
//                  If unset, server starts in DEV mode and uses http://localhost.
// Optional config:
//   PORT         - listen port (default 3000)
//   TRUST_PROXY  - express trust-proxy value (default 'loopback'; use 1 for
//                  a single front-proxy, or specific subnet for cloud)
//   DEV_MODE     - "1" suppresses the no-HTTPS warning; only for local dev
//   DUPS_DATA_DIR- override the data directory location
//
// v4 changes over v3:
// - PUBLIC_URL-driven Origin check (no more LAN auto-detection)
// - Per-IP voter join cap REMOVED (it broke under CGNAT / corporate / school
//   networks — legitimate voters share IPs at scale). Replaced by:
//     * "Lock Room" admin button (primary live defense)
//     * IP-cluster warning at tally time (informational, not enforcement)
//     * Single-redemption join tokens (carried over from v3)
// - QR URL derived from PUBLIC_URL, not from request host
// - HTTPS strongly recommended; loud boot warning if not
// - Boot banner reflects public-internet model

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
// TRUST_PROXY parsing — Express accepts boolean, integer hop count, string
// IP/CIDR list, or a function. We accept env strings 'true'/'false'/numbers
// and pass them through correctly.
function parseTrustProxy(s) {
  if (s === undefined || s === null || s === '') return 'loopback';
  const trimmed = String(s).trim();
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (/^\d+$/.test(trimmed)) return parseInt(trimmed, 10);
  return trimmed;
}
const TRUST_PROXY = parseTrustProxy(process.env.TRUST_PROXY);

// PUBLIC_URL parsing. If absent, run in dev mode against http://localhost:PORT.
// If present, voters reach this URL. The QR encodes it; the Origin check
// requires it.
let PUBLIC_URL_STR = process.env.PUBLIC_URL || '';
let PUBLIC_URL = null;
if (PUBLIC_URL_STR) {
  try {
    PUBLIC_URL = new URL(PUBLIC_URL_STR);
    // Strip trailing slash for clean concat
    PUBLIC_URL_STR = PUBLIC_URL.origin;
  } catch (e) {
    console.error(`[boot] PUBLIC_URL is not a valid URL: ${PUBLIC_URL_STR}`);
    process.exit(1);
  }
}
const IS_PUBLIC_HTTPS = !!(PUBLIC_URL && PUBLIC_URL.protocol === 'https:');

// Hard limits.
const MAX_PHOTO_COUNT          = 500;
const MAX_WS_PAYLOAD_BYTES     = 4 * 1024;
const MAX_CONNECTIONS_PER_IP   = 8;        // simultaneous WS sockets per IP (anti-DoS, not anti-dupe)
const MSG_RATE_BURST           = 30;
const MSG_RATE_PER_SEC         = 10;
const HEARTBEAT_INTERVAL_MS    = 30_000;
const HEARTBEAT_TIMEOUT_MS     = 60_000;
const JOIN_TOKEN_TTL_MS        = 6 * 60 * 60 * 1000;

// Cookie names
const VOTER_COOKIE_NAME = 'dups_voter';
const ADMIN_COOKIE_NAME = 'dups_admin';

// CSRF header. Browser cross-origin JS cannot set custom headers without a
// preflight, and we set no CORS headers, so all cross-origin POSTs are blocked.
const CSRF_HEADER = 'x-dups-origin';
const CSRF_VALUE  = 'same-site';

// HMAC secret — persisted across restarts so cookies survive.
let SERVER_SECRET = null;

// ---------------------------------------------------------------------------
// Signed tokens (HMAC-SHA256, base64url, payload|ts|sig)
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
  // constant-time compare on equal-length strings
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
// State (all in-memory, mirrored to disk on change)
// ---------------------------------------------------------------------------
const session = {
  id: null,
  adminTokenId: null,
  photoCount: null,
  votingOpen: false,
  votingClosed: false,
  locked: false,
  votes: {},                // vid -> { photoNumber, updatedAt, ipHash }
  joinedVoters: {},         // vid -> { joinedAt, ipHash, jti }
  redeemedJtis: {},         // jti -> vid    (which voter cookie redeemed this jti)
  currentQrJti: null,       // the currently-broadcast QR's jti (for admin "rotate" UX)
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
      // Write atomically so a crash mid-write doesn't corrupt state.
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
      // Be defensive about older state files missing new fields, and strip
      // any obsolete v3 fields (e.g. joinsByIpHash) that no longer apply.
      Object.assign(session, { redeemedJtis: {}, currentQrJti: null }, data);
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
  session.votes = {};
  session.joinedVoters = {};
  session.redeemedJtis = {};
  session.currentQrJti = null;
  session.results = null;
  session.createdAt = new Date().toISOString();
  delete session.joinsByIpHash; // strip any stale v3 field
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
  // Honors X-Forwarded-For via trust proxy config. Falls back to socket.
  const ip = (req.ip || (req.socket && req.socket.remoteAddress) || 'unknown');
  return String(ip).replace(/^::ffff:/, '');
}

function ipHash(ip) {
  return crypto.createHash('sha256').update(ip + (SERVER_SECRET || '')).digest('hex').slice(0, 12);
}

// Origin allow-list. In production mode (PUBLIC_URL set), only the configured
// origin is allowed. In dev mode (PUBLIC_URL unset), localhost variants are
// allowed. Non-browser clients (no Origin header) are allowed; they can't
// be the source of CSWSH.
function isOriginAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // non-browser clients (curl/tests)
  let parsed;
  try { parsed = new URL(origin); } catch { return false; }
  if (PUBLIC_URL) {
    // Production: exact origin match (scheme + host + port).
    return parsed.origin === PUBLIC_URL.origin;
  }
  // Dev mode: only localhost variants.
  const devHosts = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
  return devHosts.has(parsed.hostname) || devHosts.has(parsed.host);
}

function isHttps(req) {
  // True if PUBLIC_URL is https OR proxy says so OR request is already TLS.
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
app.set('trust proxy', TRUST_PROXY); // honors X-Forwarded-* per env config
const server = http.createServer(app);

app.use(cookieParser());
app.use(express.json({ limit: '8kb' }));

// Build connect-src directive. In production (PUBLIC_URL set) we lock it to
// the configured origin's WSS endpoint; in dev we allow ws: and wss: broadly.
function buildConnectSrc() {
  if (PUBLIC_URL) {
    const wsOrigin = PUBLIC_URL.origin.replace(/^http/, 'ws');
    return `'self' ${wsOrigin}`;
  }
  return "'self' ws: wss:";
}
const CSP_CONNECT_SRC = buildConnectSrc();

// Security headers — NO 'unsafe-inline' in style-src.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  // HSTS in production HTTPS only — never on plain HTTP (could trap dev).
  if (IS_PUBLIC_HTTPS) {
    res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  }

    //_____________________________________________________________________________________________________________
    //  Pre Sort URL mod
    //--------------------------------------------------------------------------------------------------------------

   // res.setHeader('Content-Security-Policy',
   // "default-src 'self'; " +
   // "img-src 'self' data: https://dups.club https://*.dups.club https://i0.wp.com https://fonts.gstatic.com; " +
   // "font-src 'self' https://fonts.gstatic.com data:; " +
   // "script-src 'self'; " +
   // "style-src 'self' https://fonts.googleapis.com; " +
  //  `connect-src ${CSP_CONNECT_SRC}; ` +
 //   "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
//  );

    //_____________________________________________________________________________________________________________
    // end pre Sort URL mod
    // Begin mod 1
    //--------------------------------------------------------------------------------------------------------------
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "img-src 'self' data: https://dups.club https://*.dups.club https://i0.wp.com https://fonts.gstatic.com; " +
        "font-src 'self' https://fonts.gstatic.com data:; " +
        "script-src 'self'; " +
        "style-src 'self' https://fonts.googleapis.com; " +
        `connect-src ${CSP_CONNECT_SRC} https://tinyurl.com; ` +
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    );

    //--------------------------------------------------------------------------------------------------------------
    // end mod 1
    //----------------------------------------------------------------------------------------------

    next();
});

// CSRF guard for state-changing endpoints. Cross-origin browser JS cannot send
// custom headers without a preflight; we don't reply to preflights from foreign
// origins, so this is a hard wall.
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
    // Reuse current jti if one exists; otherwise mint a fresh one.
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

// Build the voter-facing URL that the QR code encodes. Preserves any path
// from PUBLIC_URL (so PUBLIC_URL=https://example.com/voting works), normalizes
// trailing slashes, and appends ?j=<joinToken>.
function buildVoterUrl(req, joinToken) {
  let base;
  if (PUBLIC_URL) {
    // Preserve full pathname from PUBLIC_URL; strip trailing slash for clean concat.
    const path = PUBLIC_URL.pathname.replace(/\/+$/, '');
    base = `${PUBLIC_URL.origin}${path}/`;
  } else {
    // Dev fallback: synthesized from the admin's request.
    const proto = isHttps(req) ? 'https' : 'http';
    const host = req.headers.host || `localhost:${PORT}`;
    base = `${proto}://${host}/`;
  }
  return `${base}?j=${encodeURIComponent(joinToken)}`;
}

// --- API: voter join (single-redemption jti)
//
// NOTE: We deliberately do NOT cap voters per IP. Carrier-grade NAT (mobile
// carriers, corporate offices, schools) routinely puts many legitimate users
// behind a single IP. The defenses against incognito-mode dupe-voting are:
//   1. Single-redemption join tokens (jti consumed on first use)
//   2. Admin "Rotate QR" to invalidate outstanding tokens
//   3. "Lock Room" to freeze the joiner list
//   4. IP-cluster warnings at tally time (informational, not enforcement)
app.post('/api/join', requireCsrfHeader, (req, res) => {
  const { joinToken } = req.body || {};
  if (!joinToken) return res.status(400).json({ error: 'no_token' });
  const parsed = verify(joinToken, JOIN_TOKEN_TTL_MS);
  if (!parsed || parsed.kind !== 'join') return res.status(400).json({ error: 'bad_token' });
  if (parsed.sid !== session.id)         return res.status(400).json({ error: 'stale_session' });
  if (session.locked)                    return res.status(403).json({ error: 'locked' });

  // Already a voter for this session? Reuse cookie. Idempotent.
  const existing = readVoterCookie(req);
  if (existing && existing.sid === session.id && session.joinedVoters[existing.vid]) {
    return res.json({ ok: true, voterId: existing.vid });
  }

  const ip  = clientIp(req);
  const ipH = ipHash(ip);


    // *************************************************** Change to allow multiple scans of the same QR code, with a single redemption per jti. ***************************************************

  // Single-redemption jti: if this jti was already redeemed (or invalidated by
  // an admin QR rotation), reject unless the requester has the exact cookie
  // of the original redeemer.
         // if (parsed.jti && session.redeemedJtis[parsed.jti]) {
        //    const redeemerVid = session.redeemedJtis[parsed.jti];
        //  const isOriginal = existing && existing.vid === redeemerVid && redeemerVid !== '__invalidated';
        // if (!isOriginal) {
        //log('voter_join_jti_replay', { jti: parsed.jti, ipHash: ipH, reason: redeemerVid === '__invalidated' ? 'rotated' : 'replay' });
        //return res.status(409).json({ error: 'token_used', message: 'This QR code has already been used or has been replaced. Ask the Administrator for a fresh one.' });
    // }
    //}

    // ******************************************** Replacement for the above block: ********************************************
    // Allow multiple voters to scan the same QR code.
    // Only block scans if the QR has been explicitly rotated by the admin.
    if (parsed.jti && session.redeemedJtis[parsed.jti] === '__invalidated') {
        log('voter_join_jti_rotated', { jti: parsed.jti, ipHash: ipH });
        return res.status(409).json({ error: 'token_used', message: 'This QR code has been replaced. Please scan the new QR code.' });
    }

    // ****************************************** end replacement block ******************************************

  // Mint a fresh voter cookie.
  const vid = crypto.randomBytes(8).toString('hex');
  const voterTok = sign({ kind: 'voter', sid: session.id, vid, jti: parsed.jti });
  setSignedCookie(res, VOTER_COOKIE_NAME, voterTok, req);
  session.joinedVoters[vid] = { joinedAt: Date.now(), ipHash: ipH, jti: parsed.jti };
  if (parsed.jti) session.redeemedJtis[parsed.jti] = vid;
  persistSoon();
  log('voter_joined', { vid, jti: parsed.jti, ipHash: ipH });
  res.json({ ok: true, voterId: vid });
});

// --- API: admin claim
app.post('/api/admin/claim', requireCsrfHeader, (req, res) => {
  const existing = readAdminCookie(req);

  // Branch 1: existing cookie matches the current admin slot — idempotent OK.
  if (existing && existing.sid === session.id && existing.aid === session.adminTokenId) {
    return res.json({ ok: true, adminId: existing.aid });
  }
  // Branch 2: slot is taken by someone else — reject.
  if (session.adminTokenId) {
    return res.status(409).json({ error: 'taken' });
  }
  // Branch 3: slot is free — mint new admin.
  const aid = crypto.randomBytes(8).toString('hex');
  const tok = sign({ kind: 'admin', sid: session.id, aid });
  session.adminTokenId = aid;
  setSignedCookie(res, ADMIN_COOKIE_NAME, tok, req);
  persistSoon();
  log('admin_claimed', { aid, ip: clientIp(req) });
  res.json({ ok: true, adminId: aid });
});

// --- API: admin downloads the archive
app.get('/api/admin/archive', requireAdmin, (req, res) => {
  res.json({ archive });
});

// --- API: public-ish state (cookies determine 'you')
app.get('/api/session', (req, res) => {
  res.json(buildPublicState(identifyFromCookies(req)));
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
      log('photo_count_set', { x, aid: meta.aid });
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
      // Stamp the IP hash AT VOTE TIME — used for clustering check on close.
      const recordIpHash = session.joinedVoters[meta.vid] && session.joinedVoters[meta.vid].ipHash;
      session.votes[meta.vid] = { photoNumber: n, updatedAt: Date.now(), ipHash: recordIpHash };
      persistSoon();
      log('vote_recorded', { vid: meta.vid, n });
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
      log('voting_closed', { totalVotes: session.results.totalVotes, aid: meta.aid });
      broadcastState();
      broadcast({ type: 'voting-closed' }, m => m.role === 'voter');
      sendTo(ws, { type: 'results', results: session.results });
      return;
    }

    case 'rotate-qr': {
      if (meta.role !== 'admin') return reject(ws, 'not_admin');
      // Invalidate the previous QR's jti if it was never redeemed. We mark it
      // with a sentinel '__invalidated' so that future scans of the old QR
      // are rejected as token_used, the same way a normal redemption would be.
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
      if (meta.role !== 'admin') return reject(ws, 'not_admin');
      if (Object.keys(session.votes).length > 0 || session.results) {
        archive.push({
          archivedAt: new Date().toISOString(),
          sessionId: session.id,
          photoCount: session.photoCount,
          votes: session.votes,
          results: session.results,
        });
      }
          log('session_reset', { previousSessionId: session.id });
          freshSession();
          // Tell clients to clear their cookies, then disconnect them.
          broadcast({ type: 'reset' });
          for (const [w, m] of clients.entries()) {
              try { w.close(4000, 'session_reset'); } catch { }
          }
          return;

    case 'heartbeat':
      sendTo(ws, { type: 'heartbeat-ack' });
      return;
  }
  // unknown type: ignore
}

function reject(ws, message) {
  sendTo(ws, { type: 'error', message: typeof message === 'string' ? message : 'rejected' });
}

function computeResults() {
  const tally = {};
  for (let i = 1; i <= session.photoCount; i++) tally[i] = 0;
  let total = 0;
  // For admin's awareness, build IP cluster info: which IP hashes produced
  // multiple votes. This is informational; it does NOT auto-invalidate any vote.
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
