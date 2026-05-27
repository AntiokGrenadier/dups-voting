// test/harness.js — shared test infrastructure
'use strict';

const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');
const os = require('os');
const WebSocket = require('ws');

const ROOT = path.resolve(__dirname, '..');
const PORT = 30000 + Math.floor(Math.random() * 1000);
const BASE = `http://127.0.0.1:${PORT}`;
const WS_BASE = `ws://127.0.0.1:${PORT}/`;

const TMP_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'dups-test-'));

function copyRecursive(src, dst) {
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    fs.mkdirSync(dst, { recursive: true });
    for (const e of fs.readdirSync(src)) copyRecursive(path.join(src, e), path.join(dst, e));
  } else {
    fs.copyFileSync(src, dst);
  }
}

for (const f of ['server.js', 'package.json']) copyRecursive(path.join(ROOT, f), path.join(TMP_DATA, f));
copyRecursive(path.join(ROOT, 'public'), path.join(TMP_DATA, 'public'));
if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
  fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(TMP_DATA, 'node_modules'), 'dir');
}

let serverProc = null;
let serverEnv = {};  // last env used, so restartServer can preserve it

function startServer(extraEnv = {}) {
  serverEnv = { ...extraEnv };
  return new Promise((resolve, reject) => {
    serverProc = spawn(process.execPath, ['server.js'], {
      cwd: TMP_DATA,
      env: { ...process.env, PORT: String(PORT), DEV_MODE: '1', ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let buf = '';
    const onData = (chunk) => {
      buf += chunk.toString();
      // v4 banner: 'Listening:  http://0.0.0.0:PORT' OR boot JSON log line
      if (buf.includes(`Listening:`) || buf.includes(`"event":"boot"`)) {
        serverProc.stdout.off('data', onData);
        resolve();
      }
    };
    serverProc.stdout.on('data', onData);
    serverProc.stderr.on('data', d => {
      // Don't echo expected warnings to test output
      const s = d.toString();
      if (!/WARNING: PUBLIC_URL is plain http/.test(s)) {
        process.stderr.write(`[srv-err] ${s}`);
      }
    });
    serverProc.on('exit', (code) => { if (code) console.error('server exit', code); });
    setTimeout(() => reject(new Error('server boot timeout')), 5000);
  });
}

function stopServer() {
  if (serverProc) { serverProc.kill('SIGTERM'); serverProc = null; }
}

async function restartServer(extraEnv) {
  // No arg → dev-mode restart (no env overrides). Explicit {} → also dev-mode.
  // Explicit object with values → those values override.
  const envToUse = (extraEnv === undefined) ? {} : extraEnv;
  stopServer();
  try {
    const dir = path.join(TMP_DATA, 'data');
    if (fs.existsSync(dir)) {
      for (const f of fs.readdirSync(dir)) {
        if (f === 'secret') continue; // keep so cookie signatures remain valid across restart
        fs.unlinkSync(path.join(dir, f));
      }
    }
  } catch {}
  await startServer(envToUse);
  await sleep(150);
}

function httpReq({ method = 'GET', path: p = '/', body = null, headers = {}, cookies = {} }) {
  return new Promise((resolve, reject) => {
    const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    const opts = {
      hostname: '127.0.0.1', port: PORT, path: p, method,
      headers: {
        'Content-Type': 'application/json',
        ...(cookieHeader ? { 'Cookie': cookieHeader } : {}),
        ...headers,
      },
    };
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        const setCookies = res.headers['set-cookie'] || [];
        const newCookies = { ...cookies };
        for (const c of setCookies) {
          const kv = c.split(';')[0];
          const i = kv.indexOf('=');
          if (i > 0) {
            const k = kv.slice(0, i);
            const v = kv.slice(i + 1);
            // empty value means clear
            if (v === '') delete newCookies[k];
            else newCookies[k] = v;
          }
        }
        resolve({ status: res.statusCode, body: data, json: tryJSON(data), cookies: newCookies, headers: res.headers });
      });
    });
    req.on('error', reject);
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}
function tryJSON(s) { try { return JSON.parse(s); } catch { return null; } }

function openWS({ cookies = {}, origin = `http://127.0.0.1:${PORT}` } = {}) {
  const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
  const headers = origin ? { Origin: origin } : {};
  if (cookieHeader) headers.Cookie = cookieHeader;
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(WS_BASE, { headers });
    const messages = [];
    ws.on('message', (raw) => {
      try { messages.push(JSON.parse(raw.toString())); } catch {}
    });
    ws.on('open', () => resolve({ ws, messages }));
    ws.on('unexpected-response', (req, res) => { reject(new Error(`upgrade ${res.statusCode}`)); });
    ws.on('error', (e) => reject(e));
  });
}

function waitForMsg(messages, predicate, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    (function poll() {
      const found = messages.find(predicate);
      if (found) return resolve(found);
      if (Date.now() - start > timeoutMs) return reject(new Error('timeout waiting for message: ' + predicate.toString().slice(0, 80)));
      setTimeout(poll, 20);
    })();
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// CSRF-protected POST helpers
const CSRF_HEADER = { 'X-DUPS-Origin': 'same-site' };

async function claimAdmin(cookies = {}, extraHeaders = {}) {
  return httpReq({ method: 'POST', path: '/api/admin/claim', cookies, headers: { ...CSRF_HEADER, ...extraHeaders } });
}

async function getQR(cookies) {
  return httpReq({ method: 'GET', path: '/api/qr', cookies });
}

async function joinAsVoter(joinToken, cookies = {}, extraHeaders = {}) {
  return httpReq({ method: 'POST', path: '/api/join', body: { joinToken }, cookies, headers: { ...CSRF_HEADER, ...extraHeaders } });
}

function extractJoinToken(qrUrl) {
  const m = qrUrl.match(/\?j=([^&]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

// Helper: spin up a session with voting open and one voter ready.
async function setupVoting(photoCount) {
  const admin = await claimAdmin();
  const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
  await waitForMsg(am, m => m.type === 'hello');
  aws.send(JSON.stringify({ type: 'set-photo-count', photoCount }));
  await waitForMsg(am, m => m.type === 'photo-count-set');
  const qr = await getQR(admin.cookies);
  const join = extractJoinToken(qr.json.url);
  const voter = await joinAsVoter(join);
  const { ws: vws, messages: vm } = await openWS({ cookies: voter.cookies });
  await waitForMsg(vm, m => m.type === 'hello');
  return { aws, am, vws, vm, adminCookies: admin.cookies, voterCookies: voter.cookies, qrJti: qr.json.jti };
}

module.exports = {
  ROOT, PORT, BASE, WS_BASE, TMP_DATA,
  startServer, stopServer, restartServer,
  httpReq, openWS, waitForMsg, sleep,
  claimAdmin, getQR, joinAsVoter, extractJoinToken, setupVoting,
  CSRF_HEADER, WebSocket,
};
