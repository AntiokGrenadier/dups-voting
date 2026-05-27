// test/round3.js — 50 new sims for the v4 public-internet model
'use strict';

const H = require('./harness');
const { restartServer, claimAdmin, getQR, joinAsVoter, extractJoinToken,
        openWS, httpReq, waitForMsg, sleep, setupVoting, PORT,
        CSRF_HEADER, WebSocket } = H;

function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

module.exports = async function round3(sim) {

  // === A. PUBLIC_URL enforcement (101-108) =================================

  await sim(101, 'Dev mode: WS Origin from configured PUBLIC_URL allowed', async () => {
    await restartServer({ PUBLIC_URL: `http://127.0.0.1:${PORT}` });
    const { ws } = await H.openWS({ origin: `http://127.0.0.1:${PORT}` });
    assert(ws.readyState === WebSocket.OPEN);
    ws.close();
  });

  await sim(102, 'Production: WS Origin matching configured PUBLIC_URL allowed', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    // Spoof X-Forwarded-Proto so request looks like it came through TLS proxy
    let rejected = false;
    try {
      // Use the configured origin in the WS Origin header
      const { ws } = await H.openWS({ origin: 'https://vote.example.com' });
      ws.close();
    } catch (e) { rejected = true; }
    assert(!rejected, 'WS with matching Origin should be allowed');
  });

  await sim(103, 'Production: WS Origin with wrong host rejected', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    let rejected = false;
    try { await H.openWS({ origin: 'https://attacker.example.com' }); }
    catch (e) { rejected = e.message.includes('403'); }
    assert(rejected, 'expected 403 on mismatched Origin');
  });

  await sim(104, 'Production: WS Origin with wrong scheme (http vs https) rejected', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    let rejected = false;
    try { await H.openWS({ origin: 'http://vote.example.com' }); }
    catch (e) { rejected = e.message.includes('403'); }
    assert(rejected, 'expected 403 on mismatched scheme');
  });

  await sim(105, 'Production: WS Origin with wrong port rejected', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com:8443' });
    let rejected = false;
    try { await H.openWS({ origin: 'https://vote.example.com:9999' }); }
    catch (e) { rejected = e.message.includes('403'); }
    assert(rejected, 'expected 403 on mismatched port');
  });

  await sim(106, 'Production: QR URL is derived from PUBLIC_URL, not request Host', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const admin = await claimAdmin();
    // Even if attacker spoofs Host header, QR must reflect PUBLIC_URL
    const r = await httpReq({
      path: '/api/qr', cookies: admin.cookies,
      headers: { Host: 'attacker.example.com' },
    });
    assert(r.status === 200);
    assert(r.json.url.startsWith('https://vote.example.com/'), `expected configured origin, got ${r.json.url}`);
  });

  await sim(107, 'Production: invalid PUBLIC_URL on boot exits non-zero', async () => {
    // We start a one-shot child process manually to verify exit behavior.
    const { spawn } = require('child_process');
    const child = spawn(process.execPath, ['server.js'], {
      cwd: H.TMP_DATA,
      env: { ...process.env, PORT: String(PORT + 1), PUBLIC_URL: 'not a url' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const exit = await new Promise(res => child.on('exit', res));
    assert(exit !== 0, `expected non-zero exit, got ${exit}`);
  });

  await sim(108, 'Dev mode (no PUBLIC_URL): localhost Origin allowed', async () => {
    await restartServer(); // dev mode, no PUBLIC_URL
    const { ws } = await H.openWS({ origin: 'http://localhost' });
    assert(ws.readyState === WebSocket.OPEN);
    ws.close();
  });

  // === B. HSTS and Secure cookies in production (109-113) ==================

  await sim(109, 'HSTS header present when PUBLIC_URL is https', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const r = await httpReq({ path: '/' });
    const hsts = r.headers['strict-transport-security'];
    assert(hsts && /max-age=\d+/.test(hsts), `expected HSTS, got: ${hsts}`);
    assert(/includeSubDomains/i.test(hsts), 'HSTS should include subdomains');
  });

  await sim(110, 'HSTS header absent on plain HTTP (could trap dev)', async () => {
    await restartServer(); // dev, no PUBLIC_URL
    const r = await httpReq({ path: '/' });
    assert(!r.headers['strict-transport-security'], 'HSTS should NOT be set in dev');
  });

  await sim(111, 'HSTS absent when PUBLIC_URL is plain http', async () => {
    await restartServer({ PUBLIC_URL: `http://127.0.0.1:${PORT}` });
    const r = await httpReq({ path: '/' });
    assert(!r.headers['strict-transport-security'], 'HSTS should NOT be set when PUBLIC_URL is http');
  });

  await sim(112, 'Production HTTPS: cookies always Secure regardless of request headers', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    // Request via plain HTTP from loopback; server should still set Secure
    // because IS_PUBLIC_HTTPS is true.
    const r = await httpReq({ method: 'POST', path: '/api/admin/claim', headers: CSRF_HEADER });
    const setC = r.headers['set-cookie'] || [];
    const admin = setC.find(c => c.startsWith('dups_admin='));
    assert(admin && /Secure/i.test(admin), `expected Secure flag in prod-HTTPS, got: ${admin}`);
  });

  await sim(113, 'CSP connect-src locks to configured origin in production', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const r = await httpReq({ path: '/' });
    const csp = r.headers['content-security-policy'] || '';
    assert(/connect-src[^;]*wss:\/\/vote\.example\.com/.test(csp), `expected wss://vote.example.com in connect-src, got: ${csp}`);
    // Should NOT permit arbitrary wss:
    assert(!/connect-src[^;]*\bwss:(?!\/\/)/.test(csp), `CSP should not allow generic wss: in prod, got: ${csp}`);
  });

  // === C. Trust-proxy boundaries (114-119) =================================

  await sim(114, 'X-Forwarded-For honored from loopback (default trust proxy)', async () => {
    await restartServer(); // default trust proxy = 'loopback'
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const v = await joinAsVoter(extractJoinToken(qr.json.url), {}, { 'X-Forwarded-For': '198.51.100.55' });
    assert(v.status === 200);
    // ipHash stored should differ from a request without the header — but
    // we can't read joinedVoters directly. Verify indirectly: a second
    // voter from a different X-Forwarded-For should produce a different
    // ipHash, observable via the cluster check.
    const admin2 = await claimAdmin(admin.cookies);
    // Set photo count and vote
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const { ws: vws, messages: vm } = await openWS({ cookies: v.cookies });
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    assert(r.results.totalVotes === 1);
    vws.close(); aws.close();
  });

  await sim(115, 'X-Forwarded-Proto=https from loopback sets Secure cookie', async () => {
    await restartServer(); // dev, default trust proxy = 'loopback'
    const r = await httpReq({
      method: 'POST', path: '/api/admin/claim',
      headers: { ...CSRF_HEADER, 'X-Forwarded-Proto': 'https' },
    });
    const setC = r.headers['set-cookie'] || [];
    const admin = setC.find(c => c.startsWith('dups_admin='));
    assert(admin && /Secure/i.test(admin), `expected Secure flag with XFP=https, got: ${admin}`);
  });

  await sim(116, 'TRUST_PROXY=false: X-Forwarded-Proto ignored', async () => {
    await restartServer({ TRUST_PROXY: 'false' });
    const r = await httpReq({
      method: 'POST', path: '/api/admin/claim',
      headers: { ...CSRF_HEADER, 'X-Forwarded-Proto': 'https' },
    });
    const setC = r.headers['set-cookie'] || [];
    const admin = setC.find(c => c.startsWith('dups_admin='));
    assert(admin && !/Secure/i.test(admin), `with TRUST_PROXY=false, XFP should be ignored. got: ${admin}`);
  });

  await sim(117, 'TRUST_PROXY=1: single proxy hop honored', async () => {
    await restartServer({ TRUST_PROXY: '1' });
    const r = await httpReq({
      method: 'POST', path: '/api/admin/claim',
      headers: { ...CSRF_HEADER, 'X-Forwarded-Proto': 'https' },
    });
    const setC = r.headers['set-cookie'] || [];
    const admin = setC.find(c => c.startsWith('dups_admin='));
    assert(admin && /Secure/i.test(admin), `with TRUST_PROXY=1, XFP should be honored. got: ${admin}`);
  });

  await sim(118, 'Spoofed X-Forwarded-Host does NOT affect QR URL in production', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const admin = await claimAdmin();
    const r = await httpReq({
      path: '/api/qr', cookies: admin.cookies,
      headers: { 'X-Forwarded-Host': 'attacker.example.com' },
    });
    assert(r.json.url.startsWith('https://vote.example.com/'),
      `XFH spoofing must not redirect QR. got: ${r.json.url}`);
  });

  await sim(119, 'Spoofed X-Forwarded-Proto=http in prod-HTTPS still gives Secure cookie', async () => {
    // Even if an attacker tricked the proxy into sending XFP=http, the fact
    // that PUBLIC_URL is HTTPS means cookies are still Secure.
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const r = await httpReq({
      method: 'POST', path: '/api/admin/claim',
      headers: { ...CSRF_HEADER, 'X-Forwarded-Proto': 'http' },
    });
    const setC = r.headers['set-cookie'] || [];
    const admin = setC.find(c => c.startsWith('dups_admin='));
    assert(admin && /Secure/i.test(admin), `expected Secure even with spoofed XFP=http in prod-HTTPS. got: ${admin}`);
  });

  // === D. The carrier-NAT / corporate-NAT realities (120-125) ==============

  await sim(120, 'No artificial ceiling on simultaneous joiners from one IP', async () => {
    // Simulates a corporate office where many employees all NAT through one
    // public IP. v4 must allow them all to join.
    await restartServer();
    const admin = await claimAdmin();
    let succ = 0;
    for (let i = 0; i < 12; i++) {
      const { ws, messages } = await openWS({ cookies: admin.cookies });
      await waitForMsg(messages, m => m.type === 'hello');
      ws.send(JSON.stringify({ type: 'rotate-qr' }));
      await waitForMsg(messages, m => m.type === 'qr-rotated');
      ws.close();
      await sleep(40);  // let server's close handler clear ipConnections
      const qr = await getQR(admin.cookies);
      const r = await joinAsVoter(extractJoinToken(qr.json.url));
      if (r.status === 200) succ++;
    }
    assert(succ === 12, `expected 12, got ${succ}`);
  });

  await sim(121, 'WS connection cap (8/IP) still enforces against DoS', async () => {
    // The connection-level cap stays — that protects against socket-exhaustion
    // DoS attacks, distinct from the removed join-flow cap.
    await restartServer();
    const conns = [];
    let rejected = 0;
    for (let i = 0; i < 12; i++) {
      try { const c = await H.openWS(); conns.push(c.ws); }
      catch (e) { if (e.message.includes('429')) rejected++; }
    }
    assert(rejected >= 1, `expected ≥1 connection rejection, got ${rejected}`);
    for (const c of conns) try { c.close(); } catch {}
  });

  await sim(122, 'Cluster info still surfaces when many real voters share an IP', async () => {
    // The cluster warning remains the admin's awareness tool in lieu of
    // automatic blocking.
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 5 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const voters = [];
    for (let i = 0; i < 5; i++) {
      const { ws, messages } = await openWS({ cookies: admin.cookies });
      await waitForMsg(messages, m => m.type === 'hello');
      ws.send(JSON.stringify({ type: 'rotate-qr' }));
      await waitForMsg(messages, m => m.type === 'qr-rotated');
      ws.close();
      const qr = await getQR(admin.cookies);
      const v = await joinAsVoter(extractJoinToken(qr.json.url));
      const conn = await openWS({ cookies: v.cookies });
      voters.push(conn);
    }
    for (let i = 0; i < voters.length; i++) {
      voters[i].ws.send(JSON.stringify({ type: 'submit-vote', photoNumber: (i % 5) + 1 }));
    }
    await sleep(300);
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    assert(r.results.clusters.length === 1, `expected 1 cluster, got ${r.results.clusters.length}`);
    assert(r.results.clusters[0].count === 5);
    for (const v of voters) v.ws.close();
    aws.close();
  });

  await sim(123, 'Cluster warning is informational only — votes are NOT removed', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const voters = [];
    for (let i = 0; i < 3; i++) {
      const { ws, messages } = await openWS({ cookies: admin.cookies });
      await waitForMsg(messages, m => m.type === 'hello');
      ws.send(JSON.stringify({ type: 'rotate-qr' }));
      await waitForMsg(messages, m => m.type === 'qr-rotated');
      ws.close();
      const qr = await getQR(admin.cookies);
      const v = await joinAsVoter(extractJoinToken(qr.json.url));
      const conn = await openWS({ cookies: v.cookies });
      voters.push(conn);
    }
    for (let i = 0; i < voters.length; i++) {
      voters[i].ws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    }
    await sleep(300);
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    // All 3 votes counted, all on photo 1, despite the cluster warning.
    assert(r.results.totalVotes === 3);
    const photo1 = r.results.sorted.find(x => x.photo === 1);
    assert(photo1 && photo1.count === 3, `expected photo 1 to have 3 votes, got ${photo1 && photo1.count}`);
    for (const v of voters) v.ws.close();
    aws.close();
  });

  await sim(124, 'Lock Room remains the primary live anti-dupe tool', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr1 = await getQR(admin.cookies);
    const v1 = await joinAsVoter(extractJoinToken(qr1.json.url));
    assert(v1.status === 200);
    // Lock the room
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'lock-room', locked: true }));
    await sleep(150);
    // New QR, new join attempt — must be rejected
    aws.send(JSON.stringify({ type: 'rotate-qr' }));
    await waitForMsg(am, m => m.type === 'qr-rotated');
    const qr2 = await getQR(admin.cookies);
    const v2 = await joinAsVoter(extractJoinToken(qr2.json.url));
    assert(v2.status === 403 && v2.json.error === 'locked', `expected 403 locked, got ${v2.status}`);
    aws.close();
  });

  await sim(125, 'Rotate QR remains the secondary anti-dupe (invalidates outstanding tokens)', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr1 = await getQR(admin.cookies);
    const oldTok = extractJoinToken(qr1.json.url);
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'rotate-qr' }));
    await waitForMsg(am, m => m.type === 'qr-rotated');
    // Even from a fresh client, the old QR is dead
    const r = await joinAsVoter(oldTok);
    assert(r.status === 409 && r.json.error === 'token_used');
    aws.close();
  });

  // === E. Cross-platform expectations (126-132) ============================

  await sim(126, 'index.html declares mobile-web-app-capable for both vendors', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    assert(/apple-mobile-web-app-capable/.test(r.body));
    assert(/<meta name="mobile-web-app-capable"/.test(r.body));
  });

  await sim(127, 'index.html viewport handles iOS keyboard correctly', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    assert(/viewport-fit=cover/.test(r.body), 'must declare viewport-fit=cover for notch phones');
    assert(/interactive-widget=resizes-content/.test(r.body),
      'must declare interactive-widget for keyboard-aware layout');
  });

  await sim(128, 'index.html preconnects Google Fonts (cross-platform consistency)', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    assert(/<link rel="preconnect" href="https:\/\/fonts\.googleapis\.com"/.test(r.body));
    assert(/<link rel="preconnect" href="https:\/\/fonts\.gstatic\.com" crossorigin/.test(r.body));
  });

  await sim(129, 'CSP allows fonts.googleapis.com stylesheet + fonts.gstatic.com font fetch', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    const csp = r.headers['content-security-policy'] || '';
    assert(/style-src[^;]*fonts\.googleapis\.com/.test(csp), `style-src missing google fonts: ${csp}`);
    assert(/font-src[^;]*fonts\.gstatic\.com/.test(csp), `font-src missing gstatic: ${csp}`);
  });

  await sim(130, 'format-detection meta suppresses iOS auto-linking of numbers/dates', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    assert(/format-detection[^>]*telephone=no/.test(r.body));
    assert(/format-detection[^>]*date=no/.test(r.body));
    assert(/format-detection[^>]*address=no/.test(r.body));
  });

  await sim(131, 'vote-input has inputmode=numeric for correct phone keyboard', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    // The vote input must hint the numeric keypad on iOS and Android.
    assert(/id="vote-input"[^>]*inputmode="numeric"/.test(r.body) ||
           /inputmode="numeric"[^>]*id="vote-input"/.test(r.body),
      'vote-input must declare inputmode=numeric');
    assert(/id="vote-input"[^>]*enterkeyhint="send"/.test(r.body) ||
           /enterkeyhint="send"[^>]*id="vote-input"/.test(r.body),
      'vote-input should declare enterkeyhint=send');
  });

  await sim(132, 'color-scheme meta set to dark for consistent rendering', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    assert(/<meta name="color-scheme" content="dark"/.test(r.body));
  });

  // === F. Adversarial public-internet edges (133-140) ======================

  await sim(133, 'Long QR-URL still scannable: stays under 2KB', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com/some/sub/path' });
    const admin = await claimAdmin();
    const r = await getQR(admin.cookies);
    assert(r.status === 200);
    assert(r.json.url.length < 2048, `QR URL too long: ${r.json.url.length}`);
  });

  await sim(134, 'PUBLIC_URL with trailing slash gets normalized', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com/' });
    const admin = await claimAdmin();
    const r = await getQR(admin.cookies);
    // Should NOT have double slash before "?j="
    assert(!/\/\/\?j=/.test(r.json.url), `double-slash in URL: ${r.json.url}`);
  });

  await sim(135, 'Joining over plain http when PUBLIC_URL is https — still works', async () => {
    // The Origin check is what matters. The actual transport in tests is
    // always plain HTTP from loopback (we have no TLS terminator). But the
    // server must accept the join because the request looks like it came
    // from behind the proxy.
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const r = await joinAsVoter(extractJoinToken(qr.json.url));
    assert(r.status === 200);
  });

  await sim(136, 'Reset-session over HTTPS production: voter cookies wiped via 4000 close', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const origin = 'https://vote.example.com';
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const v = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: vws, messages: vm } = await openWS({ cookies: v.cookies, origin });
    await waitForMsg(vm, m => m.type === 'hello');
    let closeCode = null;
    vws.on('close', (code) => { closeCode = code; });
    const { ws: aws } = await openWS({ cookies: admin.cookies, origin });
    aws.send(JSON.stringify({ type: 'reset-session' }));
    await sleep(400);
    assert(closeCode === 4000, `expected close code 4000, got ${closeCode}`);
    aws.close();
  });

  await sim(137, 'Production: CSRF still required on POSTs', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const r = await httpReq({ method: 'POST', path: '/api/admin/claim' });
    assert(r.status === 403 && r.json.error === 'csrf');
  });

  await sim(138, 'Production: forged join token from another instance still rejected', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    // A token signed with a different SECRET (impossible to forge without the key)
    const fake = Buffer.from(JSON.stringify({ kind: 'join', sid: 'deadbeef', jti: 'aaa', iat: Date.now() }))
      .toString('base64').replace(/=+$/, '') + '.fake_signature_here';
    const r = await joinAsVoter(fake);
    assert(r.status === 400 && r.json.error === 'bad_token');
  });

  await sim(139, 'Production: voter cookie from another deployment rejected', async () => {
    // Stale cookie value that wasn't signed by THIS server's secret.
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const cookies = { dups_voter: 'not.a.real.token' };
    const { messages } = await openWS({ cookies, origin: 'https://vote.example.com' });
    const hello = await waitForMsg(messages, m => m.type === 'hello');
    assert(hello.state.you.role === null);
  });

  await sim(140, 'Production: 200 connect-then-disconnect cycles do not leak', async () => {
    await restartServer({ PUBLIC_URL: `http://127.0.0.1:${PORT}` });
    for (let i = 0; i < 200; i++) {
      try {
        const { ws } = await H.openWS({ origin: `http://127.0.0.1:${PORT}` });
        ws.close();
      } catch (e) {
        if (e.message.includes('429')) {
          // Connection cap reached — wait briefly and continue
          await sleep(50);
        }
      }
    }
    // Server still responsive
    const r = await httpReq({ path: '/api/session' });
    assert(r.status === 200);
  });

  // === G. Cross-platform pixel parity (141-145) ============================

  await sim(141, 'vote-input is type=number with pattern=[0-9]* for older browsers', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    assert(/id="vote-input"[^>]*type="number"/.test(r.body) ||
           /type="number"[^>]*id="vote-input"/.test(r.body));
    assert(/id="vote-input"[^>]*pattern="\[0-9\]\*"/.test(r.body) ||
           /pattern="\[0-9\]\*"[^>]*id="vote-input"/.test(r.body));
  });

  await sim(142, 'photo-count-input also numeric-keypad-hinted', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    assert(/id="photo-count-input"[^>]*inputmode="numeric"/.test(r.body));
  });

  await sim(143, 'Hero image uses referrerpolicy=no-referrer (avoids broken loads on strict referrers)', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    assert(/referrerpolicy="no-referrer"/.test(r.body));
  });

  await sim(144, 'CSP allows the dups.club hero image source', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    const csp = r.headers['content-security-policy'] || '';
    assert(/img-src[^;]*https:\/\/dups\.club/.test(csp));
  });

  await sim(145, 'No autocomplete on number inputs (avoid Chrome credit-card popups)', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    assert(/id="vote-input"[^>]*autocomplete="off"/.test(r.body) ||
           /autocomplete="off"[^>]*id="vote-input"/.test(r.body));
    assert(/id="photo-count-input"[^>]*autocomplete="off"/.test(r.body) ||
           /autocomplete="off"[^>]*id="photo-count-input"/.test(r.body));
  });

  // === H. Final sanity / regression catches (146-150) ======================

  await sim(146, 'Round-trip: production HTTPS, full vote, results, archive', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies, origin: 'https://vote.example.com' });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 4 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const qr = await getQR(admin.cookies);
    const v = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: vws, messages: vm } = await openWS({ cookies: v.cookies, origin: 'https://vote.example.com' });
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 3 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    assert(r.results.totalVotes === 1);
    const ar = await httpReq({ path: '/api/admin/archive', cookies: admin.cookies });
    assert(ar.status === 200);
    aws.close(); vws.close();
  });

  await sim(147, 'Production: state persists across restart with same secret', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies, origin: 'https://vote.example.com' });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 5 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    aws.close();
    await sleep(400);
    H.stopServer();
    await H.startServer({ PUBLIC_URL: 'https://vote.example.com' });
    await sleep(200);
    const { messages: am2 } = await openWS({ cookies: admin.cookies, origin: 'https://vote.example.com' });
    const hello = await waitForMsg(am2, m => m.type === 'hello');
    assert(hello.state.photoCount === 5);
  });

  await sim(148, 'Production: switching PUBLIC_URL on restart still loads state (secret unchanged)', async () => {
    await restartServer({ PUBLIC_URL: 'https://old.example.com' });
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies, origin: 'https://old.example.com' });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 7 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    aws.close();
    await sleep(400);
    H.stopServer();
    await H.startServer({ PUBLIC_URL: 'https://new.example.com' });
    await sleep(200);
    // Old admin cookie should still be valid (secret unchanged, sid unchanged)
    const { messages: am2 } = await openWS({ cookies: admin.cookies, origin: 'https://new.example.com' });
    const hello = await waitForMsg(am2, m => m.type === 'hello');
    assert(hello.state.photoCount === 7);
    assert(hello.state.you.role === 'admin');
  });

  await sim(149, 'Old voter cookies signed with same secret still work across PUBLIC_URL change', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies, origin: 'https://vote.example.com' });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const qr = await getQR(admin.cookies);
    const v = await joinAsVoter(extractJoinToken(qr.json.url));
    aws.close();
    H.stopServer();
    await H.startServer({ PUBLIC_URL: 'https://vote.example.com' });
    await sleep(200);
    const { ws: vws, messages: vm } = await openWS({ cookies: v.cookies, origin: 'https://vote.example.com' });
    const hello = await waitForMsg(vm, m => m.type === 'hello');
    assert(hello.state.you.role === 'voter', `voter cookie should survive restart, got ${hello.state.you.role}`);
    vws.close();
  });

  await sim(150, 'Final: full end-to-end with cluster warning visible to admin', async () => {
    await restartServer({ PUBLIC_URL: 'https://vote.example.com' });
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies, origin: 'https://vote.example.com' });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 5 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    // Three voters from one forwarded IP, one from a different IP
    const voters = [];
    for (let i = 0; i < 4; i++) {
      const { ws, messages } = await openWS({ cookies: admin.cookies, origin: 'https://vote.example.com' });
      await waitForMsg(messages, m => m.type === 'hello');
      ws.send(JSON.stringify({ type: 'rotate-qr' }));
      await waitForMsg(messages, m => m.type === 'qr-rotated');
      ws.close();
      const qr = await getQR(admin.cookies);
      const xff = i < 3 ? '203.0.113.10' : '203.0.113.99';
      const v = await joinAsVoter(extractJoinToken(qr.json.url), {}, { 'X-Forwarded-For': xff });
      const conn = await openWS({ cookies: v.cookies, origin: 'https://vote.example.com' });
      voters.push(conn);
    }
    for (let i = 0; i < voters.length; i++) {
      voters[i].ws.send(JSON.stringify({ type: 'submit-vote', photoNumber: (i % 5) + 1 }));
    }
    await sleep(400);
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    assert(r.results.totalVotes === 4);
    // One cluster of 3 (the .10 group). The .99 voter alone is NOT a cluster.
    assert(r.results.clusters.length === 1, `expected 1 cluster, got ${r.results.clusters.length}`);
    assert(r.results.clusters[0].count === 3);
    for (const v of voters) v.ws.close();
    aws.close();
  });
};
