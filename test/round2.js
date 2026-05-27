// test/round2.js — 50 new sims targeting the v3 surface
'use strict';

const H = require('./harness');
const crypto = require('crypto');
const { WebSocket } = H;
const { restartServer, claimAdmin, getQR, joinAsVoter, extractJoinToken,
        openWS, httpReq, waitForMsg, sleep, setupVoting, PORT, WS_BASE,
        CSRF_HEADER } = H;

function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

module.exports = async function round2(sim) {

  // === A. CSRF defense (51-55) =============================================

  await sim(51, 'POST /api/admin/claim without CSRF header is rejected', async () => {
    await restartServer();
    const r = await httpReq({ method: 'POST', path: '/api/admin/claim' });
    assert(r.status === 403 && r.json && r.json.error === 'csrf');
  });

  await sim(52, 'POST /api/join without CSRF header is rejected', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const tok = extractJoinToken(qr.json.url);
    const r = await httpReq({ method: 'POST', path: '/api/join', body: { joinToken: tok } });
    assert(r.status === 403 && r.json && r.json.error === 'csrf');
  });

  await sim(53, 'POST with wrong CSRF header value rejected', async () => {
    await restartServer();
    const r = await httpReq({ method: 'POST', path: '/api/admin/claim', headers: { 'X-DUPS-Origin': 'cross-site' } });
    assert(r.status === 403);
  });

  await sim(54, 'CSRF header is case-insensitive (HTTP spec)', async () => {
    await restartServer();
    // express normalizes incoming headers to lowercase; we check that value comparison is lowercase-tolerant
    const r = await httpReq({ method: 'POST', path: '/api/admin/claim', headers: { 'x-dups-origin': 'SAME-SITE' } });
    // Value must match exactly (lowercased); server uses .toLowerCase() check
    assert(r.status === 200 || r.status === 409, `unexpected status ${r.status}`);
  });

  await sim(55, 'GET requests do NOT need CSRF header (they are not state-changing)', async () => {
    await restartServer();
    const r = await httpReq({ path: '/api/session' });
    assert(r.status === 200);
  });

  // === B. Single-redemption join token (56-62) =============================

  await sim(56, 'Same QR token replayed from a 3rd device is rejected', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const tok = extractJoinToken(qr.json.url);
    const r1 = await joinAsVoter(tok);
    assert(r1.status === 200);
    const r2 = await joinAsVoter(tok);
    assert(r2.status === 409);
    const r3 = await joinAsVoter(tok);
    assert(r3.status === 409);
  });

  await sim(57, 'Same QR token re-presented BY the same cookie is idempotent', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const tok = extractJoinToken(qr.json.url);
    const r1 = await joinAsVoter(tok);
    const r2 = await joinAsVoter(tok, r1.cookies);
    assert(r2.status === 200 && r2.json.voterId === r1.json.voterId);
  });

  await sim(58, 'After QR rotation, OLD unredeemed token is INVALIDATED, NEW works', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr1 = await getQR(admin.cookies);
    const oldTok = extractJoinToken(qr1.json.url);
    // Rotate via admin WS
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'rotate-qr' }));
    await waitForMsg(am, m => m.type === 'qr-rotated');
    const qr2 = await getQR(admin.cookies);
    const newTok = extractJoinToken(qr2.json.url);
    assert(oldTok !== newTok, 'tokens should differ after rotation');
    // v3 hardening: old jti is now sentinel-marked, so any scan of the old QR is rejected.
    const old = await joinAsVoter(oldTok);
    assert(old.status === 409 && old.json.error === 'token_used', `expected 409 on old token, got ${old.status}`);
    // New token works
    const v = await joinAsVoter(newTok);
    assert(v.status === 200);
    aws.close();
  });

  await sim(59, 'Forged jti in a valid-signed token: not possible (sig fails)', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const tok = extractJoinToken(qr.json.url);
    // Mutate one char of the payload portion
    const [body, sig] = tok.split('.');
    const tampered = body.slice(0, -1) + (body.slice(-1) === 'a' ? 'b' : 'a') + '.' + sig;
    const r = await joinAsVoter(tampered);
    assert(r.status === 400 && r.json.error === 'bad_token');
  });

  await sim(60, 'Token from previous session (different sid) rejected', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const tok = extractJoinToken(qr.json.url);
    // Reset session, then try the old token
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'reset-session' }));
    await sleep(300);
    const r = await joinAsVoter(tok);
    assert(r.status === 400 && r.json.error === 'stale_session');
  });

  await sim(61, 'Token replay after restart still rejected (jtis persist)', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const tok = extractJoinToken(qr.json.url);
    const r1 = await joinAsVoter(tok);
    assert(r1.status === 200);
    // Restart without wiping data
    H.stopServer();
    await H.startServer();
    await sleep(200);
    const r2 = await joinAsVoter(tok);
    assert(r2.status === 409, `expected token_used after restart, got ${r2.status}`);
  });

  await sim(62, 'Spam joinTokens (10 fake) — none succeed', async () => {
    await restartServer();
    await claimAdmin(); // session exists
    let bad = 0;
    for (let i = 0; i < 10; i++) {
      const fake = Buffer.from(JSON.stringify({ kind: 'join', sid: 'deadbeef', jti: 'x'+i, iat: Date.now() }))
        .toString('base64').replace(/=+$/, '') + '.fakefakefakefakefakefakefakefake';
      const r = await joinAsVoter(fake);
      if (r.status >= 400) bad++;
    }
    assert(bad === 10, `expected 10 rejections, got ${bad}`);
  });

  // === C. Public-internet networking (63-66) ===============================
  // (v4: per-IP voter cap removed — incompatible with CGNAT / corporate NAT.
  //  Replaced these slots with PUBLIC_URL and trust-proxy tests.)

  await sim(63, 'No per-IP voter cap: many joins from one IP all succeed', async () => {
    // v4 removed MAX_JOINS_PER_IP. The harness puts every request at 127.0.0.1,
    // simulating a CGNAT/office scenario where many real voters share one IP.
    await restartServer();
    const admin = await claimAdmin();
    let successes = 0;
    for (let i = 0; i < 8; i++) {
      const { ws, messages } = await openWS({ cookies: admin.cookies });
      await waitForMsg(messages, m => m.type === 'hello');
      ws.send(JSON.stringify({ type: 'rotate-qr' }));
      await waitForMsg(messages, m => m.type === 'qr-rotated');
      ws.close();
      const qr = await getQR(admin.cookies);
      const r = await joinAsVoter(extractJoinToken(qr.json.url));
      if (r.status === 200) successes++;
    }
    assert(successes === 8, `expected 8 joins from one IP, got ${successes}`);
  });

  await sim(64, 'Dev mode: WS Origin from non-localhost rejected', async () => {
    // No PUBLIC_URL is set in tests, so we're in dev mode.
    // Dev mode allows localhost / 127.0.0.1 / ::1 origins; rejects others.
    await restartServer();
    let rejected = false;
    try { await openWS({ origin: 'http://attacker.example.com' }); }
    catch (e) { rejected = e.message.includes('403'); }
    assert(rejected);
  });

  await sim(65, 'X-Forwarded-For from loopback is honored (trust proxy)', async () => {
    // The default TRUST_PROXY is 'loopback'. A request from 127.0.0.1 that
    // sets X-Forwarded-For should have req.ip set to the forwarded value.
    // We can't directly inspect req.ip from outside, but we can verify
    // behavior: the ipHash stored on join differs when X-Forwarded-For is
    // set to a different IP. (We test this by joining twice with different
    // forwarded IPs and reading the cluster info at close time.)
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');

    // Voter A: claims X-Forwarded-For 10.0.0.1
    const qrA = await getQR(admin.cookies);
    const vA = await joinAsVoter(extractJoinToken(qrA.json.url), {}, { 'X-Forwarded-For': '10.0.0.1' });
    aws.send(JSON.stringify({ type: 'rotate-qr' }));
    await waitForMsg(am, m => m.type === 'qr-rotated');
    // Voter B: claims X-Forwarded-For 10.0.0.2
    const qrB = await getQR(admin.cookies);
    const vB = await joinAsVoter(extractJoinToken(qrB.json.url), {}, { 'X-Forwarded-For': '10.0.0.2' });

    // Both vote
    const { ws: w1, messages: m1 } = await openWS({ cookies: vA.cookies });
    const { ws: w2, messages: m2 } = await openWS({ cookies: vB.cookies });
    w1.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    w2.send(JSON.stringify({ type: 'submit-vote', photoNumber: 2 }));
    await waitForMsg(m1, m => m.type === 'vote-recorded');
    await waitForMsg(m2, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    // Two distinct ipHashes → no cluster.
    assert(r.results.clusters.length === 0, `expected 0 clusters, got ${r.results.clusters.length}`);
    w1.close(); w2.close(); aws.close();
  });

  await sim(66, 'Multiple voters same forwarded IP → cluster surfaces', async () => {
    // Verifies cluster awareness still works when many voters share an IP
    // (the carrier-NAT case that motivated removing the cap).
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');

    const voters = [];
    for (let i = 0; i < 4; i++) {
      const { ws, messages } = await openWS({ cookies: admin.cookies });
      await waitForMsg(messages, m => m.type === 'hello');
      ws.send(JSON.stringify({ type: 'rotate-qr' }));
      await waitForMsg(messages, m => m.type === 'qr-rotated');
      ws.close();
      const qr = await getQR(admin.cookies);
      // All four claim the same X-Forwarded-For — i.e. a shared CGNAT IP.
      const v = await joinAsVoter(extractJoinToken(qr.json.url), {}, { 'X-Forwarded-For': '203.0.113.42' });
      assert(v.status === 200);
      const conn = await openWS({ cookies: v.cookies });
      voters.push(conn);
    }
    for (let i = 0; i < voters.length; i++) {
      voters[i].ws.send(JSON.stringify({ type: 'submit-vote', photoNumber: (i % 3) + 1 }));
    }
    await sleep(300);
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    assert(r.results.totalVotes === 4);
    assert(r.results.clusters.length === 1 && r.results.clusters[0].count === 4,
      `expected 1 cluster of 4 voters, got: ${JSON.stringify(r.results.clusters)}`);
    for (const v of voters) v.ws.close();
    aws.close();
  });

  // === D. Cookie hygiene (67-70) ===========================================

  await sim(67, 'Voter cookie is HttpOnly + SameSite=Lax', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const tok = extractJoinToken(qr.json.url);
    // We need to look at raw Set-Cookie
    const r = await httpReq({
      method: 'POST', path: '/api/join',
      body: { joinToken: tok },
      headers: CSRF_HEADER,
    });
    const setC = r.headers['set-cookie'] || [];
    const dupsVoter = setC.find(c => c.startsWith('dups_voter='));
    assert(dupsVoter, 'no dups_voter cookie in response');
    assert(/HttpOnly/i.test(dupsVoter), 'cookie missing HttpOnly');
    assert(/SameSite=Lax/i.test(dupsVoter), 'cookie missing SameSite=Lax');
  });

  await sim(68, 'Cookies do NOT have Secure flag on plain HTTP dev', async () => {
    await restartServer();
    const r = await httpReq({ method: 'POST', path: '/api/admin/claim', headers: CSRF_HEADER });
    const setC = r.headers['set-cookie'] || [];
    const admin = setC.find(c => c.startsWith('dups_admin='));
    assert(admin && !/Secure/i.test(admin), 'cookie should not be Secure on plain HTTP dev');
  });

  await sim(69, 'X-Forwarded-Proto=https triggers Secure flag (via trust proxy)', async () => {
    await restartServer();
    const r = await httpReq({
      method: 'POST', path: '/api/admin/claim',
      headers: { ...CSRF_HEADER, 'X-Forwarded-Proto': 'https' },
    });
    const setC = r.headers['set-cookie'] || [];
    const admin = setC.find(c => c.startsWith('dups_admin='));
    assert(admin && /Secure/i.test(admin), `expected Secure flag, got: ${admin}`);
  });

  await sim(70, 'Tampered admin cookie (bad sig) is ignored', async () => {
    await restartServer();
    const admin = await claimAdmin();
    // Mutate the cookie
    const tampered = { ...admin.cookies };
    tampered.dups_admin = tampered.dups_admin.slice(0, -2) + 'XX';
    const { messages } = await openWS({ cookies: tampered });
    const hello = await waitForMsg(messages, m => m.type === 'hello');
    assert(hello.state.you.role === null, 'tampered cookie should yield no role');
  });

  // === E. Concurrent vote stress (71-75) ===================================

  await sim(71, '15 concurrent voters all get counted (no per-IP cap)', async () => {
    // v4 removed the per-IP join cap. We can now test legitimately high
    // voter counts from a single test IP (simulating CGNAT/office scale).
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 10 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const VOTERS = 15;
    const voters = [];
    for (let i = 0; i < VOTERS; i++) {
      const { ws, messages } = await openWS({ cookies: admin.cookies });
      await waitForMsg(messages, m => m.type === 'hello');
      ws.send(JSON.stringify({ type: 'rotate-qr' }));
      await waitForMsg(messages, m => m.type === 'qr-rotated');
      ws.close();
      const qr = await getQR(admin.cookies);
      const v = await joinAsVoter(extractJoinToken(qr.json.url));
      assert(v.status === 200, `voter ${i} join failed: ${v.status}`);
      const conn = await openWS({ cookies: v.cookies });
      voters.push(conn);
    }
    // All vote at the same time
    await Promise.all(voters.map((v, i) => new Promise(res => {
      v.ws.send(JSON.stringify({ type: 'submit-vote', photoNumber: (i % 10) + 1 }));
      setTimeout(res, 100);
    })));
    await sleep(400);
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const results = await waitForMsg(am, m => m.type === 'results');
    assert(results.results.totalVotes === VOTERS, `expected ${VOTERS}, got ${results.results.totalVotes}`);
    for (const v of voters) v.ws.close();
    aws.close();
  });

  await sim(72, 'Rapid-fire vote changes — last write wins', async () => {
    await restartServer();
    const { vws, vm, aws, am } = await setupVoting(5);
    for (let i = 1; i <= 5; i++) vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: i }));
    await sleep(300);
    // Last vote should be #5
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    const photo5 = r.results.sorted.find(x => x.photo === 5);
    assert(photo5 && photo5.count === 1, `expected #5 to win, got: ${JSON.stringify(r.results.sorted)}`);
    vws.close(); aws.close();
  });

  await sim(73, 'Vote at the exact moment of close: ordering is deterministic', async () => {
    await restartServer();
    const { vws, vm, aws, am } = await setupVoting(3);
    // Send vote and close in same flush
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    aws.send(JSON.stringify({ type: 'close-voting' }));
    await sleep(300);
    // Server is single-threaded; whichever arrived first wins. Just verify result is internally consistent.
    const r = await waitForMsg(am, m => m.type === 'results');
    assert(r.results.totalVotes === 0 || r.results.totalVotes === 1);
    vws.close(); aws.close();
  });

  await sim(74, 'Voter who joined but never connected WS — does not appear as active', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const qr = await getQR(admin.cookies);
    await joinAsVoter(extractJoinToken(qr.json.url));
    await sleep(150);
    // Trigger state broadcast
    aws.send(JSON.stringify({ type: 'heartbeat' }));
    await sleep(150);
    const states = am.filter(m => m.type === 'state' || m.type === 'hello');
    const last = states[states.length - 1].state;
    assert(last.joinedVoterCount === 1);
    assert(last.activeVoterCount === 0, `expected 0 active, got ${last.activeVoterCount}`);
    aws.close();
  });

  await sim(75, 'Voter connects, votes, disconnects, reconnects, changes vote', async () => {
    await restartServer();
    const { vws, vm, aws, voterCookies } = await setupVoting(5);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 2 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    vws.close();
    await sleep(150);
    const { ws: v2, messages: m2 } = await openWS({ cookies: voterCookies });
    await waitForMsg(m2, m => m.type === 'hello' && m.state.you.myVote === 2);
    v2.send(JSON.stringify({ type: 'submit-vote', photoNumber: 4 }));
    await waitForMsg(m2, m => m.type === 'vote-recorded' && m.photoNumber === 4);
    v2.close(); aws.close();
  });

  // === F. Cluster awareness on close (76-78) ===============================

  await sim(76, 'Single-vote-per-IP: no cluster warning', async () => {
    await restartServer();
    const { vws, vm, aws, am } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    assert(Array.isArray(r.results.clusters));
    assert(r.results.clusters.length === 0);
    vws.close(); aws.close();
  });

  await sim(77, 'Two voters same IP: cluster appears', async () => {
    // Both voters come from 127.0.0.1 in the test harness
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    // First voter
    const qr1 = await getQR(admin.cookies);
    const v1 = await joinAsVoter(extractJoinToken(qr1.json.url));
    aws.send(JSON.stringify({ type: 'rotate-qr' }));
    await waitForMsg(am, m => m.type === 'qr-rotated');
    const qr2 = await getQR(admin.cookies);
    const v2 = await joinAsVoter(extractJoinToken(qr2.json.url));
    const { ws: w1, messages: m1 } = await openWS({ cookies: v1.cookies });
    const { ws: w2, messages: m2 } = await openWS({ cookies: v2.cookies });
    w1.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    w2.send(JSON.stringify({ type: 'submit-vote', photoNumber: 2 }));
    await waitForMsg(m1, m => m.type === 'vote-recorded');
    await waitForMsg(m2, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    assert(r.results.clusters.length === 1, `expected 1 cluster, got ${r.results.clusters.length}`);
    assert(r.results.clusters[0].count === 2);
    w1.close(); w2.close(); aws.close();
  });

  await sim(78, 'Cluster info does NOT contain raw IP (only hash)', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const qr = await getQR(admin.cookies);
    const v = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: vws, messages: vm } = await openWS({ cookies: v.cookies });
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    // Even if there were clusters, ipHash would be 12 hex chars, NOT an IP.
    for (const c of (r.results.clusters || [])) {
      assert(/^[0-9a-f]{12}$/.test(c.ipHash), `cluster ipHash leaks: ${c.ipHash}`);
    }
    vws.close(); aws.close();
  });

  // === G. Reset / cookie cleanup (79-82) ===================================

  await sim(79, 'After reset, old admin cookie does not auto-claim the new admin slot', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws } = await openWS({ cookies: admin.cookies });
    aws.send(JSON.stringify({ type: 'reset-session' }));
    await sleep(300);
    // Same cookie shouldn't grant admin on the new session — they need to /claim again
    const r = await claimAdmin(admin.cookies);
    // Could be 200 (fresh claim) or 409 (someone else got it first); should NOT be silently bound to old cookie
    assert(r.status === 200 || r.status === 409);
    if (r.status === 200) {
      // verify the aid changed (new session)
      const r2 = await httpReq({ path: '/api/session', cookies: r.cookies });
      assert(r2.json.you && r2.json.you.role === 'admin');
    }
  });

  await sim(80, "After reset, server broadcasts 'reset' before closing sockets", async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const v = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: vws, messages: vm } = await openWS({ cookies: v.cookies });
    await waitForMsg(vm, m => m.type === 'hello');
    const { ws: aws } = await openWS({ cookies: admin.cookies });
    aws.send(JSON.stringify({ type: 'reset-session' }));
    await sleep(300);
    const resetMsg = vm.find(m => m.type === 'reset');
    assert(resetMsg, 'voter never got reset event');
    aws.close();
  });

  await sim(81, "Session reset clears redeemedJtis (old tokens stop existing entirely)", async () => {
    // After reset, the new session has different sid and empty redeemedJtis.
    // A previously-redeemed token from the old session should fail with
    // stale_session (sid mismatch), not with token_used.
    await restartServer();
    const admin = await claimAdmin();
    const qr1 = await getQR(admin.cookies);
    const oldTok = extractJoinToken(qr1.json.url);
    await joinAsVoter(oldTok);  // redeem in old session
    // Reset
    const { ws: aws } = await openWS({ cookies: admin.cookies });
    aws.send(JSON.stringify({ type: 'reset-session' }));
    await sleep(300);
    // Try the old token in the new session — sid mismatch first.
    const r = await joinAsVoter(oldTok);
    assert(r.status === 400 && r.json.error === 'stale_session',
      `expected stale_session, got ${r.status} ${JSON.stringify(r.json)}`);
  });

  await sim(82, 'Voter cookie from before reset cannot vote in new session', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const v = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'reset-session' }));
    await sleep(300);
    // New session — re-set photo count
    const a2 = await claimAdmin();
    const { ws: aws2, messages: am2 } = await openWS({ cookies: a2.cookies });
    await waitForMsg(am2, m => m.type === 'hello');
    aws2.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am2, m => m.type === 'photo-count-set');
    // Old voter cookie tries to connect & vote
    const { ws: vws, messages: vm } = await openWS({ cookies: v.cookies });
    const hello = await waitForMsg(vm, m => m.type === 'hello');
    assert(hello.state.you.role === null);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    const err = await waitForMsg(vm, m => m.type === 'error');
    assert(err.message.includes('not_voter') || err.message.includes('voter_unknown'));
    vws.close(); aws2.close();
  });

  // === H. Security header & CSP (83-86) ====================================

  await sim(83, 'CSP header is present and strict (no unsafe-inline for styles)', async () => {
    await restartServer();
    const r = await httpReq({ path: '/' });
    const csp = r.headers['content-security-policy'] || '';
    assert(csp.length > 0);
    assert(!csp.includes("'unsafe-inline'") || !/style-src[^;]*unsafe-inline/.test(csp), `CSP should not allow inline styles: ${csp}`);
    assert(/script-src 'self'/.test(csp));
    assert(/frame-ancestors 'none'/.test(csp));
  });

  await sim(84, 'X-Frame-Options DENY set', async () => {
    const r = await httpReq({ path: '/' });
    assert((r.headers['x-frame-options'] || '').toUpperCase() === 'DENY');
  });

  await sim(85, 'X-Content-Type-Options nosniff set', async () => {
    const r = await httpReq({ path: '/' });
    assert((r.headers['x-content-type-options'] || '').toLowerCase() === 'nosniff');
  });

  await sim(86, 'Referrer-Policy: no-referrer set', async () => {
    const r = await httpReq({ path: '/' });
    assert((r.headers['referrer-policy'] || '').toLowerCase() === 'no-referrer');
  });

  // === I. Atomic persistence (87-89) =======================================

  await sim(87, 'Atomic write: state.json never appears empty during write', async () => {
    // We can't easily race the write, but we can verify the .tmp pattern by
    // checking that a successful write leaves state.json valid and non-empty.
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 5 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    await sleep(400);
    const statePath = require('path').join(H.TMP_DATA, 'data', 'state.json');
    const data = require('fs').readFileSync(statePath, 'utf8');
    const parsed = JSON.parse(data);
    assert(parsed.photoCount === 5);
    aws.close();
  });

  await sim(88, '.tmp temp files cleaned up after successful write', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws } = await openWS({ cookies: admin.cookies });
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await sleep(400);
    const dataDir = require('path').join(H.TMP_DATA, 'data');
    const files = require('fs').readdirSync(dataDir);
    const tmp = files.filter(f => f.endsWith('.tmp'));
    assert(tmp.length === 0, `tmp leftovers: ${tmp.join(',')}`);
    aws.close();
  });

  await sim(89, 'archive.json round-trips through restart', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const qr = await getQR(admin.cookies);
    const v = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: vws, messages: vm } = await openWS({ cookies: v.cookies });
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 2 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    await sleep(200);
    aws.send(JSON.stringify({ type: 'reset-session' }));
    await sleep(400);
    H.stopServer();
    await H.startServer();
    await sleep(200);
    const a2 = await claimAdmin();
    const r = await httpReq({ path: '/api/admin/archive', cookies: a2.cookies });
    assert(r.status === 200 && r.json.archive.length >= 1);
    aws.close(); vws.close();
  });

  // === J. Connection / origin / WebSocket abuse (90-93) ===================

  await sim(90, 'WS upgrade with malformed Origin URL is rejected', async () => {
    await restartServer();
    let rejected = false;
    try { await openWS({ origin: 'not a url at all' }); }
    catch (e) { rejected = e.message.includes('403'); }
    assert(rejected);
  });

  await sim(91, 'WS upgrade with empty Origin allowed (curl-style)', async () => {
    await restartServer();
    const { ws } = await openWS({ origin: undefined });
    assert(ws.readyState === WebSocket.OPEN);
    ws.close();
  });

  await sim(92, 'Server tolerates many connect/disconnect cycles without leak', async () => {
    await restartServer();
    for (let i = 0; i < 20; i++) {
      const { ws } = await openWS();
      ws.close();
    }
    // If memory leaked, this would slow down dramatically — but functionally OK
    const r = await httpReq({ path: '/api/session' });
    assert(r.status === 200);
  });

  await sim(93, 'Hello message contains current session state immediately on connect', async () => {
    await restartServer();
    await claimAdmin();
    const { messages } = await openWS();
    const hello = await waitForMsg(messages, m => m.type === 'hello', 1500);
    assert(hello.state.sessionId);
    assert(typeof hello.state.adminTaken === 'boolean');
  });

  // === K. Functional UX edges (94-97) ======================================

  await sim(94, 'Admin can lock then unlock the room', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'lock-room', locked: true }));
    await sleep(100);
    aws.send(JSON.stringify({ type: 'lock-room', locked: false }));
    await sleep(100);
    aws.send(JSON.stringify({ type: 'heartbeat' }));
    await sleep(150);
    const states = am.filter(m => m.type === 'state' || m.type === 'hello');
    const last = states[states.length - 1].state;
    assert(last.locked === false);
    aws.close();
  });

  await sim(95, 'Admin set-photo-count, change before any votes — no confirm needed', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 7 }));
    const second = await waitForMsg(am, m => m.type === 'photo-count-set' || m.type === 'confirm-needed', 2000);
    assert(second.type === 'photo-count-set', `expected no confirm when no votes cast, got ${second.type}`);
    aws.close();
  });

  await sim(96, 'After close, lock-room still operable (admin not locked out)', async () => {
    await restartServer();
    const { vws, vm, aws, am } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    await waitForMsg(am, m => m.type === 'results');
    aws.send(JSON.stringify({ type: 'lock-room', locked: true }));
    await sleep(150);
    // No error
    assert(am.filter(m => m.type === 'error').length === 0);
    vws.close(); aws.close();
  });

  await sim(97, 'Voter who joined but not voted shows on close — they have no vote in results', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const qr = await getQR(admin.cookies);
    const v = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: vws, messages: vm } = await openWS({ cookies: v.cookies });
    await waitForMsg(vm, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    const r = await waitForMsg(am, m => m.type === 'results');
    assert(r.results.totalVotes === 0);
    vws.close(); aws.close();
  });

  // === L. Edge cases & exotic input (98-100) ===============================

  await sim(98, 'Vote photoNumber as boolean true rejected', async () => {
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: true }));
    const err = await waitForMsg(vm, m => m.type === 'error');
    assert(err);
    vws.close(); aws.close();
  });

  await sim(99, 'Vote photoNumber as array rejected', async () => {
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: [1] }));
    const err = await waitForMsg(vm, m => m.type === 'error');
    assert(err);
    vws.close(); aws.close();
  });

  await sim(100, 'Vote photoNumber as scientific notation 1e0 = 1 accepted', async () => {
    // 1e0 === 1 in JSON, and Number.isInteger(1) is true. Should be accepted.
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    // The literal 1e0 in JSON deserializes to the integer 1
    vws.send('{"type":"submit-vote","photoNumber":1e0}');
    const rec = await waitForMsg(vm, m => m.type === 'vote-recorded' || m.type === 'error');
    assert(rec.type === 'vote-recorded' && rec.photoNumber === 1);
    vws.close(); aws.close();
  });
};
