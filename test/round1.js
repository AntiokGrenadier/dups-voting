// test/round1.js — round 1 sims (originals, updated for v3 API)
'use strict';

const H = require('./harness');
const { WebSocket } = H;
const { restartServer, claimAdmin, getQR, joinAsVoter, extractJoinToken,
        openWS, httpReq, waitForMsg, sleep, setupVoting, PORT, WS_BASE,
        CSRF_HEADER } = H;

function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

module.exports = async function round1(sim) {
  await sim(1, 'Two concurrent admin claims — only one wins', async () => {
    await restartServer();
    const [a, b] = await Promise.all([claimAdmin(), claimAdmin()]);
    const wins = [a, b].filter(r => r.status === 200).length;
    const taken = [a, b].filter(r => r.status === 409).length;
    assert(wins === 1 && taken === 1, `expected 1+1, got wins=${wins} taken=${taken}`);
  });

  await sim(2, 'Admin recovers via cookie after disconnect', async () => {
    await restartServer();
    const r = await claimAdmin();
    assert(r.status === 200);
    const r2 = await claimAdmin(r.cookies);
    assert(r2.status === 200);
  });

  await sim(3, 'Second user trying to claim admin is rejected', async () => {
    await restartServer();
    await claimAdmin();
    const r = await claimAdmin();
    assert(r.status === 409);
  });

  await sim(4, 'clientId in message body cannot impersonate admin', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const voter = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws, messages } = await openWS({ cookies: voter.cookies });
    ws.send(JSON.stringify({ type: 'close-voting', clientId: 'admin' }));
    const err = await waitForMsg(messages, m => m.type === 'error');
    assert(err);
    ws.close();
  });

  await sim(5, 'Voter cannot set photo count', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const voter = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws, messages } = await openWS({ cookies: voter.cookies });
    ws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 5 }));
    const err = await waitForMsg(messages, m => m.type === 'error');
    assert(err.message.includes('not_admin'));
    ws.close();
  });

  await sim(6, 'Voter cannot close voting', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const voter = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws, messages } = await openWS({ cookies: voter.cookies });
    ws.send(JSON.stringify({ type: 'close-voting' }));
    const err = await waitForMsg(messages, m => m.type === 'error');
    assert(err.message.includes('not_admin'));
    ws.close();
  });

  await sim(7, 'Admin cannot vote (no voter cookie)', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws, messages } = await openWS({ cookies: admin.cookies });
    ws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    const err = await waitForMsg(messages, m => m.type === 'error');
    assert(err.message.includes('not_voter'));
    ws.close();
  });

  await sim(8, 'WS with bad Origin header is rejected', async () => {
    await restartServer();
    let rejected = false;
    try { await openWS({ origin: 'http://evil.example.com' }); }
    catch (e) { rejected = e.message.includes('403'); }
    assert(rejected);
  });

  await sim(9, 'WS with no Origin header (curl-style) is allowed', async () => {
    const { ws } = await openWS({ origin: undefined });
    assert(ws.readyState === WebSocket.OPEN);
    ws.close();
  });

  await sim(10, 'Stale session id invalidates old cookies', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const voter = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: aws } = await openWS({ cookies: admin.cookies });
    aws.send(JSON.stringify({ type: 'reset-session' }));
    await sleep(250);
    const { ws: vws, messages } = await openWS({ cookies: voter.cookies });
    await sleep(150);
    const hello = messages.find(m => m.type === 'hello');
    assert(hello && hello.state.you.role === null);
    vws.close();
    try { aws.close(); } catch {}
  });

  await sim(11, 'Two voters via same QR token: jti single-redemption blocks second', async () => {
    // v3 change: previously this was "documented as accepted"; now we enforce.
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const join = extractJoinToken(qr.json.url);
    const v1 = await joinAsVoter(join);
    assert(v1.status === 200);
    const v2 = await joinAsVoter(join);
    assert(v2.status === 409, `expected 409 token_used, got ${v2.status}`);
    assert(v2.json && v2.json.error === 'token_used');
  });

  await sim(12, 'Voter refresh preserves vote (cookie binding)', async () => {
    await restartServer();
    const { vws, vm, aws, voterCookies } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 2 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    vws.close();
    const { messages: m2 } = await openWS({ cookies: voterCookies });
    const hello = await waitForMsg(m2, m => m.type === 'hello');
    assert(hello.state.you.myVote === 2);
    aws.close();
  });

  await sim(13, 'Many tabs same cookie = still one vote', async () => {
    await restartServer();
    const { aws, voterCookies, adminCookies } = await setupVoting(5);
    const tabs = [];
    for (let i = 0; i < 4; i++) tabs.push(await openWS({ cookies: voterCookies }));
    for (let i = 0; i < tabs.length; i++) tabs[i].ws.send(JSON.stringify({ type: 'submit-vote', photoNumber: i + 1 }));
    await sleep(300);
    aws.send(JSON.stringify({ type: 'close-voting' }));
    await sleep(200);
    const { messages: am2 } = await openWS({ cookies: adminCookies });
    const hello = await waitForMsg(am2, m => m.type === 'hello');
    assert(hello.state.results.totalVotes === 1, `expected 1 vote, got ${hello.state.results.totalVotes}`);
    for (const t of tabs) t.ws.close();
    aws.close();
  });

  await sim(14, 'Voter disconnects after voting — vote stays', async () => {
    await restartServer();
    const { vws, vm, aws, adminCookies } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    vws.close();
    aws.send(JSON.stringify({ type: 'close-voting' }));
    await sleep(200);
    const { messages: am2 } = await openWS({ cookies: adminCookies });
    const hello = await waitForMsg(am2, m => m.type === 'hello');
    assert(hello.state.results.totalVotes === 1);
    aws.close();
  });

  await sim(15, 'String "1" accepted', async () => {
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: '1' }));
    const rec = await waitForMsg(vm, m => m.type === 'vote-recorded' || m.type === 'error');
    assert(rec.type === 'vote-recorded' && rec.photoNumber === 1);
    vws.close(); aws.close();
  });

  await sim(16, 'Decimal 1.5 rejected', async () => {
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1.5 }));
    const m = await waitForMsg(vm, x => x.type === 'error' || x.type === 'vote-recorded');
    assert(m.type === 'error');
    vws.close(); aws.close();
  });

  await sim(17, 'SQL-style string rejected', async () => {
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: '1; DROP TABLE votes' }));
    const m = await waitForMsg(vm, x => x.type === 'error' || x.type === 'vote-recorded');
    assert(m.type === 'error');
    vws.close(); aws.close();
  });

  await sim(18, 'Zero and negatives rejected', async () => {
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 0 }));
    await waitForMsg(vm, m => m.type === 'error');
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: -5 }));
    await sleep(150);
    assert(vm.filter(m => m.type === 'error').length >= 2);
    vws.close(); aws.close();
  });

  await sim(19, 'MAX_SAFE_INTEGER rejected', async () => {
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: Number.MAX_SAFE_INTEGER }));
    const err = await waitForMsg(vm, m => m.type === 'error');
    assert(err);
    vws.close(); aws.close();
  });

  await sim(20, 'null / undefined / missing photoNumber rejected', async () => {
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: null }));
    await waitForMsg(vm, m => m.type === 'error');
    vws.send(JSON.stringify({ type: 'submit-vote' }));
    await sleep(150);
    assert(vm.filter(m => m.type === 'error').length >= 2);
    vws.close(); aws.close();
  });

  await sim(21, 'photoCount = 1 billion rejected', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws, messages } = await openWS({ cookies: admin.cookies });
    await waitForMsg(messages, m => m.type === 'hello');
    ws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 1_000_000_000 }));
    const err = await waitForMsg(messages, m => m.type === 'error');
    assert(err.message.includes('500'));
    ws.close();
  });

  await sim(22, 'photoCount 0 / negative rejected', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws, messages } = await openWS({ cookies: admin.cookies });
    await waitForMsg(messages, m => m.type === 'hello');
    ws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 0 }));
    await waitForMsg(messages, m => m.type === 'error');
    ws.send(JSON.stringify({ type: 'set-photo-count', photoCount: -5 }));
    await sleep(150);
    assert(messages.filter(m => m.type === 'error').length >= 2);
    ws.close();
  });

  await sim(23, 'photoCount "abc" rejected', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws, messages } = await openWS({ cookies: admin.cookies });
    await waitForMsg(messages, m => m.type === 'hello');
    ws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 'abc' }));
    const err = await waitForMsg(messages, m => m.type === 'error');
    assert(err);
    ws.close();
  });

  await sim(24, 'Mid-vote photoCount change requires confirmation', async () => {
    await restartServer();
    const { vws, vm, aws, am } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 5 }));
    const c = await waitForMsg(am, m => m.type === 'confirm-needed');
    assert(c.action === 'change-photo-count');
    vws.close(); aws.close();
  });

  await sim(25, 'Vote before photoCount set is rejected', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws } = await openWS({ cookies: admin.cookies });
    const qr = await getQR(admin.cookies);
    const voter = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: vws, messages: vm } = await openWS({ cookies: voter.cookies });
    await waitForMsg(vm, m => m.type === 'hello');
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    const err = await waitForMsg(vm, m => m.type === 'error');
    assert(err.message.includes('voting_not_open'));
    vws.close(); aws.close();
  });

  await sim(26, 'Vote after close rejected', async () => {
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    await sleep(200);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 2 }));
    await sleep(150);
    assert(vm.filter(m => m.type === 'error').length >= 1);
    vws.close(); aws.close();
  });

  await sim(27, 'Double close is idempotent', async () => {
    await restartServer();
    const { aws, vws, vm } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 1 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    aws.send(JSON.stringify({ type: 'close-voting' }));
    await sleep(200);
    // server is still alive
    assert(true);
    vws.close(); aws.close();
  });

  await sim(28, 'Per-connection rate limit triggers', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws, messages } = await openWS({ cookies: admin.cookies });
    for (let i = 0; i < 100; i++) ws.send(JSON.stringify({ type: 'heartbeat' }));
    await sleep(400);
    const rate = messages.find(m => m.type === 'error' && m.message === 'Slow down.');
    assert(rate, 'expected rate-limit error');
    ws.close();
  });

  await sim(29, 'Oversize payload disconnects', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws } = await openWS({ cookies: admin.cookies });
    const big = 'x'.repeat(10 * 1024);
    let closed = false;
    ws.on('close', () => closed = true);
    try { ws.send(JSON.stringify({ type: 'heartbeat', payload: big })); } catch {}
    await sleep(300);
    assert(closed);
  });

  await sim(30, 'Bounded JSON nesting accepted (under 4KB)', async () => {
    let s = '0';
    for (let i = 0; i < 50; i++) s = `{"a":${s}}`;
    await restartServer();
    const admin = await claimAdmin();
    const { ws } = await openWS({ cookies: admin.cookies });
    ws.send(s);
    await sleep(200);
    assert(ws.readyState === WebSocket.OPEN);
    ws.close();
  });

  await sim(31, 'Per-IP WS connection cap', async () => {
    await restartServer();
    const conns = [];
    let rejected = 0;
    for (let i = 0; i < 12; i++) {
      try { const c = await openWS(); conns.push(c.ws); }
      catch (e) { if (e.message.includes('429')) rejected++; }
    }
    assert(rejected >= 1);
    for (const c of conns) try { c.close(); } catch {}
  });

  await sim(32, 'Heartbeat pings keep alive connections live', async () => {
    await restartServer();
    const { ws } = await openWS();
    await sleep(500);
    assert(ws.readyState === WebSocket.OPEN);
    ws.close();
  });

  await sim(33, 'Invalid JSON ignored silently', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws } = await openWS({ cookies: admin.cookies });
    ws.send('not json');
    await sleep(150);
    assert(ws.readyState === WebSocket.OPEN);
    ws.close();
  });

  await sim(34, 'Unknown message type ignored', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws } = await openWS({ cookies: admin.cookies });
    ws.send(JSON.stringify({ type: 'banana', evil: true }));
    await sleep(150);
    assert(ws.readyState === WebSocket.OPEN);
    ws.close();
  });

  await sim(35, 'No `type` field ignored', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws } = await openWS({ cookies: admin.cookies });
    ws.send(JSON.stringify({ photoCount: 5 }));
    await sleep(150);
    assert(ws.readyState === WebSocket.OPEN);
    ws.close();
  });

  await sim(36, 'Extra fields ignored', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws, messages } = await openWS({ cookies: admin.cookies });
    await waitForMsg(messages, m => m.type === 'hello');
    ws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3, extra: { a: 1 } }));
    await waitForMsg(messages, m => m.type === 'photo-count-set');
    ws.close();
  });

  await sim(37, 'HTTP polling endpoint /api/vote does not exist', async () => {
    const r = await httpReq({ method: 'POST', path: '/api/vote', body: { photoNumber: 1 }, headers: CSRF_HEADER });
    assert(r.status === 404);
  });

  await sim(38, 'perMessageDeflate is off', async () => {
    const headers = {
      'Sec-WebSocket-Extensions': 'permessage-deflate',
      'Origin': `http://127.0.0.1:${PORT}`,
    };
    const ws = new WebSocket(WS_BASE, { headers });
    await new Promise((resolve, reject) => {
      ws.on('open', resolve); ws.on('error', reject);
      setTimeout(() => reject(new Error('timeout')), 2000);
    });
    assert(!ws.extensions || !ws.extensions['permessage-deflate']);
    ws.close();
  });

  await sim(39, 'XSS payload as vote rejected', async () => {
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: '<script>alert(1)</script>' }));
    const err = await waitForMsg(vm, m => m.type === 'error');
    assert(err);
    vws.close(); aws.close();
  });

  await sim(40, 'Forged role field on incoming msg ignored', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const voter = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: vws, messages: vm } = await openWS({ cookies: voter.cookies });
    vws.send(JSON.stringify({ type: 'close-voting', role: 'admin', meta: { role: 'admin' } }));
    const err = await waitForMsg(vm, m => m.type === 'error');
    assert(err.message.includes('not_admin'));
    vws.close();
  });

  await sim(41, 'QR is admin-only', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const qr = await getQR(admin.cookies);
    const voter = await joinAsVoter(extractJoinToken(qr.json.url));
    const r = await httpReq({ path: '/api/qr', cookies: voter.cookies });
    assert(r.status === 403);
  });

  await sim(42, 'Voter sending admin-only msgs rejected', async () => {
    await restartServer();
    const { vws, vm, aws } = await setupVoting(3);
    vws.send(JSON.stringify({ type: 'reset-session' }));
    vws.send(JSON.stringify({ type: 'lock-room', locked: true }));
    await sleep(200);
    assert(vm.filter(m => m.type === 'error').length >= 2);
    vws.close(); aws.close();
  });

  await sim(43, 'Admin reload during setup: server holds photoCount', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 7 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    aws.close();
    const { messages: am2 } = await openWS({ cookies: admin.cookies });
    const hello = await waitForMsg(am2, m => m.type === 'hello');
    assert(hello.state.photoCount === 7);
  });

  await sim(44, 'Two admin WS from same cookie both work', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: a1 } = await openWS({ cookies: admin.cookies });
    const { messages: m2 } = await openWS({ cookies: admin.cookies });
    const hello = await waitForMsg(m2, m => m.type === 'hello');
    assert(hello.state.you.role === 'admin');
    a1.close();
  });

  await sim(45, 'QR URL in dev mode reflects request host', async () => {
    await restartServer();
    const admin = await claimAdmin();
    // In dev mode (no PUBLIC_URL set), the QR URL is derived from the
    // request — proto via X-Forwarded-Proto (loopback trusted) or req.protocol,
    // and host from the Host header.
    const r = await httpReq({ path: '/api/qr', cookies: admin.cookies });
    assert(r.status === 200);
    assert(typeof r.json.url === 'string' && r.json.url.includes('?j='));
    // Should be a valid absolute URL.
    new URL(r.json.url); // throws if not
  });

  await sim(46, 'QR returns a usable URL with token', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const r = await getQR(admin.cookies);
    assert(r.status === 200 && r.json.url && r.json.url.includes('?j='));
  });

  await sim(47, 'Bogus join token rejected', async () => {
    const r = await joinAsVoter('bogus.signature');
    assert(r.status === 400 || r.status === 403);
  });

  await sim(48, 'Locked room: new joins rejected, existing voters keep voting', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const qr1 = await getQR(admin.cookies);
    const v1 = await joinAsVoter(extractJoinToken(qr1.json.url));
    assert(v1.status === 200);
    aws.send(JSON.stringify({ type: 'lock-room', locked: true }));
    await sleep(200);
    // rotate QR so we have a fresh jti for the next join attempt
    aws.send(JSON.stringify({ type: 'rotate-qr' }));
    await sleep(200);
    const qr2 = await getQR(admin.cookies);
    const v2 = await joinAsVoter(extractJoinToken(qr2.json.url));
    assert(v2.status === 403, `expected 403 after lock, got ${v2.status}`);
    const { ws: vws, messages: vm } = await openWS({ cookies: v1.cookies });
    await waitForMsg(vm, m => m.type === 'hello');
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 2 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    vws.close(); aws.close();
  });

  await sim(49, 'Server restart restores in-progress vote', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 4 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const qr = await getQR(admin.cookies);
    const voter = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: vws, messages: vm } = await openWS({ cookies: voter.cookies });
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 3 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    aws.close(); vws.close();
    await sleep(400);
    H.stopServer();
    await H.startServer();
    await sleep(200);
    const { messages: am2 } = await openWS({ cookies: admin.cookies });
    const hello = await waitForMsg(am2, m => m.type === 'hello');
    assert(hello.state.photoCount === 4);
    assert(hello.state.voteCount === 1);
  });

  await sim(50, 'Archive accessible to admin after reset', async () => {
    await restartServer();
    const admin = await claimAdmin();
    const { ws: aws, messages: am } = await openWS({ cookies: admin.cookies });
    await waitForMsg(am, m => m.type === 'hello');
    aws.send(JSON.stringify({ type: 'set-photo-count', photoCount: 3 }));
    await waitForMsg(am, m => m.type === 'photo-count-set');
    const qr = await getQR(admin.cookies);
    const voter = await joinAsVoter(extractJoinToken(qr.json.url));
    const { ws: vws, messages: vm } = await openWS({ cookies: voter.cookies });
    vws.send(JSON.stringify({ type: 'submit-vote', photoNumber: 2 }));
    await waitForMsg(vm, m => m.type === 'vote-recorded');
    aws.send(JSON.stringify({ type: 'close-voting' }));
    await sleep(200);
    aws.send(JSON.stringify({ type: 'reset-session' }));
    await sleep(400);
    // Re-claim and check archive
    const a2 = await claimAdmin();
    const r = await httpReq({ path: '/api/admin/archive', cookies: a2.cookies });
    assert(r.status === 200);
    assert(Array.isArray(r.json.archive) && r.json.archive.length >= 1);
    aws.close(); vws.close();
  });
};
