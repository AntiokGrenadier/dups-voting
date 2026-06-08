// public/app.js — DUPS Photo Contest (hardened v3)
//
// v3 changes:
// - All POSTs include X-DUPS-Origin: same-site (CSRF defense)
// - On 'reset' from server: clear all in-memory state, scrub URL, request
//   server-side cookie clear, and route back to splash
// - On 'qr-rotated': refresh the QR via /api/qr
// - On result render: surface IP-cluster warnings to admin
// - Cleaner reconnection — backoff resets on successful 'hello'

'use strict';

(function () {
  const $ = s => document.querySelector(s);
  const screens = Array.from(document.querySelectorAll('.screen'));
  function show(id) { screens.forEach(s => s.classList.toggle('active', s.id === id)); }

  // CSRF: every POST gets this header. Browser cross-origin JS cannot.
  const CSRF_HEADERS = { 'X-DUPS-Origin': 'same-site' };

  const state = {
    sessionId: null,
    adminTaken: false,
    photoCount: null,
    votingOpen: false,
    votingClosed: false,
    locked: false,
    voteCount: 0,
    activeVoterCount: 0,
    joinedVoterCount: 0,
    role: null,
    myVote: null,
    results: null,
  };

  function resetLocalState() {
    state.sessionId = null;
    state.role = null;
    state.myVote = null;
    state.photoCount = null;
    state.votingOpen = false;
    state.votingClosed = false;
    state.results = null;
    const vi = $('#vote-input'); if (vi) vi.value = '';
    const pi = $('#photo-count-input'); if (pi) pi.value = '';
    const pc = $('#photo-count-confirm'); if (pc) pc.classList.add('hidden');
    const qi = $('#qr-image'); if (qi) qi.src = '';
    const ar = $('#role-admin'); if (ar) ar.checked = false;
    const vr = $('#role-voter'); if (vr) vr.checked = false;
  }

  // -----------------------------------------------------------------------
  // Step 0: handle ?j=<joinToken> in URL on first paint
  // -----------------------------------------------------------------------
  async function handleJoinTokenFromURL() {
    const u = new URL(location.href);
    const j = u.searchParams.get('j');
    if (!j) return;
    // Strip token from URL immediately — no leak via screenshots, bookmarks, etc.
    u.searchParams.delete('j');
    history.replaceState(null, '', u.toString());
    try {
      const r = await fetch('/api/join', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS },
        credentials: 'same-origin',
        body: JSON.stringify({ joinToken: j }),
      });
      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        showError('Could not join', mapJoinError(err));
        return;
      }
      const voterRadio = $('#role-voter');
      if (voterRadio) voterRadio.checked = true;
      $('#role-continue').disabled = false;
    } catch (e) {
      showError('Network error', 'Could not reach the server. Check your Wi-Fi connection and try again.');
    }
  }

  function mapJoinError(err) {
    const code = err && err.error;
    switch (code) {
      case 'stale_session': return 'This QR code is from a previous session. Please ask the Administrator for a new one.';
      case 'locked':        return 'The Administrator has locked the room. No new voters can join.';
      case 'bad_token':     return 'This QR code is invalid or has expired.';
      case 'token_used':    return (err.message || 'This QR code has already been used. Ask the Administrator for a fresh one.');
      case 'csrf':          return 'Security check failed. Please reload and try again.';
      default:              return 'The join request was rejected.';
    }
  }

  // -----------------------------------------------------------------------
  // Splash / role pick
  // -----------------------------------------------------------------------
  const adminRadio  = $('#role-admin');
  const voterRadio  = $('#role-voter');
  const continueBtn = $('#role-continue');
  const adminStatus = $('#admin-status');
  const voterStatus = $('#voter-status');
  const roleError   = $('#role-error');

  [adminRadio, voterRadio].forEach(r => r.addEventListener('change', () => {
    continueBtn.disabled = !(adminRadio.checked || voterRadio.checked);
    roleError.textContent = '';
  }));

  continueBtn.addEventListener('click', async () => {
    continueBtn.disabled = true;
    if (adminRadio.checked) {
      try {
        const r = await fetch('/api/admin/claim', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS },
          credentials: 'same-origin',
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) {
          if (data.error === 'taken') {
            roleError.textContent = 'The Administrator role is already taken.';
            adminRadio.disabled = true;
            adminStatus.textContent = '(taken)';
          } else if (data.error === 'csrf') {
            roleError.textContent = 'Security check failed. Please reload.';
          } else {
            roleError.textContent = 'Could not claim Administrator role.';
          }
          continueBtn.disabled = false;
          return;
        }
        state.role = 'admin';
        reconnectWS();
      } catch (e) {
        roleError.textContent = 'Network error.';
        continueBtn.disabled = false;
      }
    } else if (voterRadio.checked) {
      state.role = 'voter';
      reconnectWS();
    }
  });

  // -----------------------------------------------------------------------
  // Admin: photo-count setup
  // -----------------------------------------------------------------------
  $('#photo-count-submit').addEventListener('click', () => {
    const raw = $('#photo-count-input').value;
    const v = parseInt(raw, 10);
    if (!Number.isInteger(v) || v < 1 || v > 500 || String(v) !== String(raw).trim()) {
      alert('Enter an integer between 1 and 500.');
      return;
    }
    $('#photo-count-display').textContent = v;
    $('#photo-count-confirm').classList.remove('hidden');
  });

  $('#photo-count-change').addEventListener('click', () => {
    $('#photo-count-confirm').classList.add('hidden');
    $('#photo-count-input').focus();
  });

  $('#photo-count-confirm-btn').addEventListener('click', () => {
    const v = parseInt($('#photo-count-input').value, 10);
    sendMsg({ type: 'set-photo-count', photoCount: v });
  });

  // Admin: voting controls
  $('#count-votes-btn').addEventListener('click', () => {
    if (confirm('Close voting and tally results now?')) {
      sendMsg({ type: 'close-voting' });
    }
  });

  $('#rotate-qr-btn').addEventListener('click', () => {
    if (confirm('Rotate to a new QR code? Existing voters keep voting, but anyone who hasn\'t joined yet must scan the new code.')) {
      sendMsg({ type: 'rotate-qr' });
    }
  });

  $('#lock-room-btn').addEventListener('click', () => {
    sendMsg({ type: 'lock-room', locked: !state.locked });
  });

  $('#new-session-btn').addEventListener('click', () => {
    if (confirm('Start a new session? This clears the current vote and archives it.')) {
      sendMsg({ type: 'reset-session' });
    }
  });

  $('#download-archive-btn').addEventListener('click', async () => {
    try {
      const r = await fetch('/api/admin/archive', { credentials: 'same-origin' });
      if (!r.ok) { alert('Could not load archive.'); return; }
      const data = await r.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `dups-archive-${new Date().toISOString().slice(0,10)}.json`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    } catch (e) { alert('Download failed.'); }
  });

  // -----------------------------------------------------------------------
  // Voter: vote submit
  // -----------------------------------------------------------------------
  $('#vote-submit').addEventListener('click', submitVote);
  $('#vote-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submitVote(); }
  });

  function submitVote() {
    const raw = $('#vote-input').value;
    const v = parseInt(raw, 10);
    if (!Number.isInteger(v) || v < 1 || v > state.photoCount || String(v) !== String(raw).trim()) {
      setVoteStatus(`Enter an integer between 1 and ${state.photoCount}.`, 'error');
      return;
    }
    sendMsg({ type: 'submit-vote', photoNumber: v });
  }

  function setVoteStatus(text, kind) {
    const el = $('#vote-status');
    el.textContent = text;
    el.className = `status-text ${kind || ''}`;
  }

  function showError(title, message) {
    $('#error-title').textContent = title;
    $('#error-message').textContent = message;
    show('screen-error');
  }
  $('#error-reload').addEventListener('click', () => location.reload());

  // -----------------------------------------------------------------------
  // QR fetch Original
  // -----------------------------------------------------------------------
   //  let qrLoadInFlight = false;
 // async function loadQR() {
   // if (qrLoadInFlight) return;
   // qrLoadInFlight = true;
   // try {
    //  const r = await fetch('/api/qr', { credentials: 'same-origin' });
   //   if (!r.ok) { $('#qr-url').textContent = 'Could not generate QR.'; return; }
   //   const data = await r.json();
    //  $('#qr-image').src = data.dataUrl;
    //  $('#qr-url').textContent = data.url;
    //} catch (e) {
    //  $('#qr-url').textContent = 'QR fetch failed.';
    //} finally {
     // qrLoadInFlight = false;
    //}
  //}

    //__________________________________________________________________
    // End of original QR fetch. New QR fetch below 
    //------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // QR fetch
    // -----------------------------------------------------------------------
    let qrLoadInFlight = false;
    async function loadQR() {
        if (qrLoadInFlight) return;
        qrLoadInFlight = true;
        try {
            const r = await fetch('/api/qr', { credentials: 'same-origin' });
            if (!r.ok) { $('#qr-url').textContent = 'Could not generate QR.'; return; }
            const data = await r.json();
            $('#qr-image').src = data.dataUrl;
            // Show full URL immediately while we fetch the short one
            $('#qr-url').textContent = data.url;
            // Try to shorten via TinyURL
            try {
                const tiny = await fetch(`https://tinyurl.com/api-create.php?url=${encodeURIComponent(data.url)}`);
                if (tiny.ok) {
                    const short = await tiny.text();
                    if (short.startsWith('https://tinyurl.com/')) {
                        $('#qr-url').textContent = short;
                    }
                }
            } catch { /* keep full URL if shortening fails */ }
        } catch (e) {
            $('#qr-url').textContent = 'QR fetch failed.';
        } finally {
            qrLoadInFlight = false;
        }
    }
    //---------------------------------------------------------------
    //end of new QR fetch implementation
    //__________________________________________________________________

    // -----------------------------------------------------------------------
  // Routing
  // -----------------------------------------------------------------------
  function route() {
    if (state.role === 'admin') {
      if (state.votingClosed) {
        renderResults(state.results);
        show('screen-admin-results');
        return;
      }
      if (state.votingOpen && state.photoCount) {
        $('#admin-photo-count').textContent = state.photoCount;
        $('#joined-count').textContent = state.joinedVoterCount;
        $('#voter-count').textContent = state.activeVoterCount;
        $('#vote-count').textContent = state.voteCount;
        $('#lock-room-btn').textContent = state.locked ? 'Unlock room' : 'Lock room';
        show('screen-admin-voting');
        if (!$('#qr-image').src) loadQR();
        return;
      }
      show('screen-admin-setup');
      return;
    }
    if (state.role === 'voter') {
      if (state.votingClosed) {
        $('#voter-final').textContent = state.myVote != null ? state.myVote : '— (no vote cast)';
        show('screen-voter-closed');
        return;
      }
      if (state.votingOpen && state.photoCount) {
        $('#voter-max').textContent = state.photoCount;
        $('#vote-input').max = state.photoCount;
        if (state.myVote != null && !$('#vote-input').value) {
          $('#vote-input').value = state.myVote;
          setVoteStatus(`Current vote: Photo #${state.myVote}. You can still change it.`, 'ok');
        }
        show('screen-voter-vote');
        return;
      }
      show('screen-voter-wait');
      return;
    }
    // No role
    adminRadio.disabled = state.adminTaken;
    adminStatus.textContent = state.adminTaken ? '(taken)' : '';
    voterStatus.textContent = state.locked ? '(room locked)' : '';
    if (state.adminTaken && adminRadio.checked) {
      adminRadio.checked = false;
      continueBtn.disabled = !voterRadio.checked;
    }
    show('screen-splash');
  }

  function renderResults(results) {
    if (!results) return;
    $('#results-total').textContent = results.totalVotes;
    const tbody = $('#results-body');
    tbody.innerHTML = '';
    // Max vote count for proportional bar widths
    const maxCount = results.sorted.reduce((m, r) => Math.max(m, r.count), 0) || 1;
    results.sorted.forEach((row, i) => {
      const tr = document.createElement('tr');
      if (i === 0 && row.count > 0) tr.classList.add('first-place');

      const tdRank = document.createElement('td');
      tdRank.className = 'col-rank';
      // Two-digit padded rank (01, 02, …) for editorial typography
      tdRank.textContent = String(i + 1).padStart(2, '0');

      const tdPhoto = document.createElement('td');
      tdPhoto.className = 'col-photo';
      tdPhoto.textContent = `Photo No. ${row.photo}`;

      const tdCount = document.createElement('td');
      tdCount.className = 'col-votes';
      tdCount.textContent = String(row.count);

      const tdBar = document.createElement('td');
      tdBar.className = 'col-bar';
      const bar = document.createElement('span');
      bar.className = 'bar';
      const pct = Math.round((row.count / maxCount) * 100);
      bar.style.setProperty('--w', `${pct}%`);
      tdBar.appendChild(bar);

      tr.appendChild(tdRank);
      tr.appendChild(tdPhoto);
      tr.appendChild(tdCount);
      tr.appendChild(tdBar);
      tbody.appendChild(tr);
    });
    // Cluster warning — informational only. Carrier-grade NAT, corporate
    // offices, schools, and home Wi-Fi all routinely share an IP across
    // many legitimate users. Surface the pattern; let the admin judge.
    const cw = $('#cluster-warning');
    const ct = $('#cluster-warning-text');
    if (results.clusters && results.clusters.length > 0) {
      const total = results.clusters.reduce((s, c) => s + c.count, 0);
      ct.textContent = `${results.clusters.length} network${results.clusters.length === 1 ? '' : 's'} produced multiple votes (${total} votes total). This is often legitimate — mobile carriers, offices, and households commonly route many people through one address — but worth a glance.`;
      cw.classList.remove('hidden');
    } else {
      cw.classList.add('hidden');
    }
  }

  // -----------------------------------------------------------------------
  // WebSocket
  // -----------------------------------------------------------------------
  let ws = null;
  let backoffMs = 500;
  let manualClose = false;

  function reconnectWS() {
    if (ws) {
      manualClose = true;
      try { ws.close(); } catch {}
      ws = null;
      manualClose = false;
    }
    connectWS();
  }

  function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    try {
      ws = new WebSocket(`${proto}://${location.host}/`);
    } catch (e) {
      scheduleReconnect();
      return;
    }
    ws.addEventListener('open', () => { /* backoff reset happens on hello */ });
    ws.addEventListener('message', (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      handleServerMessage(msg);
    });
    ws.addEventListener('close', (ev) => {
      if (manualClose) return;
// Fix
        if (ev.code === 4000) {
            // Session reset from server. Wipe everything and reload.
            resetLocalState();
            location.reload();
        }

        scheduleReconnect();
    });
    ws.addEventListener('error', () => { /* close follows */ });
  }

  function scheduleReconnect() {
    setTimeout(connectWS, backoffMs);
    backoffMs = Math.min(8000, backoffMs * 2);
  }

  function sendMsg(obj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify(obj));
  }

  function applyServerState(s) {
    state.sessionId        = s.sessionId;
    state.adminTaken       = !!s.adminTaken;
    state.photoCount       = s.photoCount;
    state.votingOpen       = !!s.votingOpen;
    state.votingClosed     = !!s.votingClosed;
    state.locked           = !!s.locked;
    state.voteCount        = s.voteCount | 0;
    state.activeVoterCount = s.activeVoterCount | 0;
    state.joinedVoterCount = s.joinedVoterCount | 0;
    if (s.you) {
      state.role   = s.you.role || null;
      // Preserve myVote across role transitions only when we know the server's value
      state.myVote = (s.you.myVote != null) ? s.you.myVote :
                     (state.role === 'voter' ? state.myVote : null);
    }
    if (s.results) state.results = s.results;
    route();
  }

  function handleServerMessage(msg) {
    switch (msg.type) {
      case 'hello':
        backoffMs = 500; // healthy connection
        if (msg.state) applyServerState(msg.state);
        break;
      case 'state':
        if (msg.state) applyServerState(msg.state);
        break;
      case 'photo-count-set':
        state.photoCount = msg.photoCount;
        state.votingOpen = true;
        $('#photo-count-confirm').classList.add('hidden');
        route();
        break;
      case 'confirm-needed':
        if (msg.action === 'change-photo-count') {
          if (confirm(msg.message + '\n\nProceed?')) {
            const v = parseInt($('#photo-count-input').value, 10);
            sendMsg({ type: 'set-photo-count', photoCount: v, confirmReset: true });
          }
        }
        break;
      case 'vote-recorded':
        state.myVote = msg.photoNumber;
        setVoteStatus(`Vote recorded for Photo #${msg.photoNumber}. You may change it until voting closes.`, 'ok');
        $('#vote-input').value = msg.photoNumber;
        break;
      case 'voting-closed':
        state.votingClosed = true;
        state.votingOpen = false;
        route();
        break;
      case 'results':
        state.results = msg.results;
        renderResults(msg.results);
        route();
        break;
      case 'qr-rotated':
        // Force a fresh QR fetch.
        $('#qr-image').src = '';
        loadQR();
        break;
      case 'reset':
        // Server-initiated. The 4000-close handler does the cleanup.
        resetLocalState();
        break;
      case 'error':
        if (state.role === 'voter') setVoteStatus(msg.message, 'error');
        else alert(msg.message);
        break;
    }
  }

  // Reconnect when phone wakes
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && (!ws || ws.readyState !== WebSocket.OPEN)) {
      backoffMs = 500;
      connectWS();
    }
  });

  // Boot
  (async function boot() {
    show('screen-splash');
    await handleJoinTokenFromURL();
    connectWS();
  })();
})();
