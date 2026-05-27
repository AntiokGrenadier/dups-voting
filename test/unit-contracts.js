// test/unit-contracts.js
//
// Verifies the HTML/JS contract: every id and class that public/app.js
// references actually exists in public/index.html. Catches the entire class
// of "I renamed an ID and forgot to update the JS" bugs.
//
// Runs without npm install.

'use strict';

const fs = require('fs');
const path = require('path');

const HTML = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
const APP_JS = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  PASS  ${name}`); }
  catch (e) { failed++; console.log(`  FAIL  ${name}\n        ${e.message}`); }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || 'assert failed'); }

// =============================================================================
// 1. Every $('#foo') in app.js → there is id="foo" in index.html
// =============================================================================

console.log('\n[1] ID references resolve');

const idMatches = APP_JS.match(/\$\(['"]#([\w-]+)['"]\)/g) || [];
const idsReferenced = [...new Set(idMatches.map(m => m.match(/#([\w-]+)/)[1]))];

for (const id of idsReferenced) {
  test(`#${id} exists in index.html`, () => {
    const re = new RegExp(`id="${id}"`);
    assert(re.test(HTML), `no element with id="${id}"`);
  });
}

// =============================================================================
// 2. Every class the JS toggles → has at least one element with that class in HTML
// (or is dynamically added — those are OK; we check the IMPORTANT ones)
// =============================================================================

console.log('\n[2] Class references the JS depends on');

// Classes that MUST exist as HTML markup (not just dynamically added)
const requiredClasses = [
  'screen',
  'splash-hero',
  'splash-image',
  'splash-overlay',
  'splash-title',
  'splash-subtitle',
  'role-card',
  'role-prompt',
  'role-option',
  'page-header',
  'muted',
  'card',
  'qr-card',
  'big-label',
  'big-text',
  'btn',
  'primary',
  'danger',
  'ghost',
  'large',
  'row',
  'stats-row',
  'stat-label',
  'stat-value',
  'results-table',
  'status-text',
  'spinner',
];

for (const cls of requiredClasses) {
  test(`.${cls} present in index.html`, () => {
    // class can be alone, first, middle, or last in attribute
    const re = new RegExp(`class="[^"]*\\b${cls}\\b[^"]*"`);
    assert(re.test(HTML), `no element with class containing "${cls}"`);
  });
}

// =============================================================================
// 3. Every <section class="screen" id="screen-X"> the routing references exists
// =============================================================================

console.log('\n[3] All routed screens exist');

// Routing references in app.js
const screenRefs = [...new Set(
  (APP_JS.match(/show\(['"](screen-[\w-]+)['"]\)/g) || [])
    .map(m => m.match(/'(screen-[\w-]+)'/)[1])
)];

for (const screenId of screenRefs) {
  test(`<section id="${screenId}"> exists`, () => {
    const re = new RegExp(`<section[^>]*id="${screenId}"[^>]*class="[^"]*screen[^"]*"|<section[^>]*class="[^"]*screen[^"]*"[^>]*id="${screenId}"`);
    assert(re.test(HTML), `screen ${screenId} not declared as <section class="screen">`);
  });
}

// =============================================================================
// 4. Cross-platform meta-tag promises from the design prompt
// =============================================================================

console.log('\n[4] Cross-platform HTML hooks');

test('viewport-fit=cover present', () => {
  assert(/viewport-fit=cover/.test(HTML));
});

test('interactive-widget=resizes-content present', () => {
  assert(/interactive-widget=resizes-content/.test(HTML));
});

test('apple-mobile-web-app-capable present', () => {
  assert(/<meta name="apple-mobile-web-app-capable"/.test(HTML));
});

test('mobile-web-app-capable (Android) present', () => {
  assert(/<meta name="mobile-web-app-capable"/.test(HTML));
});

test('color-scheme set to dark', () => {
  assert(/<meta name="color-scheme" content="dark"/.test(HTML));
});

test('format-detection covers telephone/date/address/email', () => {
  assert(/telephone=no/.test(HTML));
  assert(/date=no/.test(HTML));
  assert(/address=no/.test(HTML));
  assert(/email=no/.test(HTML));
});

test('Google Fonts preconnect both hosts', () => {
  assert(/preconnect[^>]+fonts\.googleapis\.com/.test(HTML));
  assert(/preconnect[^>]+fonts\.gstatic\.com[^>]+crossorigin/.test(HTML));
});

test('vote-input has inputmode=numeric + pattern=[0-9]*', () => {
  // Find the <input id="vote-input"> tag and check attrs (may be multi-line)
  const re = /<input[^>]*id="vote-input"[^>]*>/s;
  const m = HTML.match(re);
  assert(m, 'vote-input tag not found');
  assert(/inputmode="numeric"/.test(m[0]), 'vote-input missing inputmode=numeric');
  assert(/pattern="\[0-9\]\*"/.test(m[0]), 'vote-input missing pattern=[0-9]*');
  assert(/enterkeyhint="send"/.test(m[0]), 'vote-input missing enterkeyhint=send');
  assert(/autocomplete="off"/.test(m[0]), 'vote-input missing autocomplete=off');
});

test('photo-count-input has inputmode=numeric + pattern + min/max', () => {
  const re = /<input[^>]*id="photo-count-input"[^>]*>/s;
  const m = HTML.match(re);
  assert(m, 'photo-count-input tag not found');
  assert(/inputmode="numeric"/.test(m[0]));
  assert(/pattern="\[0-9\]\*"/.test(m[0]));
  assert(/min="1"/.test(m[0]));
  assert(/max="500"/.test(m[0]));
});

test('Hero images use referrerpolicy=no-referrer', () => {
  // Could be one or two; ensure all .splash-image tags have it
  const heroes = HTML.match(/<img[^>]*class="splash-image"[^>]*>/gs) || [];
  assert(heroes.length >= 2, `expected ≥2 hero images, got ${heroes.length}`);
  for (const h of heroes) {
    assert(/referrerpolicy="no-referrer"/.test(h), `hero img missing referrerpolicy: ${h.slice(0, 100)}`);
  }
});

// =============================================================================
// 5. CSRF: every fetch() with POST has CSRF header
// =============================================================================

console.log('\n[5] Every POST in app.js carries CSRF header');

// Find all fetch() calls with method: 'POST'
const fetches = APP_JS.match(/fetch\([^)]*method:\s*['"]POST['"][\s\S]*?\}\)/g) || [];
test(`At least one POST fetch exists in app.js (${fetches.length})`, () => {
  assert(fetches.length >= 2, 'expected at least 2 POSTs (claim, join)');
});

for (let i = 0; i < fetches.length; i++) {
  test(`POST #${i+1} includes CSRF_HEADERS`, () => {
    assert(/CSRF_HEADERS/.test(fetches[i]), `POST does not spread CSRF_HEADERS:\n${fetches[i].slice(0, 200)}`);
  });
}

test('CSRF_HEADERS is defined as X-DUPS-Origin: same-site', () => {
  assert(/'X-DUPS-Origin':\s*'same-site'/.test(APP_JS), 'CSRF_HEADERS constant misdefined');
});

// =============================================================================
// 6. WebSocket build uses protocol-relative pattern
// =============================================================================

console.log('\n[6] WebSocket connection URL');

test('WS URL adapts to https/http page', () => {
  // Pattern: const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  assert(/location\.protocol\s*===\s*['"]https:['"]/.test(APP_JS), 'WS proto adaptation missing');
  assert(/new WebSocket\(/.test(APP_JS), 'no WebSocket constructor call');
});

// =============================================================================
// 7. Reset / disconnect handling
// =============================================================================

console.log('\n[7] Reset handling');

test("'reset' message handler exists", () => {
  assert(/case ['"]reset['"]:/.test(APP_JS), 'no reset case');
});

test('close code 4000 (session_reset) handled', () => {
  assert(/4000/.test(APP_JS), 'no 4000 close handler');
});

test('resetLocalState clears in-memory state', () => {
  assert(/function resetLocalState/.test(APP_JS), 'no resetLocalState fn');
});

// =============================================================================
// 8. Join token URL handling
// =============================================================================

console.log('\n[8] Join token URL handling');

test("URL '?j=' param read on boot", () => {
  assert(/searchParams\.get\(['"]j['"]\)/.test(APP_JS), 'no ?j= reader');
});

test('Join token stripped from URL after read (no leak via bookmarks)', () => {
  assert(/history\.replaceState/.test(APP_JS), 'token not stripped from URL');
  assert(/searchParams\.delete\(['"]j['"]\)/.test(APP_JS), 'no ?j= delete');
});

// =============================================================================
// 9. Voter has autoreconnect with backoff
// =============================================================================

console.log('\n[9] Auto-reconnect');

test('backoff cap at 8s', () => {
  assert(/Math\.min\(8000,/.test(APP_JS), 'backoff cap missing');
});

test('backoff resets on hello', () => {
  // Look for backoffMs = 500 inside the hello handler
  assert(/case ['"]hello['"]:[\s\S]{0,400}backoffMs\s*=\s*500/.test(APP_JS),
    'backoff not reset on hello');
});

test('visibilitychange triggers reconnect when phone wakes', () => {
  assert(/visibilitychange/.test(APP_JS), 'no visibilitychange listener');
});

// =============================================================================
// 10. Design-pass integration (v5: editorial CSS contract)
// =============================================================================

console.log('\n[10] Design-pass integration');

test('Google Fonts stylesheet linked (Cormorant + Inter + JetBrains Mono)', () => {
  assert(/fonts\.googleapis\.com\/css2[^"]*Cormorant\+Garamond/.test(HTML), 'no Cormorant Garamond');
  assert(/fonts\.googleapis\.com\/css2[^"]*Inter/.test(HTML), 'no Inter');
  assert(/fonts\.googleapis\.com\/css2[^"]*JetBrains\+Mono/.test(HTML), 'no JetBrains Mono');
  assert(/display=swap/.test(HTML), 'font-display swap missing — would cause FOIT on slow networks');
});

test('QR <img> carries .qr-image class so design-pass styling applies', () => {
  const re = /<img[^>]*id="qr-image"[^>]*class="[^"]*\bqr-image\b[^"]*"|<img[^>]*class="[^"]*\bqr-image\b[^"]*"[^>]*id="qr-image"/s;
  assert(re.test(HTML), 'qr-image img missing .qr-image class');
});

test('QR URL paragraph carries .qr-url class so design-pass styling applies', () => {
  // The HTML has class="muted small qr-url" id="qr-url"
  const re = /id="qr-url"[^>]*class="[^"]*\bqr-url\b[^"]*"|class="[^"]*\bqr-url\b[^"]*"[^>]*id="qr-url"/s;
  assert(re.test(HTML), '#qr-url missing .qr-url class');
});

test('Projector screens have .projector on their page-header (cinematic h2 sizing)', () => {
  // page-header.projector is for the larger 5vw h2 on #screen-admin-voting & #screen-admin-results
  const projHeaders = HTML.match(/<header[^>]*class="[^"]*\bpage-header projector\b[^"]*"/g) || [];
  assert(projHeaders.length >= 2, `expected ≥2 projector page-headers, got ${projHeaders.length}`);
});

test('#screen-admin-voting uses .projector-grid layout', () => {
  // Look for projector-grid inside the voting screen
  const m = HTML.match(/<section[^>]*id="screen-admin-voting"[^>]*>[\s\S]*?<\/section>/);
  assert(m, 'screen-admin-voting section not found');
  assert(/<div[^>]*class="projector-grid"/.test(m[0]), 'projector-grid missing inside #screen-admin-voting');
});

test('#screen-admin-voting has .projector-side wrapping stats + actions', () => {
  const m = HTML.match(/<section[^>]*id="screen-admin-voting"[^>]*>[\s\S]*?<\/section>/);
  assert(m, 'screen-admin-voting section not found');
  assert(/<div[^>]*class="projector-side"/.test(m[0]), 'projector-side missing');
  assert(/<div[^>]*class="card stats-card"/.test(m[0]), 'stats-card missing');
  assert(/<div[^>]*class="card actions-card"/.test(m[0]), 'actions-card missing');
});

test('Results table has 4 column headers with col-* classes', () => {
  const m = HTML.match(/<thead>[\s\S]*?<\/thead>/);
  assert(m, 'no thead found');
  assert(/<th class="col-rank">/.test(m[0]),  'col-rank header missing');
  assert(/<th class="col-photo">/.test(m[0]), 'col-photo header missing');
  assert(/<th class="col-votes">/.test(m[0]), 'col-votes header missing');
  assert(/<th class="col-bar"/.test(m[0]),    'col-bar header missing');
});

test('Results table wrapped in .results-wrap (the dark cinematic frame)', () => {
  assert(/<div class="results-wrap">[\s\S]*<table class="results-table">/.test(HTML),
    'results-table not wrapped in .results-wrap');
});

test('app.js renderResults emits col-rank, col-photo, col-votes, col-bar classes', () => {
  // The function should set tdRank.className = 'col-rank' etc., not just plain td.
  assert(/className\s*=\s*['"]col-rank['"]/.test(APP_JS), 'col-rank class not set');
  assert(/className\s*=\s*['"]col-photo['"]/.test(APP_JS), 'col-photo class not set');
  assert(/className\s*=\s*['"]col-votes['"]/.test(APP_JS), 'col-votes class not set');
  assert(/className\s*=\s*['"]col-bar['"]/.test(APP_JS), 'col-bar class not set');
});

test('app.js renderResults builds a .bar with --w custom property (proportional bar)', () => {
  assert(/className\s*=\s*['"]bar['"]/.test(APP_JS), 'bar span class not set');
  assert(/setProperty\(['"]--w['"]/.test(APP_JS), '--w custom property not set');
});

test('app.js rank is zero-padded (editorial "01", "02" style)', () => {
  // String(i + 1).padStart(2, '0')
  assert(/padStart\(2,\s*['"]0['"]\)/.test(APP_JS), 'rank not zero-padded');
});

test('Cluster warning uses .warning-label class for the eyebrow', () => {
  assert(/<span class="warning-label">/.test(HTML),
    '.warning-label not used — eyebrow styling will not apply');
});

// =============================================================================
// 11. CSS doesn't ship dev-only markers
// =============================================================================

console.log('\n[11] CSS production-ready cleanup');

const CSS = fs.readFileSync(path.join(__dirname, '..', 'public', 'style.css'), 'utf8');

test('No dev-marker content "drop-in JPEG here" left in CSS', () => {
  assert(!/drop-in JPEG here/.test(CSS), 'dev marker still in CSS');
});

test('No fake QR pattern (would conflict with real <img> QR)', () => {
  // The fake QR used repeating-conic-gradient with the QR pattern
  assert(!/repeating-conic-gradient[^;]*ink-abyss[^;]*0 25%/.test(CSS),
    'fake QR pattern still in CSS');
});

test('No prototype demo-switcher chrome shipped', () => {
  assert(!/\.demo-switcher\b/.test(CSS), '.demo-switcher should be stripped');
});

test('CSS uses oklch for color-mix (modern, vivid blending)', () => {
  assert(/color-mix\(in oklch/.test(CSS), 'expected oklch color-mix usage');
});

test('CSS uses 100svh (not just 100vh) for stable mobile heights', () => {
  assert(/100svh/.test(CSS), '100svh not used — iOS Safari address-bar jumps would occur');
});


// =============================================================================
// 12. User documentation completeness
// =============================================================================

console.log('\n[12] Documentation completeness');

const ROOT = path.join(__dirname, '..');

test('README.md exists', () => {
  assert(fs.existsSync(path.join(ROOT, 'README.md')));
});

test('ADMIN-GUIDE.md exists (meeting-host walkthrough)', () => {
  assert(fs.existsSync(path.join(ROOT, 'ADMIN-GUIDE.md')));
});

test('VOTER-GUIDE.md exists (one-page voter handout)', () => {
  assert(fs.existsSync(path.join(ROOT, 'VOTER-GUIDE.md')));
});

test('REDTEAM.md exists (attack catalogue)', () => {
  assert(fs.existsSync(path.join(ROOT, 'REDTEAM.md')));
});

test('AUDIT.md exists (audit history)', () => {
  assert(fs.existsSync(path.join(ROOT, 'AUDIT.md')));
});

test('DESIGN-HANDOFF.md exists (for future redesigns)', () => {
  assert(fs.existsSync(path.join(ROOT, 'DESIGN-HANDOFF.md')));
});

// README is for deployers — make sure key sections are present
const README = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');

test('README documents required env vars', () => {
  assert(/PUBLIC_URL/.test(README), 'PUBLIC_URL not documented');
  assert(/TRUST_PROXY/.test(README), 'TRUST_PROXY not documented');
  assert(/PORT/.test(README), 'PORT not documented');
});

test('README has a Quick start section', () => {
  assert(/[Qq]uick start/.test(README));
  assert(/npm install/.test(README));
  assert(/npm start/.test(README));
});

test('README has a Troubleshooting section', () => {
  assert(/[Tt]roubleshooting/.test(README));
});

test('README provides at least one concrete deployment example', () => {
  assert(/Caddy|nginx|Render|Fly|Railway/.test(README), 'no concrete hosting example');
});

test('README points deployers to ADMIN-GUIDE for meeting host', () => {
  assert(/ADMIN-GUIDE/.test(README), 'README does not point to ADMIN-GUIDE');
});

// ADMIN-GUIDE is for the meeting host — verify it walks through a full meeting
const ADMIN = fs.readFileSync(path.join(ROOT, 'ADMIN-GUIDE.md'), 'utf8');

test('ADMIN-GUIDE covers claiming the Administrator role', () => {
  assert(/[Cc]laim.*[Aa]dministrator|[Aa]dministrator.*[Cc]laim/.test(ADMIN));
});

test('ADMIN-GUIDE covers setting the photo count', () => {
  assert(/photo count|number of photos|photos in this/.test(ADMIN));
});

test('ADMIN-GUIDE covers the QR code projection', () => {
  assert(/QR/.test(ADMIN));
});

test('ADMIN-GUIDE explains Lock Room', () => {
  assert(/[Ll]ock [Rr]oom/.test(ADMIN));
});

test('ADMIN-GUIDE explains Rotate QR', () => {
  assert(/[Rr]otate QR/.test(ADMIN));
});

test('ADMIN-GUIDE explains Count Votes Now', () => {
  assert(/[Cc]ount [Vv]otes/.test(ADMIN));
});

test('ADMIN-GUIDE explains Start New Session', () => {
  assert(/[Ss]tart [Nn]ew [Ss]ession|new session/.test(ADMIN));
});

test('ADMIN-GUIDE explains Download archive', () => {
  assert(/[Dd]ownload archive|archive.*JSON/.test(ADMIN));
});

test('ADMIN-GUIDE explains the cluster warning', () => {
  assert(/cluster|Review|networks produced multiple/.test(ADMIN));
});

test('ADMIN-GUIDE has a Troubleshooting section', () => {
  assert(/[Tt]roubleshooting/.test(ADMIN));
});

test('ADMIN-GUIDE has an FAQ', () => {
  assert(/FAQ|Frequently/.test(ADMIN));
});

// VOTER-GUIDE is for voters — verify it covers the basics
const VOTER = fs.readFileSync(path.join(ROOT, 'VOTER-GUIDE.md'), 'utf8');

test('VOTER-GUIDE explains how to scan the QR', () => {
  assert(/QR/.test(VOTER));
  assert(/scan|camera/.test(VOTER));
});

test('VOTER-GUIDE explains how to submit a vote', () => {
  assert(/[Ss]ubmit/.test(VOTER));
  assert(/[Tt]ype.*number|[Nn]umber.*[Pp]hoto/.test(VOTER));
});

test('VOTER-GUIDE explains how to change a vote', () => {
  assert(/[Cc]hange.*vote|change your vote|change.*number/.test(VOTER));
});

test('VOTER-GUIDE covers the disconnect/reconnect case', () => {
  assert(/sleep|wake|reconnect|signal/.test(VOTER));
});

test('VOTER-GUIDE includes a privacy statement', () => {
  assert(/[Pp]rivacy|anonymous/.test(VOTER));
});

test('VOTER-GUIDE is short (≤200 lines — handout-sized)', () => {
  const lines = VOTER.split('\n').length;
  assert(lines <= 200, `VOTER-GUIDE.md is ${lines} lines; should be ≤200 for one-page handout`);
});


// =============================================================================
// Summary
// =============================================================================
console.log('\n=== Contract test summary ===');
console.log(`  Total:  ${passed + failed}`);
console.log(`  Passed: ${passed}`);
console.log(`  Failed: ${failed}`);
if (failed > 0) process.exit(1);
process.exit(0);
