# v2 Audit — real bugs I found re-reading my own code

Read the whole tree top to bottom looking for things I'd be embarrassed to ship.
Found a mix of real bugs and "fine but should be tighter."

## CRITICAL bugs in v2

### A1. Join token is reusable (real flaw)
`/api/qr` mints a fresh signed token on every fetch and `/api/join` only checks
the signature + `sid`. The `jti` is generated but **never tracked**, so the
same QR-encoded token can be replayed forever by anyone who captured it.
This means: photo-of-the-projector → infinite ballot stuffing.

**FIX**: Track issued+consumed `jti` values in session state. `/api/join`
rejects tokens whose jti has already been redeemed by a different cookie.
Also rotate the QR token periodically and on demand.

### A2. Voter cookie outlives the session id (real flaw)
The voter cookie embeds `sid` and `vid`, but the cookie itself has a 6-hour
`maxAge` set in the browser. After a session reset the server invalidates by
`sid` mismatch — but the cookie remains in the browser. When the next session
starts, that cookie sits unused but adds confusion. Worse: the `secret` file
persists across restarts (good for crash recovery, bad here) so old cookies
still verify cryptographically; only the `sid` mismatch stops them. That's
adequate but fragile.

**FIX**: On `/api/join` for a new session, always clear any old `dups_voter`
cookie first. Also include a `kind` distinguisher already (good), AND on
session reset, broadcast `clear-cookies` so clients wipe them client-side.

### A3. Admin cookie can outlive the admin slot release (real flaw)
`reset-session` regenerates `session.id`, which invalidates everything via
sid mismatch. But the admin cookie itself stays in the browser. If the same
browser then becomes the admin of a *new* session, they get a new aid; the
old aid sits as a stale cookie. Not exploitable today, but a footgun.

**FIX**: Same as A2 — explicitly clear cookies on reset.

### A4. `Set-Cookie` doesn't set `Secure` (real flaw on HTTPS)
Cookies are `httpOnly` + `sameSite: 'lax'` but not `Secure`. On a LAN-only HTTP
deployment that's fine. But the moment anyone runs this behind HTTPS (which
is recommended for any external network), the cookies will leak over
plain-HTTP fallbacks.

**FIX**: Auto-set `Secure` when `req.protocol === 'https'` or
`X-Forwarded-Proto: https`. Detected at runtime.

### A5. CSP allows `'unsafe-inline'` for styles (real but minor)
The CSP has `style-src 'self' 'unsafe-inline'`. The current code doesn't
need it. Tighten.

**FIX**: Drop `'unsafe-inline'` from style-src; verify nothing relies on it.
(Inline style attributes are not used in our HTML/JS.)

### A6. No CSRF protection on POST endpoints (real flaw)
`/api/admin/claim` and `/api/join` accept POSTs based on cookies + sameSite=Lax.
SameSite=Lax protects against most CSRF on POST, but a top-level navigation
GET can still trigger Lax cookies. We're using POST so we're mostly OK, but
defense in depth says: require a custom header that browser cross-origin
JS cannot forge, OR a double-submit token.

**FIX**: Require an `X-DUPS-Origin` header set to `same-site` on all POSTs.
Browser cross-origin JS can't add custom headers without a preflight, and
the preflight will be blocked by our CORS (we set none — same-origin only).

### A7. Race on admin claim is single-threaded but not idempotent (real)
The Node event loop guarantees only one admin claim wins per tick — that's
true. BUT: the existing-cookie short-circuit in `/api/admin/claim` checks
`session.adminTokenId === existing.aid`. If the admin's cookie aid doesn't
match `adminTokenId` (e.g., a stale cookie from before a reset), it falls
through to the "is the slot free?" check. If the slot was previously taken
and is still taken, this returns 409 — correct. If the slot was freed by
reset, this issues a *new* admin token to whoever calls first — correct.
So it actually works, but the code path is hard to reason about.

**FIX**: Refactor: explicit "is this cookie still the active admin?" check
first; otherwise treat as a fresh claim. Comments clarifying intent.

### A8. `req.protocol` is unreliable when behind a proxy
We use `req.protocol` in QR URL building. If anyone runs this behind nginx,
they'll get `http` even when the public URL is `https`, embedding the wrong
scheme in the QR.

**FIX**: Enable `app.set('trust proxy', 'loopback')` so X-Forwarded-Proto is
respected from a local reverse proxy only. Comment that further trust must
be explicit.

### A9. Test `data` directory cleanup doesn't actually run (real test bug)
The test harness has this code:
```js
for (const f of fs.readdirSync(path.join(TMP_DATA, 'data') || '/dev/null').filter(_ => true).catch?.(()=>[]) || []) {}
```
That's nonsense — `readdirSync` doesn't return a promise, `.catch?.()` is
undefined for an array, and the IIFE-style filter does nothing. The actual
cleanup is in the `try/catch` below it, which is fine, but the prior line
is dead garbage. Code stink.

**FIX**: Delete the dead line.

### A10. Test `restartServer` keeps `secret` but wipes everything else
This is by design (so cookies stay valid across restarts in sim #49). But it
means sim #1 ("two admin claims") is run AFTER previous sims have already
written a `secret` file. That's fine — the secret is per-server, not
per-session — but if a previous sim left `state.json` claiming an admin
exists, `loadPersisted` restores it. We wipe state files but keep secret.
Let me re-read… yes, the cleanup wipes state.json + archive.json + keeps
secret. Correct.

But there's still a subtle issue: `restartServer` is called at the start of
each sim. The very first sim has no prior server, but `restartServer`
calls `stopServer()` which does nothing (no `serverProc`). Then `startServer`.
That should work. OK.

## HIGH severity

### A11. WS upgrade per-IP cap is fooled by IPv6 vs IPv4
`clientIp` strips `::ffff:` prefix to normalize. But a client connecting via
IPv6 directly (`::1`) is a different bucket from IPv4 (`127.0.0.1`). Not
exploitable in any real scenario, just inconsistent.

**FIX**: Document. Not worth normalizing IPv6.

### A12. `req.protocol` in QR URL embeds `http://` always over LAN
Phones expect that. But if admin uses Safari and the QR encodes `http://`,
on iOS 17+ Safari sometimes warns. Acceptable.

**FIX**: None. Doc.

### A13. Token bucket capacity is 30 burst — admin reload triggers it?
On reload, admin's WS sends ~5 messages quickly (claim-role isn't a WS
msg — it's HTTP). The WS only does heartbeat + actions. So burst of 30 is
generous. Voters submit ~1 vote/sec max realistically. Bucket is fine.

### A14. `freshSession()` doesn't broadcast state — only `reset` event
Look at the reset handler:
```js
freshSession();
broadcast({ type: 'reset' });
for (const [w] of clients.entries()) { try { w.close(4000, 'session_reset'); } catch {} }
```
After close, those clients aren't in `clients` anymore (the close handler
removes them). When they reconnect, they'll receive a hello with fresh state.
OK, that's actually correct.

But: the admin who *triggered* the reset is also closed. The client code
treats code 4000 as a reset signal and routes to splash. The admin's cookie
is still in their browser (carrying old aid for old sid). When they reconnect,
the WS handler treats their cookie as not matching the new sid, so they get
role=null. Then they click Administrator again, the cookie's aid doesn't match
`adminTokenId` (which is null now), so they get a *new* claim. Server sets
a fresh cookie, overwriting the old. OK, that works — but only after the
admin clicks "Administrator" again. UX is okay; they're meant to start a
new session.

### A15. Voter status updates on race after admin closes voting
`close-voting` does:
```js
session.votingOpen = false;
session.votingClosed = true;
session.results = computeResults();
broadcastState();
broadcast({ type: 'voting-closed' }, m => m.role === 'voter');
```
A voter submitting at the exact same instant: their `submit-vote` handler
checks `session.votingOpen` after `broadcastState` but before the message
is delivered. Node is single-threaded so within one handler, no race. Across
handlers, the second one observes the state change. OK.

But: a voter's `submit-vote` could land in the queue BEFORE `close-voting`
in the same loop tick. Then it'd be accepted, then close-voting would tally
including that late vote. That's correct behavior — vote came in first, was
accepted, gets counted. Not a bug.

### A16. `getQR` regenerates a new joinToken on every call
Each admin reload of the voting screen requests a fresh QR. New token, new
jti. Old jti is never invalidated. So if anyone scanned the old QR, that
token works indefinitely until either (a) the session resets or (b) we
track-and-invalidate (A1 fix).

**FIX**: A1 fix covers this.

## VPN and incognito mode — what's actually possible

This is the question I have to be straight about.

### VPN
A VPN changes the client's source IP. From the server's perspective, a
voter behind a VPN looks like a voter from somewhere else. We have no way
to know they're using one without third-party services (IPQualityScore,
MaxMind, etc.) which:
- Cost money
- Phone home (privacy issue for a 30-person photography club)
- Are easy to circumvent (residential proxies)
- Are inappropriate for a LAN meeting

**For a LAN-only app**: VPN simply doesn't matter. Voters connect to the
admin's LAN IP. If they're on the LAN, they're in the room. If they're not
on the LAN, they can't reach the server in the first place. The QR encodes
a LAN URL like `http://192.168.1.5:3000/...` which only resolves on the
LAN. Done.

**For a hypothetical internet-deployed version**: VPN detection without
paid services is a losing fight. The right defense is per-member credentials.

### Incognito mode
Incognito creates a fresh cookie jar. Voter scans QR in incognito → fresh
voter cookie → second vote. This is the Mentimeter limit I called out
before. Here's what's actually possible without changing the threat model:

**Layer 1: Per-IP voter cap on join.**
At the same physical meeting, multiple voters can share an IP (NAT, guest
Wi-Fi). But the same single person creating multiple voter identities will
share their IP across them. A simple rule: cap joins per IP at, say, 3.
Most households send ≤2 voters; a single attacker creating 10 ghost voters
would all share their phone's IP.

**Layer 2: Per-IP voter consolidation at tally.**
At close time, examine the votes: any IPs that produced multiple voter ids
get a warning shown to the admin. Admin sees "192.168.1.x cast 4 votes —
review?" Admin can choose to keep, dedupe to most-recent, or dedupe by
majority. Not automated invalidation — admin's call.

**Layer 3: Single-redemption join tokens (A1 fix).**
Each QR scan = one redemption of one jti. The QR refreshes its token
periodically. A photo of the projector is now a moving target.

**Layer 4: Admin can rotate the QR.**
Add a "Rotate QR" button. Invalidates all previously issued join tokens,
shows a fresh one. Anyone wanting to dupe-vote has to find the projector
again. Honest voters who already joined keep their voter cookie and aren't
affected.

**Layer 5: Lock the room.**
Already exists. After a few minutes of meeting time, admin locks — no new
joins allowed. Combined with layers above, dupe-voting must happen during
the join window.

**Layer 6: Member roster (optional, future).**
If DUPS provides a member list, we can move to per-member credentials.
That's a hard 1-member-1-vote. Not requested today, but architected to
support it.

Layers 1+2+3+4+5 are all baked in now (after the A1 fix). That's about as
hard as you can make ballot stuffing without member auth.

## What 50 NEW sims should cover

Different scope than round 1. Round 1 hit the obvious surface. Round 2 should:
1. Stress timing/race conditions
2. Hammer the new join-token tracking
3. Verify the per-IP voter cap
4. Verify cookie-clearing on reset
5. Verify CSRF custom-header defense
6. Verify Secure-cookie auto-detection
7. Verify VPN-style requests don't break anything
8. Hammer concurrent voters at scale
9. Verify state determinism across crash points
10. Verify admin UX edge cases

---

# Resolution status (after v3 implementation)

| ID | Severity | Status in v3 |
|----|----------|--------------|
| A1 — Reusable join token (jti not tracked) | CRITICAL | **FIXED.** `session.redeemedJtis` tracks every jti redemption. Replay → 409 token_used. Plus "Rotate QR" admin button marks old unredeemed jtis as `__invalidated` sentinel. |
| A2 — Voter cookie outlives session | CRITICAL | **FIXED.** Server broadcasts `reset` event before closing sockets so clients wipe local state. `joinedVoters` lookup in the voter cookie check means cookies for deleted vid's are rejected even if signature still valid. |
| A3 — Admin cookie outlives slot release | CRITICAL | **FIXED.** Same mechanism as A2; admin must re-claim explicitly. Branch 1 of `/api/admin/claim` requires `aid === session.adminTokenId`. |
| A4 — Cookies missing `Secure` flag | CRITICAL | **FIXED.** `setSignedCookie()` reads `isHttps(req)` (which honors `X-Forwarded-Proto` via `trust proxy 'loopback'`) and sets `secure: true` accordingly. |
| A5 — CSP allowed `'unsafe-inline'` for styles | MINOR | **FIXED.** `style-src 'self'` only. Also added COOP/CORP headers. |
| A6 — No CSRF defense | CRITICAL | **FIXED.** `requireCsrfHeader` middleware requires `X-DUPS-Origin: same-site` on all POSTs. Browser cross-origin JS cannot send this header without a preflight, which we don't honor for foreign origins. |
| A7 — Admin claim branching unclear | LOW | **FIXED.** Refactored into three explicit branches (existing-cookie match → slot taken → fresh mint), commented clearly. |
| A8 — `req.protocol` unreliable behind proxy | LOW | **FIXED.** `app.set('trust proxy', 'loopback')` + `isHttps()` helper. |
| A9 — Dead test cleanup code | TRIVIAL | **FIXED.** Removed during harness rewrite into `test/harness.js`. |
| A10 — Test secret persistence (not a bug, just a note) | INFO | **CONFIRMED OK.** Harness deletes everything except `secret` on `restartServer` — that's by design (sim #49 needs cookies to survive a restart). |
| A11 — IPv6/IPv4 normalization inconsistency | INFO | **DOCUMENTED.** No real-world impact; not exploitable. |
| A12 — QR HTTP scheme on LAN | INFO | **DOCUMENTED.** Expected behavior. |
| A13 — Burst capacity sanity check | INFO | **CONFIRMED OK.** 30/burst, 10/sec sustained is comfortably above legitimate use. |
| A14 — Reset flow correctness | INFO | **CONFIRMED OK.** Trace verified; admin must re-claim, which is the intended UX. |
| A15 — Vote-vs-close race | INFO | **CONFIRMED OK.** Node single-threaded; deterministic; correct behavior either way. |
| A16 — Stale QR jti was unkillable | CRITICAL (combines with A1) | **FIXED.** Covered by A1 fix + rotation sentinel. |

---

# v3 → v4 audit (threat-model shift to public-internet)

After v3 shipped, the actual use case clarified: this is a REMOTE app, voters
connect over the public internet. Several v3 defenses were designed for LAN
deployment and become wrong or harmful in the public-internet model.

## What needed rethinking

### B1 — Per-IP join cap of 3 (NOW HARMFUL in v3)

**LAN reasoning (v3):** Each phone is one household member. A single attacker
trying to dupe-vote via incognito tabs shares an IP. Cap at 3 catches them.

**Public-internet reality:** Mobile carriers route ALL their traffic through
carrier-grade NAT (CGNAT). One IP can legitimately represent thousands of real
voters. Corporate offices, schools, libraries, coworking spaces, hotel WiFi —
all NAT many users through one IP. A cap of 3 will silently lock out real
voters and make the app feel broken.

**FIX (v4):** Cap removed. Defenses against incognito dupe-voting now layered:
- Single-redemption join tokens (carried from v3)
- Admin "Rotate QR" (carried from v3)
- "Lock Room" admin button (carried from v2)
- IP-cluster warnings at tally (informational only)

### B2 — Origin allow-list included auto-detected LAN IPs (WRONG SHAPE)

**FIX (v4):** `PUBLIC_URL` env var provides the canonical public origin. The
Origin allow-list is now exactly that origin in production, or localhost
variants in dev mode.

### B3 — QR URL auto-detected the request Host header (UNSAFE)

In a public-internet deployment, the Host header is attacker-controlled (or
at minimum non-canonical when multiple domains point to the same server).

**FIX (v4):** QR URL is built from `PUBLIC_URL.origin` in production. Host
header spoofing has no effect.

### B4 — No HSTS (acceptable on LAN, unsafe on public internet)

**FIX (v4):** HSTS header sent (`max-age=15552000; includeSubDomains`) when
`PUBLIC_URL` is HTTPS. Suppressed in dev mode and on plain-HTTP deployments
to avoid trapping development.

### B5 — CSP connect-src too permissive (`ws: wss:`)

Allowed connections to ANY ws/wss endpoint. Wrong in production.

**FIX (v4):** In production, `connect-src` is locked to the configured WSS
origin only. In dev mode, broader for convenience.

### B6 — Boot banner suggested sharing LAN IPs

Misleading for the new use case. Replaced with deployment-aware messaging.

### B7 — No loud warning when running plain HTTP in non-dev

Could be deployed publicly over plain HTTP without realizing the cookie-Secure
implications. **FIX (v4):** Boot warning unless `DEV_MODE=1` is set.

### B8 — Cross-platform consistency hooks missing

Multiple subtle iOS Safari / Android Chrome / desktop browser differences
were not addressed in markup. **FIX (v4):** Added `viewport-fit=cover` and
`interactive-widget=resizes-content` meta, both vendor PWA-capable metas,
`color-scheme: dark`, format-detection extensions for date/address/email,
and Google Fonts preconnect hints. Updated CSP to permit Google Fonts. The
remaining cross-platform work (actual CSS rules for `100svh`, `appearance: none`
on number inputs, etc.) lands in the design pass — the design prompt now
documents the hooks the CSS must use.

## Confirmed safe (no change needed)

- **WS connection cap (8/IP)** stays. Defends against socket exhaustion,
  not against legitimate voters. 8 simultaneous sockets is comfortably above
  realistic legitimate usage even from a big NAT.
- **Token-bucket message rate limit (10/sec sustained, 30 burst)** stays.
  Per-connection, not per-IP, so CGNAT users aren't punished collectively.
- **Single-redemption join tokens** carry over unchanged.
- **CSRF custom header** carries over unchanged.
- **HMAC-signed cookies** carry over unchanged.
- **Atomic disk persistence** carries over unchanged.
- **Cluster warning at tally** carries over but is now the PRIMARY signal,
  not a side note — copy was softened to reflect that shared IPs are usually
  legitimate.

## Resolution table

| ID | Severity | v4 Status |
|----|----------|-----------|
| B1 — Per-IP join cap of 3 incompatible with CGNAT | CRITICAL (false positives) | **REMOVED.** Replaced by jti + Rotate QR + Lock Room + cluster warnings. |
| B2 — LAN-driven Origin allow-list | CRITICAL (wrong shape) | **FIXED.** `PUBLIC_URL`-driven. |
| B3 — Host-header-derived QR URL | HIGH | **FIXED.** Built from `PUBLIC_URL.origin`. |
| B4 — No HSTS | HIGH | **FIXED.** Sent when `PUBLIC_URL` is https. |
| B5 — Loose connect-src CSP | MEDIUM | **FIXED.** Locked to configured origin in prod. |
| B6 — Misleading boot banner | LOW | **FIXED.** Deployment-aware messaging. |
| B7 — No HTTP warning | MEDIUM | **FIXED.** Loud warn unless DEV_MODE=1. |
| B8 — Missing cross-platform meta hints | MEDIUM | **FIXED.** Viewport, app-capable, color-scheme, format-detection extended; CSS hooks documented in design prompt. |

---

# v4 → v5 (design-pass integration)

The visual design pass landed (editorial / oceanographic field-journal aesthetic,
brass accent, Cormorant Garamond + Inter + JetBrains Mono pairing, two viewport
modes: bone-paper voter screens, deep-navy projector screens).

## Audit of the design-pass CSS against my HTML/JS contract

The design pass produced a thoughtful, system-grade `style.css`. Auditing
against the existing HTML and JS, I found four CSS expectations that needed
small additive changes to render correctly. None of them required renaming or
removing any existing id or class — all preserve the JS contract.

### C1 — Splash `<img>` vs `<div>` semantics

The CSS targeted `.splash-image` with `position: absolute; inset: 0` and a CSS
gradient background (with a dev-marker pseudo-element). My HTML uses
`<img class="splash-image" src="https://dups.club/...">`. Result if shipped
as-is: real DUPS photo would render *behind* the gradient placeholder,
producing a confusing visual.

**FIX:** Replaced the placeholder gradient with `width: 100%; height: 100%;
object-fit: cover` so the `<img>` fills the hero plate naturally. Removed
the dev-marker `::after` (pseudo-elements don't render on replaced elements
anyway, but I stripped the rule for cleanliness).

### C2 — Faux QR pattern would conflict with real `<img id="qr-image">`

The CSS painted a fake QR pattern with `repeating-conic-gradient`. My JS sets
`qr.src` on `<img id="qr-image">`. Result if shipped as-is: empty `<img>` would
show the fake QR pattern as background instead of the real QR.

**FIX:** Stripped the fake QR pattern. Kept the `.qr-image` sizing rules
(`max-width: 560px`, `aspect-ratio: 1/1`, paper background, rounded corner)
which apply to the `<img>` element when it has `class="qr-image"`. Added
`class="qr-image"` to `<img id="qr-image">` in index.html.

### C3 — Results table needed a 4th "bar" column and `.col-*` class hooks

The design's podium row, italicized photo names, and the proportional vote-bar
all depended on column classes (`.col-rank`, `.col-photo`, `.col-votes`,
`.col-bar`) and a `.bar` span with a `--w` custom property. My JS rendered
3 plain `<td>` elements with no classes and no bar. Result if shipped as-is:
table would be flat — no podium gold, no proportional bars, no editorial
column styling.

**FIX:** Updated `renderResults` in app.js to emit 4 column classes plus the
`.bar` span with `style="--w: X%"` (computed as a percent of the max vote
count). Added a 4th `<th class="col-bar">` to the table head in index.html.
Also zero-pad ranks ("01", "02") per the editorial typography.

### C4 — Projector screens needed a grid layout wrapper

The CSS expected `.projector-grid > .qr-card + .projector-side > .stats-card
+ .actions-card` for the cinematic two-column projection layout. My HTML
had everything in one stacked `.card.qr-card`. Result if shipped as-is:
QR + stats + buttons would stack vertically even on a 1920px projector,
wasting horizontal space.

**FIX:** Restructured `#screen-admin-voting` in index.html with the wrappers
the design expected. The JS id hooks (`#qr-image`, `#joined-count`,
`#voter-count`, `#vote-count`, `#rotate-qr-btn`, `#lock-room-btn`,
`#count-votes-btn`) all remain in place — the wrappers are pure
presentation layer.

## Other small integration changes

- Added the three Google Fonts `<link>` tags to `<head>` per the design handoff.
- Added `class="qr-url"` to `<p id="qr-url">` so the mono URL styling applies.
- Added `class="projector"` to the page-headers on `#screen-admin-voting` and
  `#screen-admin-results` so the cinematic 5vw h2 size kicks in.
- Wrapped the results table in `<div class="results-wrap">` for the dark
  cinematic frame.
- Cluster-warning markup uses `<span class="warning-label">Review</span>` as
  the eyebrow instead of `<strong>` (matches the brass eyebrow style).
- Stripped the demo-switcher prototype chrome from the CSS (`.demo-switcher`
  rules) — not needed in production.

## Verification

Extended `test/unit-contracts.js` with 17 new design-integration assertions
(see "[10] Design-pass integration" and "[11] CSS production-ready cleanup"
in that file). All 110 contract tests now pass, plus 86 unit-pure and 18
unit-behavior — 214 directly-executed tests total, all passing. The 150
integration sims still parse clean.

## What I did NOT change

- No JS id/class hooks renamed.
- No security-relevant code touched.
- No animations added beyond the spinner the design pass shipped (which the
  existing `prefers-reduced-motion` rule already disables).
