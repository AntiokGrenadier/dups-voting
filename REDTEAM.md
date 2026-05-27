# Red Team: 50 Attack Scenarios Against DUPS Voting v1

Each row: scenario → does v1 fail? → fix in v2.

## A. Authentication / Role attacks
1. **Race two admin claims sent simultaneously.** Two clients send `claim-role:admin` in the same tick. v1: Node is single-threaded, so the second one is rejected — but no atomic guard if we ever go async. FIX: keep explicit check + add a server-side mutex flag, log all admin claim attempts.
2. **Admin disconnects, attacker claims admin.** v1: explicitly keeps the admin slot held on disconnect — good, but there's no way for the real admin to recover after a crash. FIX: admin gets a one-time recovery token (signed cookie) on claim; presenting that token re-binds the slot.
3. **Voter sends `claim-role:admin` after voting started.** v1: rejected (slot taken). PASS.
4. **Voter spoofs `clientId` of admin in a message.** v1: `clientId` comes from `clients.get(ws)` — server-side mapping, ignored from message body. PASS.
5. **Voter sends `set-photo-count` directly.** v1: checks role + clientId === adminClientId. PASS.
6. **Voter sends `close-voting` directly.** Same as above. PASS.
7. **Admin sends `submit-vote`.** v1: only voters can vote — but the admin's vote isn't counted. INTENTIONAL per spec (admin role excludes voting). Document this.
8. **Connect WebSocket without going through HTTP first.** v1: no Origin check, no handshake validation. FAIL. FIX: validate Origin header against allow-list, reject cross-origin upgrades, enforce same-origin in `verifyClient`.
9. **CSWSH: malicious site embeds JS that opens WS to admin's LAN URL.** v1: no Origin check. FAIL. FIX: Origin validation + per-connection nonce in cookie that the malicious site can't read.
10. **Replay an old session's QR after a reset.** v1: `session.id` regenerates on reset, but QR URL has session id only as a query param — the server doesn't actually validate it. FAIL. FIX: validate session id on every WS connect; reject stale ids.

## B. Vote integrity attacks
11. **One voter opens app in incognito + normal window, votes twice.** v1: two WS connections = two clientIds = two votes counted. FAIL. This is the Mentimeter problem. FIX: require a signed join-token from the admin's QR; bind one vote per token; cap one token per IP per session unless admin explicitly allows shared devices.
12. **Voter refreshes the page mid-session.** v1: gets a new clientId → their old vote orphaned in `votes` map but their new connection has no vote linked. FAIL. FIX: durable voter id stored in cookie; reconnects rebind to the same vote slot.
13. **Voter opens 50 tabs and votes 50 times.** Same as 11. FIX same.
14. **Voter votes, then disconnects.** v1: vote is kept in the map. PASS — but is that desired? Spec says "Each user's final vote submission" — if they disconnect they didn't submit a final vote. AMBIGUOUS. Decision: keep last submitted vote even if they disconnect (consistent with humans putting down their phone).
15. **Voter sends `submit-vote` with photoNumber = "1" (string).** v1: `parseInt` handles it. PASS.
16. **`photoNumber = 1.5`.** v1: `parseInt` truncates to 1 → silently miscounted. FAIL. FIX: use `Number.isInteger(Number(x))` and reject decimals explicitly.
17. **`photoNumber = "1; DROP TABLE votes"`.** v1: parseInt → NaN → rejected. PASS (no SQL anyway).
18. **`photoNumber = 0` or `-5`.** v1: range checked. PASS.
19. **`photoNumber = Number.MAX_SAFE_INTEGER`.** v1: range-checked against photoCount. PASS.
20. **`photoNumber = null` / `undefined`.** v1: parseInt → NaN → rejected. PASS.
21. **`photoCount = 1e9` (admin sets billion).** v1: accepted. FAIL (DoS via tally Map of 1B entries). FIX: cap photoCount at a reasonable max (e.g., 500).
22. **`photoCount = 0` or negative.** v1: rejected. PASS.
23. **`photoCount = "abc"`.** v1: parseInt → NaN → rejected. PASS.
24. **Admin changes photoCount mid-vote.** v1: `set-photo-count` clears votes and reopens. Probably surprising — but consistent. Document. Could be a UX issue if admin slips. FIX: require explicit reset to change count after voting opens, OR confirm clearly.
25. **Voter submits before photoCount is set.** v1: `votingOpen` false → rejected. PASS.
26. **Voter submits after `close-voting`.** v1: `votingClosed` true → rejected. PASS.
27. **Admin closes voting twice.** v1: second call no-ops because `votingOpen` is false. PASS.

## C. Protocol / DoS attacks
28. **Send 10,000 messages per second.** v1: no rate limit. FAIL. FIX: per-connection token bucket (e.g., 10 msg/sec sustained, 30 burst).
29. **Send a 100MB JSON message.** v1: ws library default maxPayload is 100MB. FAIL. FIX: set `maxPayload` to 4 KB.
30. **Send deeply nested JSON `{"a":{"a":{"a":...}}}`.** v1: JSON.parse handles it, but it costs memory. FAIL with maxPayload not set. FIXED by 29.
31. **Connect 10,000 WebSockets from one IP.** v1: no per-IP cap. FAIL. FIX: cap concurrent connections per IP (e.g., 5).
32. **Open then never send anything — slowloris.** v1: connection stays open forever. FAIL. FIX: heartbeat/ping every 30s, terminate dead clients.
33. **Send invalid JSON.** v1: try/catch returns silently. PASS — but no logging.
34. **Send unknown message types.** v1: switch falls through. PASS.
35. **Send message without `type` field.** v1: switch falls through. PASS.
36. **Send extra fields in messages.** v1: ignored. PASS.
37. **Disable WebSocket, force HTTP polling.** N/A — app requires WS. PASS.
38. **Compression-based amplification (CRIME/BREACH on perMessageDeflate).** v1: deflate is default-on in `ws`. FAIL per OWASP guidance. FIX: `perMessageDeflate: false`.

## D. UI / Client-side attacks
39. **Voter types `<script>alert(1)</script>` somewhere.** v1: nowhere echoes voter input as HTML — all values are numbers or assigned via textContent. PASS.
40. **Voter modifies DOM to enable disabled admin radio.** v1: server enforces. PASS (server is source of truth).
41. **Voter swaps the QR image on admin's screen via XSS.** v1: no XSS surface; QR comes from same-origin endpoint. PASS.
42. **Open Dev Console and call `send({type:'close-voting'})` as voter.** v1: server checks role. PASS.
43. **Reload during admin setup, lose photoCount.** v1: server holds it. PASS — but admin's UI doesn't restore state. FAIL UX. FIX: client routes from server state on connect.
44. **Two browser windows logged in as admin on the same machine.** v1: first one wins; second one becomes a voter? Actually v1: second window can re-claim admin since `adminClientId` is per-clientId, and a refreshed admin loses their clientId. FAIL (the disconnect-keeps-claim logic depends on clientId persistence which the client doesn't have). FIX: admin recovery token in HttpOnly cookie.

## E. QR / join attacks
45. **QR URL embeds wrong host (e.g., 0.0.0.0 or localhost).** v1: uses `req.get('host')` — if admin connected via localhost, the QR encodes localhost, which phones can't reach. FAIL. FIX: detect non-routable hosts in QR endpoint and substitute a LAN IP; surface a warning if ambiguous.
46. **Admin behind NAT, voters on different network.** Out of scope (LAN app). Document.
47. **QR scanned by passerby on guest WiFi.** v1: no auth on join. FAIL for "real integrity". FIX: QR carries a single-use join token; admin can see/limit joins.
48. **Voter shares the URL outside the room.** Same as 47.

## F. Persistence / archive attacks
49. **Server crashes mid-vote.** v1: all state in memory. FAIL for "real integrity". FIX: persist votes + session to disk on every change (small JSON file is enough at this scale); restore on boot.
50. **Archived votes accessible via what endpoint?** v1: only in-memory, no endpoint. PASS but useless. FIX: add an admin-only endpoint to download archived sessions as JSON.

---

# Summary of v2 changes needed

1. **Origin validation** on WS upgrade — block CSWSH.
2. **maxPayload = 4 KB**, **perMessageDeflate = false** — block oversize/compression attacks.
3. **Heartbeat ping/pong**, terminate dead WS — block slowloris and stale connections.
4. **Per-IP connection cap** (5).
5. **Per-connection rate limit** (token bucket: 10/sec sustained, 30 burst).
6. **Cap photoCount** (e.g., 500).
7. **Reject non-integer / decimal photoNumber** explicitly (don't trust parseInt).
8. **Signed join token** in QR — voters must present it; one vote per token.
9. **Durable voter cookie** — reconnects rebind to the same vote slot (prevents accidental dup and supports refresh).
10. **Admin recovery cookie** — refresh-safe admin role binding.
11. **Session-id validation** — every WS message must match current session id.
12. **Disk persistence** of session + archived votes, restored on boot.
13. **Restore client UI state** from server on connect (already partly done — extend it).
14. **Admin-only archive download endpoint** (auth via admin cookie).
15. **QR endpoint smart host detection** — replace localhost/0.0.0.0 with a LAN IP.
16. **Structured logging** — every claim, vote, close, reset, rejection.
17. **Mobile-first UI** — bigger tap targets, proper viewport handling, iOS/Android tested patterns.
18. **Confirm-before-change** when admin changes photoCount mid-vote.

The hardest call: **how strict to be about one-vote-per-device**. Cookie-based tracking is reliable for honest users, defeatable by motivated cheaters (incognito). True 1-voter-1-vote needs per-member credentials (which DUPS doesn't have set up). I'll implement:
- Cookie-based voter binding (handles 99% — refresh, accidental tab close, etc.)
- Single-use join token from QR (raises the bar — cheater needs to scan QR fresh each time, admin sees join count)
- Admin can see voter join count vs. votes received, so anomalies are visible
- Optional "lock the room" mode — admin can freeze the voter list, so late joiners are rejected

That's the honest answer about integrity at this app's scope. Documenting the threat model is part of the deliverable.

---

# Round 2: v2 → v3 hardening (50 additional scenarios)

After v2 shipped I re-audited the code looking for things I'd be embarrassed
to ship. Found nine real bugs documented in AUDIT.md and addressed all of them.
Then ran 50 fresh attack simulations focused on the v3 attack surface.

## What v2 still got wrong

- **Join tokens were reusable.** v2's `jti` was generated but never tracked.
  A photo of the projector → infinite ballot stuffing.
- **No CSRF defense.** SameSite=Lax was the only protection.
- **Cookies missing `Secure` flag** when running behind HTTPS.
- **CSP still allowed `'unsafe-inline'`** for styles (unneeded).
- **No defense against multiple incognito-window votes** from the same person.
- **Admin claim flow** had an unclear three-way branch — worked but hard to reason about.
- **`req.protocol`** unreliable behind a reverse proxy.
- **State writes were not atomic** — a crash mid-write could corrupt state.

## v3 fixes

- **Single-redemption join tokens.** Each `jti` tracked in `session.redeemedJtis`.
  Replay returns 409.
- **Per-IP voter join cap** (default 3). The main incognito-mitigation knob.
  Caps multiple voter-creation attempts from one network address.
- **"Rotate QR" admin button.** Mints a fresh `jti` AND marks the previous
  unredeemed one as invalidated (sentinel). Existing voters keep voting.
- **CSRF custom-header defense.** All POST endpoints require
  `X-DUPS-Origin: same-site`. Cross-origin browser JS cannot send custom
  headers without preflight, which we don't honor for foreign origins.
- **`Secure` cookies auto-detected** via `req.secure` / `X-Forwarded-Proto`,
  with `trust proxy 'loopback'` for safe extraction from local reverse proxies.
- **CSP tightened** — removed `'unsafe-inline'` from style-src; added COOP/CORP.
- **Atomic state writes** via `.tmp + rename`.
- **`reset` broadcast before close** so clients clear local state before disconnect.
- **IP cluster awareness on close** — admin sees informational warnings when
  the same network produced multiple voter ids. NOT auto-invalidated.
- **Cleaner admin-claim flow** with explicit numbered branches.

## Round-2 scenario catalogue (50 sims, see test/round2.js)

### CSRF defense (51-55)
51. POST `/api/admin/claim` without CSRF header → 403
52. POST `/api/join` without CSRF header → 403
53. POST with wrong CSRF header value → 403
54. CSRF header value comparison is lowercase-tolerant
55. GET requests do not require CSRF header

### Single-redemption join tokens (56-62)
56. Same QR token replayed from a third device → 409
57. Same token re-presented by the same cookie → idempotent 200
58. After rotation, OLD unredeemed token is invalidated; NEW works
59. Tampered token (broken signature) → 400
60. Token from previous session (`sid` mismatch) → 400 stale_session
61. Token replay across server restart still rejected (`redeemedJtis` persists)
62. Spam of fake tokens — all 10 rejected

### Per-IP voter join cap (63-66)
63. Cap kicks in at 4th incognito attempt from same IP → 429
64. Cap error message names the limit
65. Existing voter cookie does NOT consume cap (idempotent re-join)
66. Session reset clears the IP counter

### Cookie hygiene (67-70)
67. Voter cookie has HttpOnly + SameSite=Lax
68. Cookies do NOT carry Secure flag on plain-HTTP LAN
69. `X-Forwarded-Proto: https` triggers Secure flag
70. Tampered admin cookie is silently ignored (no role granted)

### Concurrent vote stress (71-75)
71. Multiple concurrent voters all counted (within IP cap)
72. Rapid-fire vote changes — last write wins, single vote per voter
73. Vote at the exact instant of close — deterministic ordering
74. Voter who joined but never connected WS — not counted as active
75. Voter disconnect/reconnect with cookie restores vote

### Cluster awareness on close (76-78)
76. Single-vote-per-IP: no cluster warning
77. Two voters same IP: cluster appears in results
78. Cluster info contains only an opaque hash — no raw IP leak

### Reset / cookie cleanup (79-82)
79. After reset, old admin cookie does not auto-claim new admin slot
80. Server broadcasts `reset` event before closing sockets
81. Reset clears IP join counter
82. Voter cookie from previous session cannot vote in new session

### Security headers / CSP (83-86)
83. CSP present, strict; no `'unsafe-inline'` for styles
84. `X-Frame-Options: DENY` set
85. `X-Content-Type-Options: nosniff` set
86. `Referrer-Policy: no-referrer` set

### Atomic persistence (87-89)
87. `state.json` never appears partial — `.tmp + rename` pattern works
88. No `.tmp` leftovers after successful write
89. `archive.json` round-trips through server restart

### Connection / origin / WS abuse (90-93)
90. WS upgrade with malformed Origin URL → 403
91. WS upgrade with empty Origin (curl-style) allowed (non-browser client)
92. 20 connect/disconnect cycles do not leak memory/connections
93. `hello` message contains current state immediately on connect

### Functional UX edges (94-97)
94. Admin can lock then unlock the room
95. Admin changes photo count before any votes → no confirmation prompt
96. After voting closes, admin can still lock the room
97. Voter who joined but never voted → 0 votes in results

### Exotic input (98-100)
98. Vote photoNumber as boolean → rejected
99. Vote photoNumber as array → rejected
100. Vote photoNumber as scientific notation (1e0) — accepted as 1

## The honest VPN/incognito answer

**VPN:** for the LAN-only deployment DUPS uses, VPNs are a non-issue — the
QR encodes a LAN IP (`http://192.168.1.5:3000/...`). If a voter is on a VPN,
they can't reach the LAN at all. For an internet-deployed version, VPN
detection without paid third-party services (IPQualityScore, MaxMind) is
unreliable and easy to circumvent with residential proxies. The right
defense at that point is per-member credentials, which we don't have.

**Incognito mode:** five layers in v3:
1. Per-IP voter join cap (3) catches a single attacker spawning multiple
   voter cookies — they all share the attacker's IP.
2. Single-redemption join tokens — photo-of-the-projector attack now needs
   a fresh QR scan each time.
3. Admin "Rotate QR" button invalidates outstanding tokens on demand.
4. "Lock room" button stops all new joins.
5. IP cluster warning at tally time — admin sees if any network produced
   multiple voter ids. This is informational; admin decides what to do.

Layers 1+2+3+4 are automatic. Layer 5 surfaces what the admin should review.
True 1-member-1-vote still requires per-member credentials — that's the
last 1% gap, and the architecture supports adding it without rewrites.

---

# Round 3: v3 → v4 (public-internet model)

The voting app turned out to be a remote-use application, not LAN-only. That
is a fundamentally different threat model and several v3 defenses had to be
re-examined.

## What v3 got wrong for public-internet use

- **Auto-detected LAN IPs in the QR URL.** Pointed voters at unreachable
  private addresses if accessed via internet.
- **Origin allow-list included LAN IPs.** Wrong shape entirely — needed to
  be a configured single public origin.
- **Per-IP voter join cap of 3.** Reasonable on LAN where each phone is
  one household. Catastrophic for public-internet voters where most mobile
  carriers route everyone through CGNAT and corporate offices/schools NAT
  hundreds of users through one IP. Would silently block real voters.
- **Boot banner instructed sharing LAN IPs.** Misleading for the new use.
- **No HSTS.** Acceptable on LAN but unsafe over the public internet.
- **CSP `connect-src` allowed any `ws:` or `wss:`.** Too permissive for
  production deployment; should lock to the configured origin.

## v4 changes

- **`PUBLIC_URL` environment variable** drives QR URL and Origin allow-list.
  In dev mode (unset), only localhost variants are allowed.
- **Per-IP voter cap removed.** Replaced by:
  - Single-redemption join tokens (from v3, retained)
  - Admin "Rotate QR" to invalidate outstanding tokens (from v3, retained)
  - "Lock Room" admin button (from v2, retained)
  - IP-cluster warnings at tally time (informational only)
- **`TRUST_PROXY` env var** for behind-reverse-proxy deployment. Default
  `loopback` honors X-Forwarded-* only from local proxies.
- **HSTS** added when `PUBLIC_URL` is `https://`. Absent on plain HTTP to
  avoid trapping development.
- **CSP `connect-src` locked** to the configured WSS origin in production.
- **Cookies always Secure** when `PUBLIC_URL` is HTTPS, even if X-Forwarded-Proto
  is spoofed (defense-in-depth against misconfigured proxy).
- **CSP opens fonts.googleapis.com and fonts.gstatic.com** so the design
  pass can use Google Fonts without further config (the primary mechanism
  for cross-platform visual consistency).
- **Boot banner** rewritten — no LAN IP suggestions, clear warning if
  PUBLIC_URL is plain HTTP and not in dev mode.

## Threat model — restated honestly for public internet

Defends against:

- Random network observers, cross-site attackers (HTTPS, HSTS, signed
  cookies, Origin lockdown, CSRF custom header)
- Accidental double-voting from refresh, multiple tabs, phone sleep
- Replay of QR-photo attacks (single-redemption jti + Rotate QR)
- Malformed / oversized / flood traffic (payload cap, rate limit, IP
  connection cap, heartbeat)
- Server crash during a vote (atomic disk persistence)
- Voters trying to act as admin
- Cross-site WebSocket hijacking (production Origin lockdown)
- Forged/tampered cookies and tokens (HMAC verification)
- Misconfigured reverse proxy leaking spoofed scheme/host into QR URL

Does NOT defend against:

- **A determined cheater on multiple separate devices on different networks.**
  Without per-member credentials, no app can fully prevent this. The available
  mitigations: Live joined-vs-voted counts, "Lock Room" button, "Rotate QR"
  button, IP-cluster warning at tally time.

If DUPS later wants stricter 1-member-1-vote, the right extension is per-member
credentials. The architecture supports adding it without rewrites.

## Round-3 scenario catalogue (50 sims, see test/round3.js)

### PUBLIC_URL enforcement (101-108)
101. Dev mode: WS Origin matching configured PUBLIC_URL allowed
102. Prod: WS Origin matching PUBLIC_URL allowed
103. Prod: wrong host → 403
104. Prod: wrong scheme (http vs https) → 403
105. Prod: wrong port → 403
106. Prod: QR URL derived from PUBLIC_URL, NOT request Host header
107. Prod: invalid PUBLIC_URL crashes on boot
108. Dev mode: localhost Origin allowed

### HSTS and Secure cookies (109-113)
109. HSTS header present when PUBLIC_URL is https
110. HSTS absent in dev mode
111. HSTS absent when PUBLIC_URL is plain http
112. Prod HTTPS: cookies always Secure regardless of request headers
113. CSP connect-src locked to configured origin in production

### Trust-proxy boundaries (114-119)
114. X-Forwarded-For honored from loopback (default)
115. X-Forwarded-Proto=https from loopback sets Secure cookie
116. TRUST_PROXY=false: X-Forwarded-Proto ignored
117. TRUST_PROXY=1: single proxy hop honored
118. Spoofed X-Forwarded-Host does NOT affect QR URL
119. Spoofed X-Forwarded-Proto=http in prod-HTTPS still gives Secure cookie

### Carrier-NAT / corporate realities (120-125)
120. No ceiling on simultaneous joiners from one IP (12 joins succeed)
121. WS connection cap (8/IP) still enforces against DoS
122. Cluster info surfaces when many real voters share an IP
123. Cluster warning is informational — votes NOT removed
124. Lock Room remains primary live anti-dupe tool
125. Rotate QR remains secondary anti-dupe

### Cross-platform expectations (126-132)
126. apple-mobile-web-app-capable + mobile-web-app-capable both present
127. viewport-fit=cover + interactive-widget=resizes-content
128. Google Fonts preconnect hints
129. CSP allows Google Fonts stylesheet + font fetches
130. format-detection suppresses iOS auto-linking
131. vote-input has inputmode=numeric + enterkeyhint=send
132. color-scheme meta = dark

### Adversarial public-internet edges (133-140)
133. Long QR URL stays under 2KB
134. PUBLIC_URL trailing slash normalized
135. Joining works even when transport is plain http behind https-terminator
136. Reset-session over HTTPS production: voter sockets get 4000 close
137. Production: CSRF still required on POSTs
138. Production: forged join token from another instance rejected
139. Production: voter cookie from another deployment rejected
140. Production: 200 connect/disconnect cycles do not leak

### Cross-platform pixel parity (141-145)
141. vote-input type=number + pattern=[0-9]*
142. photo-count-input also numeric-keypad-hinted
143. Hero image referrerpolicy=no-referrer
144. CSP allows dups.club hero image source
145. autocomplete=off on number inputs (no Chrome credit-card popup)

### Final regression / E2E (146-150)
146. Full end-to-end in production HTTPS mode
147. State persists across restart in production
148. State survives PUBLIC_URL change (secret unchanged)
149. Voter cookies survive PUBLIC_URL change
150. Full E2E with cluster warning visible to admin

## What deployment ought to look like

```
Internet ──► Reverse proxy (nginx / Caddy / Cloudflare / Render / Fly)
              │
              ├─ TLS termination (Let's Encrypt or platform-managed)
              ├─ Adds: X-Forwarded-Proto: https
              └─ Forwards to ──► Node server on :3000
                                  PUBLIC_URL=https://vote.dups.club
                                  TRUST_PROXY=loopback (or 1)
```
