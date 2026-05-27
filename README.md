# DUPS Photo Contest Voting (v5)

Real-time photo-contest voting for the Dallas Underwater Photography Society.
Voters connect remotely from phones, tablets, or laptops over the public
internet. The meeting host runs the contest from a laptop and projects the
QR code and live results.

**This README is for the person hosting the application** — the deployer.
For the person running a contest meeting, see **`ADMIN-GUIDE.md`**.
For voters, see **`VOTER-GUIDE.md`** (a one-page hand-out).

---

## What this is, in one paragraph

You host a small Node web server somewhere reachable on the internet (a
VPS, your own desktop with a tunnel, or a one-click platform like Render
or Fly). At each monthly meeting, the contest host opens the URL, claims
the Administrator role, sets how many photos are in the vote, and projects
the QR code. Members scan the QR with their phones, type the number of
their favorite photo, and tap Submit. When voting closes, the projector
shows ranked results with the winner highlighted. Everything is real-time;
no one has to refresh anything.

---

## Table of contents

- [Requirements](#requirements)
- [Quick start (local test)](#quick-start-local-test)
- [Production deployment](#production-deployment)
  - [Option A: One-click cloud platform (easiest)](#option-a-one-click-cloud-platform-easiest)
  - [Option B: VPS with a reverse proxy (cheapest at scale)](#option-b-vps-with-a-reverse-proxy-cheapest-at-scale)
  - [Option C: Your own machine + Cloudflare Tunnel (zero-cost)](#option-c-your-own-machine--cloudflare-tunnel-zero-cost)
- [Environment variables](#environment-variables)
- [Updating the app](#updating-the-app)
- [Backing up and rotating secrets](#backing-up-and-rotating-secrets)
- [Troubleshooting](#troubleshooting)
- [Tests](#tests)
- [Threat model](#threat-model)
- [File layout](#file-layout)
- [License](#license)

---

## Requirements

- **Node.js 18 or newer** (`node -v` should print v18.x or higher).
- Roughly 50 MB of disk (the app + Node dependencies).
- A way to reach the server over HTTPS from the public internet. See
  deployment options below.

That's it. There is no database, no Redis, no message queue. All state
lives in a single JSON file in the `data/` directory.

---

## Quick start (local test)

Run it on your own laptop just to see it working. No hosting required for
this test:

```bash
# 1. Get the code
unzip dups-voting.zip
cd dups-voting

# 2. Install dependencies (downloads a few small Node packages)
npm install

# 3. Start the server
npm start
```

You'll see:

```
DUPS Photo Contest server (hardened v5 — public-internet model)
  Listening:  http://0.0.0.0:3000
  Data dir:   /path/to/dups-voting/data
  Trust:      loopback
  Public URL: (none — running in DEV mode against this host)
  Set PUBLIC_URL=https://your.domain.com before production use.
```

Open `http://localhost:3000` in your browser. You'll see the splash screen.
To test voting, open the same URL in a second browser window (or in
incognito mode) — one window claims Administrator, the other can scan/visit
the QR URL to join as Voter.

This works for a sanity check but is **not suitable for a real meeting** —
voters can't reach `localhost:3000` from their phones. For that you need
real hosting. Read on.

---

## Production deployment

You have three reasonable paths, listed from easiest to most hands-on.
Pick one.

### Option A: One-click cloud platform (easiest)

Recommended for non-sysadmins. Render, Fly.io, and Railway all let you
push the code and get an HTTPS URL in 5 minutes. No reverse-proxy setup,
no TLS certificates to manage.

**Example: Render.com (free tier works for the meeting frequency this app
is designed for):**

1. Push the unzipped folder to a Git repository (GitHub, GitLab — your choice).
2. Create a Render account, click "New" → "Web Service".
3. Connect your repository.
4. Configure:
   - **Build command**: `npm install`
   - **Start command**: `npm start`
   - **Environment variables** (in the Render dashboard, "Environment" tab):
     - `PUBLIC_URL` = the URL Render assigns you (something like
       `https://dups-voting.onrender.com`)
     - `TRUST_PROXY` = `1`
5. Click "Create Web Service". Wait ~2 minutes for the first build.
6. Visit your URL. The splash screen should appear.

Fly.io and Railway work the same way; the dashboard names are different but
the two environment variables are the same.

**Cost**: free tier is plenty for monthly meetings. The free tier on Render
spins down after 15 minutes of inactivity, which means the first person to
visit before the meeting will see a 30-second "loading" delay while it
spins back up. Tell the meeting host to open the URL 5 minutes early.

### Option B: VPS with a reverse proxy (cheapest at scale)

If you already have a Linux server somewhere (DigitalOcean, Linode, AWS
Lightsail, a Raspberry Pi behind your router), this is the leanest path.

**Step 1**: Install Node 18+ on the server.

**Step 2**: Get a domain pointing at the server's public IP. Free options:
DuckDNS, a free Cloudflare-managed subdomain.

**Step 3**: Install Caddy (the easiest reverse proxy — it handles HTTPS
automatically). Create `/etc/caddy/Caddyfile`:

```caddy
vote.your-domain.com {
    encode gzip
    reverse_proxy localhost:3000
}
```

**Step 4**: Copy the unzipped app to `/opt/dups-voting/` (or wherever). Run:

```bash
cd /opt/dups-voting
npm install
PUBLIC_URL=https://vote.your-domain.com TRUST_PROXY=loopback npm start
```

Caddy will fetch a free Let's Encrypt TLS certificate the first time it
proxies a request — no manual steps.

**Step 5**: Make it survive reboots. The simplest way is a systemd unit.
Create `/etc/systemd/system/dups-voting.service`:

```ini
[Unit]
Description=DUPS Photo Contest Voting
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/dups-voting
Environment="PUBLIC_URL=https://vote.your-domain.com"
Environment="TRUST_PROXY=loopback"
Environment="PORT=3000"
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Then `sudo systemctl enable --now dups-voting`. Logs go to journald
(`journalctl -u dups-voting -f`).

**nginx alternative**: If you prefer nginx, use this server block instead
of the Caddyfile. You'll need to handle the TLS certificate yourself
(`certbot` from Let's Encrypt is standard).

```nginx
server {
    server_name vote.your-domain.com;
    listen 443 ssl http2;
    # ssl_certificate /etc/letsencrypt/live/.../fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/.../privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

The `proxy_set_header Upgrade` and `Connection "upgrade"` lines are
essential — without them, the real-time WebSocket connection won't work
and live counts won't update.

### Option C: Your own machine + Cloudflare Tunnel (zero-cost)

If you want to host on a laptop or home machine without opening firewall
ports, Cloudflare Tunnel gives you a public HTTPS URL pointing at
`localhost:3000` for free.

1. `npm install && npm start` (with `PUBLIC_URL` and `TRUST_PROXY=1` set
   to the tunnel URL once you have it).
2. Install `cloudflared` from cloudflare.com/products/tunnel.
3. `cloudflared tunnel --url http://localhost:3000`.
4. Cloudflare prints a public `https://xyz.trycloudflare.com` URL.
5. Stop the Node server, set `PUBLIC_URL=https://xyz.trycloudflare.com`,
   restart.

The tunnel URL is temporary — fine for a one-off meeting, less convenient
for a recurring monthly schedule. For a permanent setup, register a free
named tunnel through your Cloudflare dashboard.

---

## Environment variables

| Variable          | Default               | What it does |
|-------------------|-----------------------|--------------|
| `PUBLIC_URL`      | (none)                | The canonical URL voters reach. Used to build the QR code and lock down which origins can connect. **Required for production.** |
| `PORT`            | `3000`                | Which port the Node server listens on. Change if 3000 is in use. |
| `TRUST_PROXY`     | `loopback`            | How much to trust `X-Forwarded-*` headers. Use `1` if behind exactly one reverse proxy (the common case). Use `false` to disable. Use a CIDR string like `10.0.0.0/8` for a specific proxy network. |
| `DEV_MODE`        | (off)                 | Set to `1` to suppress the no-HTTPS warning during local development. Leave unset in production. |
| `DUPS_DATA_DIR`   | `./data`              | Where state.json, archive.json, and the HMAC secret are stored. Use a persistent path on platforms with ephemeral filesystems. |

**The PUBLIC_URL must be exactly what voters will reach.** If voters reach
`https://vote.dups.club` but `PUBLIC_URL=http://vote.dups.club`, all
WebSocket connections will be rejected. If voters reach the apex domain
but `PUBLIC_URL` says `www.`, same problem.

---

## Updating the app

When a new version of the code arrives:

```bash
cd /path/to/dups-voting
# Stop the server (Ctrl-C, or `sudo systemctl stop dups-voting`)
# Copy the new files into the same directory, OVERWRITING existing ones
# But DO NOT delete the `data/` directory — it holds the HMAC secret and archive

npm install   # in case dependencies changed
# Restart the server
```

The `data/secret` file is a random 32-byte HMAC key generated on first boot.
**Do not delete it across updates.** If you delete it, all live admin and
voter cookies become invalid (they fail signature verification). Mid-meeting,
this would kick everyone out. Between meetings it's harmless.

---

## Backing up and rotating secrets

The only things worth backing up:

- `data/archive.json` — accumulated tally history of past contests
- `data/secret` — the HMAC key

A nightly `cp data/*.json elsewhere/` is sufficient. The `state.json` file
is the *current* in-progress session and is regenerated on every reset.

**Rotating the secret**: Stop the server, delete `data/secret`, restart.
A new secret is generated. All previously-issued cookies are invalidated.
Do this if you suspect compromise, or just routinely once a year.

---

## Troubleshooting

### The server prints a "WARNING: PUBLIC_URL is plain http" message

You set `PUBLIC_URL=http://...` instead of `https://`. Voter cookies will
not have the `Secure` flag, which on the public internet is a real
problem. Either set up TLS (see deployment options) or, if this really is
just a local dev test, set `DEV_MODE=1` to silence the warning.

### Voters see "Could not reach the server" or the page won't load

Check, in order:
1. Is the server actually running? `curl https://your-public-url/` should
   return HTML.
2. Does `PUBLIC_URL` match the URL voters are typing? Exact scheme + host
   + port match is required.
3. If you're behind a reverse proxy, are the `proxy_set_header Upgrade`
   and `Connection "upgrade"` lines present? Without them, WebSocket fails
   and the page loads but counts don't update.

### Live counts don't update; voters' votes don't seem to register

The WebSocket connection is being dropped. Most common cause: reverse
proxy not configured to forward WebSocket upgrades (Caddy does this by
default; nginx requires the two `proxy_set_header` lines shown earlier).
Second most common cause: a corporate firewall between voters and the
server is stripping WebSocket connections (rare on public hosting).

Open the browser's developer console on a voter device. If you see
"WebSocket connection failed", the upgrade is being blocked.

### "Security check failed. Please reload."

This is the CSRF defense firing. It means the `X-DUPS-Origin: same-site`
header didn't reach the server. Almost always caused by a proxy stripping
custom headers. Check your reverse-proxy config; the standard configs
above pass headers through correctly.

### Admin slot is "taken" but I'm the only one

Some previous admin session is holding the slot. Either:
- Wait for the previous admin's cookie to expire (6 hours), or
- Stop the server, delete `data/state.json` (NOT `data/secret`), restart.
  This wipes the current session but preserves cookie keys and the
  archive. The next person to claim Administrator gets the slot.

### The QR code points at "localhost" or my private IP

You're missing the `PUBLIC_URL` env var. Set it to the public HTTPS URL.

### I want to wipe everything and start fresh

```bash
# Stop the server
rm -rf data/
# Start the server. A new secret will be generated. Archive is gone.
```

### Logs

The server logs to stdout as JSON, one event per line. Useful events to
grep for:

```
{"event":"boot"}            # server started
{"event":"admin_claimed"}   # someone became Administrator
{"event":"voter_joined"}    # a voter scanned the QR
{"event":"vote_recorded"}   # a vote came in (with vid + photo number)
{"event":"voting_closed"}   # admin counted votes
{"event":"session_reset"}   # admin started a new session
{"event":"voter_join_jti_replay"}  # someone tried to reuse a QR scan
{"event":"ws_reject"}       # WebSocket upgrade refused (Origin / IP cap)
{"event":"ws_rate_limit"}   # too many messages from one connection
```

If the deployment uses systemd, follow logs with
`journalctl -u dups-voting -f`.

---

## Tests

```bash
npm test
```

This runs:

- **214 unit tests** that execute pure logic, HTML/JS contract checks, and
  endpoint behavior with stubs. These pass even on a barebones machine.
- **150 integration simulations** that spawn the server and exercise it
  with real HTTP and WebSocket traffic — auth races, role escape, input
  fuzzing, DoS vectors, replay attacks, persistence, CSRF, single-redemption
  tokens, cluster awareness, cross-platform meta hooks, and 150 more scenarios.

See `REDTEAM.md` for the full catalogue of attacks the suite covers.

---

## Threat model

### Defends against

- Random network observers and cross-site attackers (HTTPS, HSTS, signed
  cookies, Origin lockdown, CSRF custom header)
- Accidental double-voting from refresh, multiple tabs, phone sleep,
  network flapping (cookie-bound voter identity, idempotent re-join)
- Replay of QR-photo attacks (single-redemption tokens + Rotate QR)
- Mass dupe-voting by one person across multiple incognito windows
  (Rotate QR + Lock Room + cluster warnings — see ADMIN-GUIDE for usage)
- Malformed / oversized / flooded traffic (payload cap, rate limit, IP
  connection cap, heartbeat)
- Server crash during a vote (atomic disk persistence)
- Voters trying to act as admin (server-side cookie check, ignores all
  message claims)
- Stale cookies after admin reset (session id rotation + sentinel)
- Forged/tampered cookies (HMAC verification, constant-time compare)
- Forged join tokens (HMAC verification of signed jti)
- Cross-site WebSocket hijacking (Origin lockdown at upgrade)
- Misconfigured reverse proxy spoofing scheme/host into the QR URL

### Does NOT defend against (honest limitations)

**A determined cheater with multiple separate devices on different networks.**
Without per-member credentials (an email list or membership database), no
app can fully prevent this. The available mitigations:

- Live joined-vs-voted counts visible on the admin's projector
- **Lock Room** button — freezes the voter list after a few minutes
- **Rotate QR** button — invalidates outstanding join tokens on demand
- **IP-cluster warning** at tally time — admin sees if any network produced
  multiple votes (often legitimate from carrier NAT or shared WiFi, but
  worth a glance)

If DUPS later wants strict 1-member-1-vote, the right extension is per-member
credentials. The current architecture supports adding that cleanly.

---

## File layout

```
dups-voting/
├── server.js              # backend, ~850 lines, no DB
├── package.json           # express, ws, qrcode, cookie-parser
├── public/
│   ├── index.html         # 7 screens (splash, admin x3, voter x3, error)
│   ├── app.js             # client state machine + WebSocket + auto-reconnect
│   └── style.css          # design-pass-integrated editorial styling
├── test/
│   ├── unit-pure.js       # 86 standalone tests (no npm install required)
│   ├── unit-contracts.js  # 110 HTML/JS-contract tests
│   ├── unit-behavior.js   # 18 endpoint-stub tests
│   ├── harness.js         # integration test infrastructure
│   ├── round1.js          # integration sims 1-50
│   ├── round2.js          # integration sims 51-100
│   ├── round3.js          # integration sims 101-150
│   └── run-sims.js        # top-level runner
├── data/                  # auto-created (state.json, archive.json, secret)
├── README.md              # ← you are here (deployer documentation)
├── ADMIN-GUIDE.md         # for the meeting host
├── VOTER-GUIDE.md         # for voters (one-page handout)
├── AUDIT.md               # all audit findings v1 → v5
└── REDTEAM.md             # all 150 simulated attacks documented
```

---

## License

MIT-ish. Use it.
