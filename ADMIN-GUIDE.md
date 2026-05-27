# DUPS Photo Contest — Administrator Guide

This guide is for the person running a contest meeting. You don't need to
know anything about servers or code. You just need:

- A laptop with a web browser (Chrome, Firefox, Safari, or Edge)
- A projector or large display the laptop can connect to
- The URL of the voting app (something like `https://vote.dups.club` — your
  deployer will give you this)

If you're also the deployer (the person who hosts the app), see `README.md`
for setup. This guide assumes the app is already running somewhere reachable.

---

## Table of contents

- [Before the meeting](#before-the-meeting)
- [Starting a contest](#starting-a-contest)
- [During voting](#during-voting)
- [Counting votes and showing results](#counting-votes-and-showing-results)
- [Starting another contest (multiple votes per meeting)](#starting-another-contest-multiple-votes-per-meeting)
- [Saving the archive](#saving-the-archive)
- [Every button explained](#every-button-explained)
- [Troubleshooting on the day](#troubleshooting-on-the-day)
- [FAQ](#faq)

---

## Before the meeting

**The day before** (or any time earlier):

1. Open the voting URL in your laptop's browser. You should see the DUPS
   splash screen with a hero image and two options: Administrator, Voter.
   If you don't see this, ask the deployer to check that the server is
   running.
2. **Don't click anything yet.** Just confirm the page loads.
3. Close the browser tab.

**The day of the meeting, 10 minutes before voting**:

1. Plug your laptop into the projector. Make sure the laptop's screen is
   being mirrored or extended to the projector.
2. Open the voting URL in a fresh browser tab. Put that tab in fullscreen
   (F11 on Windows/Linux, Cmd-Ctrl-F on Mac) once you're past the splash.
3. Have a printed copy of `VOTER-GUIDE.md` handy in case anyone asks how
   to vote.

---

## Starting a contest

### Step 1: Claim the Administrator role

On the splash screen, select **Administrator** and click **Continue**.

> If you see "The Administrator role is already taken," someone else (or a
> previous session of yours) is holding the slot. See [Troubleshooting](#troubleshooting-on-the-day).

### Step 2: Set the number of photos

You'll see a screen asking "How many photos in this Vote?" Type the number
and click **Set**.

A confirmation card appears showing your number. You have two buttons:

- **Change** — go back and pick a different number
- **Confirm & Open Voting** — click this when you're sure

Once you confirm, voting is open and the QR screen appears.

> Photo numbers run 1 through X. Tell your members "Photo number 1 is the
> first one I'll show," or however you're presenting them.

### Step 3: Project the QR code

The screen now shows:

- A large QR code that voters scan
- The URL beneath it (in case anyone wants to type it instead of scanning)
- Three live counters: **Joined**, **Active**, **Voted**
- Two buttons: **Rotate QR**, **Lock room**
- A red **Count Votes Now** button at the bottom

**Project this screen.** This is what the room sees while voting is open.

### Step 4: Walk members through their first vote (optional, for the first meeting)

If this is your club's first time using the app:

1. Ask everyone to scan the QR code with their phone camera (it'll open
   their browser automatically).
2. They tap their phone screen to confirm joining.
3. They wait until you start showing photos. The phone screen says
   "Cast Your Vote — Choose a photo from 1 to X."
4. Type the number of their favorite. Tap Submit. Done.

After the first meeting, everyone knows the routine and you don't need
this walkthrough.

---

## During voting

### What you'll see on the projector

- **Joined** count goes up as people scan the QR
- **Active** is how many are currently connected (someone closing the
  browser drops this count but their vote is preserved)
- **Voted** is how many have submitted at least one vote

Voters can change their vote until you close voting. The Voted count is
"how many distinct voters have voted," not "how many submit clicks have
happened."

### Showing the photos

The app does not display the photos themselves. You show them however you
already do — slideshow on the same projector (you'll need to switch the
browser tab away and back), printed copies, a separate physical display,
etc. The app only collects numerical votes.

### Common things that happen

- **Someone scans late** — they can join any time before you close voting
  or lock the room.
- **Someone changes their mind** — they re-type a different number and tap
  Submit again. Only their most recent vote counts.
- **Someone's phone goes to sleep** — when they wake it, the app reconnects
  automatically. Their vote is preserved.
- **Someone leaves the building** — their Active count drops, but their
  vote stays.

---

## Counting votes and showing results

When all photos have been shown and everyone has had a chance to vote:

### Step 1: Click **Count Votes Now**

A confirmation dialog asks "Close voting and tally results now?" Click OK.

> **This is final within this session.** You cannot reopen voting for the
> same set of photos. If you click this by accident, see Troubleshooting.

### Step 2: Look at the results

The projector now shows:

- The total vote count at the top
- A ranked table — #1 photo first, descending order, with a brass-accented
  podium row for the winner
- A proportional bar showing how much of the lead the #1 photo had
- Optionally: an amber **Review** callout if multiple votes came from the
  same network (often legitimate; see [Every button explained](#every-button-explained))

Members see "Voting Closed. Your final vote: N" on their phones.

### Step 3: Announce the winner

The app doesn't broadcast a winner message. You read it off the projector
and announce it in the room.

---

## Starting another contest (multiple votes per meeting)

Some meetings have multiple categories (Novice, Advanced, Best in Show).
Each is its own vote.

After showing the results of the first contest:

1. Click **Start New Session** at the bottom of the results screen.
2. A confirmation dialog appears. Click OK.
3. The current vote is **archived** automatically (saved to disk for later).
4. You're back at the splash screen.
5. Repeat the contest flow for the next category.

> Members will see their phones reset to "Waiting for the Administrator…"
> They don't have to scan a new QR — when you set the next photo count and
> open voting, their existing connection picks up automatically. They will
> need to vote again, because the previous session's votes don't carry over.

---

## Saving the archive

After the last contest of the meeting, before closing your laptop:

1. On the final results screen, click **Download archive (JSON)**.
2. Your browser saves a file named like `dups-archive-2026-05-24.json`.
3. Stash it somewhere safe — the club's shared drive, your email, wherever.

This file contains every contest you've ever run on this server (or since
the last time the deployer wiped the data directory). Open it in any text
editor to see the photo counts, vote tallies, and timestamps.

---

## Every button explained

### Splash screen

| Button | What it does |
|--------|--------------|
| **Administrator** | Claim the Administrator role for this session. Only one person can hold this at a time. |
| **Voter** | Become a voter for the current session. You'd normally not do this on the admin laptop. |
| **Continue** | Proceed with whichever role you picked. |

### Admin setup screen

| Button | What it does |
|--------|--------------|
| **Set** | Confirm the photo count you typed. Brings up the confirmation card. |
| **Change** | Go back and enter a different number. |
| **Confirm & Open Voting** | Lock in the count and open voting. After this, the QR appears. |

### Admin voting screen (the projected one)

| Button | What it does |
|--------|--------------|
| **Rotate QR** | Generate a fresh QR code and invalidate the old one. Use this if you suspect someone took a photo of the projector and is sharing it externally. Members already in the room who have already joined are NOT kicked out — they continue voting normally. Anyone holding a screenshot of the old QR finds it dead. |
| **Lock room** | Stop allowing new voters to join. Existing voters keep voting normally. Use this once everyone in the room has scanned in, to prevent anyone joining late from outside. Click again to unlock. |
| **Count Votes Now** | Close voting and tally results. **Final for this session.** Confirms with a dialog before doing it. |

### Admin results screen

| Button | What it does |
|--------|--------------|
| **Download archive (JSON)** | Save the entire vote history of the server as a downloaded file. |
| **Start New Session** | Archive the current results, clear everything, return to the splash screen, and disconnect all voters (their phones gracefully reset to the waiting screen). Use this between contests in the same meeting. |

### What the **Review** card means (cluster warning)

After tallying, you might see an amber-toned card above the results table
that says something like:

> *Review: 2 networks produced multiple votes (5 votes total). This is
> often legitimate — mobile carriers, offices, and households commonly
> route many people through one address — but worth a glance.*

This is informational only. The votes are still counted. The app noticed
that some voters' devices appeared to come from the same network address.
Common reasons:

- Two family members in the same household, both on home WiFi
- A few people sharing a hotspot
- Many people on a mobile carrier (Verizon, T-Mobile, etc.) which routes
  thousands of phones through one IP — this is called "CGNAT" and is very
  common today
- A school, office, or hotel WiFi
- Someone genuinely voting twice from two devices (rare)

**The app does not automatically remove these votes.** It's up to your
judgment. If you know the room, you'll usually know the explanation. If
something looks fishy and you have the option to do so, you can click
**Start New Session** to discard the result and re-run the vote with
**Lock Room** enabled earlier. But in most meetings you simply ignore the
warning and announce the winner.

---

## Troubleshooting on the day

### "The Administrator role is already taken"

A previous admin session is still holding the slot. Either:

- **Easy fix**: refresh your browser. If your laptop was the previous admin,
  your cookie is still valid and refreshing will resume your session.
- **If it's still taken after refresh**: someone else in the past 6 hours
  claimed admin from a different browser. Contact your deployer to wipe
  the current session (`rm data/state.json` and restart the server).

### Voters say "Could not reach the server"

Most likely the server isn't running. Try the URL yourself from your
laptop — if you also see an error, contact the deployer. If you see the
splash screen but voters don't, ask them what they're seeing exactly.

### Voters can scan the QR but their votes never register

Live counts not updating? The real-time WebSocket connection isn't
working. Try refreshing the admin page. If that doesn't help, contact the
deployer — they need to check the reverse-proxy configuration.

### Someone says "This QR code has already been used"

They scanned a QR code that has since been rotated, OR they scanned an
old screenshot. Show them the current QR on the projector and have them
scan it fresh.

### I accidentally clicked "Count Votes Now" too early

The current session's voting is closed and you can't reopen it. But you
can:

1. Click **Start New Session**.
2. Set up the same photo count again.
3. Have members re-scan and re-vote.

The previous (premature) results are archived but you can ignore them.
Members' phones will reset automatically.

### Someone says they can't change their vote

Voting may have closed. If you haven't clicked Count Votes Now, ask them
to refresh their phone. If they were briefly disconnected (subway tunnel,
elevator, etc.) the auto-reconnect normally restores their state, but a
hard refresh always works.

### The laptop loses internet mid-vote

If the laptop reconnects within ~60 seconds, the meeting continues without
issue — voters are still connected to the server, you're just temporarily
disconnected from observing.

If the server itself goes down, the votes already submitted are saved to
disk and restored when it comes back up. Worst case: ask the deployer how
long until the server is back, and resume.

### I want to start completely over

Click **Start New Session** at any point (even before counting votes —
the confirmation dialog warns that the current vote will be discarded).

---

## FAQ

**Can voters be at home or somewhere else, not in the meeting room?**
Yes. The app is designed for remote voting. Anyone with the meeting's QR
URL can vote.

**Can the same person vote twice from different devices?**
Honestly, yes, if they're determined enough. The app makes it hard but
not impossible — see the threat-model discussion in `README.md` if you
want details. For typical DUPS use, the live counters, Lock Room button,
and Rotate QR button are sufficient deterrents.

**What if someone forwards the QR link to a non-member?**
The non-member can vote. The app has no concept of membership. If this
becomes an issue, use Lock Room once everyone is in the room. For
stronger control, the deployer can add per-member credentials in a
future version.

**Can I run two contests at the same time?**
Not on one server instance. One Administrator, one current vote. If you
need parallel contests (very unusual), the deployer would need to run
multiple instances of the app on different URLs.

**How many voters can the app handle?**
Comfortably hundreds. Well into the thousands with adequate hosting.
Not the limit you'll hit first.

**What happens to my vote if my phone dies mid-meeting?**
Vote is saved server-side as soon as you tap Submit. If your phone dies
after submitting, your vote still counts. If your phone dies before
submitting, no vote was recorded.

**Can I see how individual people voted?**
No. The app intentionally doesn't link votes to identities. Members are
anonymous to the system; only an opaque per-device cookie is used to
prevent double-voting from the same device.

**Do I need to ask for permission to enable cookies?**
No. The app uses a single cookie strictly for session identity, which
under most privacy laws is exempt from consent requirements. There are no
tracking cookies, no third-party scripts, no analytics.

**Can I edit results after they're shown?**
No. Once voting is closed and tallied, the result is final. You can
archive it and start a new session, but you can't modify the numbers.
This is intentional — it's a vote, not a draft.

**What if there's a tie?**
The lower photo number wins the tie. (Photo 3 beats Photo 7 if both have
the same count.) This is deterministic so everyone sees the same result.
Announce the tie and how you'd like to resolve it in the room.

**Can I save the cluster-warning details?**
The downloaded archive JSON includes everything — vote counts, photo
numbers, cluster info, timestamps.
