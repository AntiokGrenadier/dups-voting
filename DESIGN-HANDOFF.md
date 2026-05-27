# DUPS Photo Contest — Visual Redesign Handoff

The v5 visual design is in (editorial / oceanographic field journal, brass
accent, Cormorant Garamond + Inter + JetBrains Mono). If you ever want a
fresh aesthetic, this is the prompt that produced the current one — adapt
the "vibe" section for a different look and reuse the contract.

---

> Hey, I have a working real-time voting web app for the **Dallas Underwater
> Photography Society**'s monthly photo contest. The HTML, JavaScript, and
> server logic are done and locked. **I want you to focus ONLY on visual
> design** — rewrite `public/style.css` and only `public/style.css` (plus,
> if you need, add up to three `<link>` tags to `public/index.html` `<head>`
> for Google Fonts imports).
>
> ## The product
>
> Members vote on photo contest entries from their phones, tablets, or
> browsers, while the admin's screen shows the live tally and projects QR
> codes. **Voters connect remotely over the public internet** — there is
> no LAN aspect. The app must look and feel identical across iOS Safari,
> Android Chrome, desktop Chrome/Firefox/Safari/Edge.
>
> ## The vibe (THIS IS THE ONE TO CUSTOMIZE)
>
> Think **editorial / oceanographic field journal**. Deep, watery blues.
> Generous whitespace. One sharp accent color — pick one and commit (warm
> coral, brass, or signal-flag yellow). Refined typography — pick a pair
> from fonts.google.com like Cormorant Garamond + Inter, or DM Serif Display
> + DM Sans. Do NOT use system defaults, garish gradients, or generic "AI
> app" looks.
>
> ## Audience
>
> Hobbyist scuba-diving photographers, mostly age 40+. The interface has
> to read instantly without squinting. On the admin/projector view it has
> to look *presentable* — this is replacing a paper ballot, and the org
> takes the craft seriously.
>
> ## Hard constraints
>
> ### Cross-platform pixel parity (critical)
>
> The app MUST look identical on iOS Safari, Android Chrome, and desktop
> browsers. The HTML already includes the meta hooks; your CSS needs to
> honor them.
>
> 1. **Use `100svh` over `100vh`** for full-height layouts. `vh` includes
>    the iOS Safari address bar and causes jumpy resizes. `svh` (small
>    viewport units) is stable across all modern browsers.
> 2. **Reset `-webkit-tap-highlight-color: transparent`** on `html` or
>    `body`. Without it, iOS shows a grey flash on every tap. Define your
>    own `:active` states instead.
> 3. **Reset number-input spin buttons:** `input[type="number"]` must use
>    `appearance: none; -webkit-appearance: none;` and `::-webkit-inner-spin-button`
>    and `::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }`.
>    Otherwise iOS Safari shows up/down arrows that Chrome doesn't.
> 4. **`text-size-adjust: 100%`** on `html` (with `-webkit-` and `-ms-`
>    prefixes). Prevents iOS Safari from auto-enlarging text on landscape.
> 5. **`font-feature-settings: "tnum" 1`** on number elements (the vote
>    count, stat values, results table) so digits have uniform width.
>    Otherwise rendered counts can shift around as they update.
> 6. **`overscroll-behavior: none`** on `html` and `body`. Prevents
>    rubber-band scroll on iOS and pull-to-refresh on Android Chrome from
>    interfering with the voting UI.
> 7. **Input `font-size: 16px` minimum** on all `<input>` elements. iOS
>    Safari zooms when an input under 16px receives focus.
> 8. **Tap targets ≥ 48×48px.** Buttons, radios, the role-card option rows.
> 9. **`env(safe-area-inset-*)`** padding on the outermost container so
>    notch phones (iPhone X+) don't put content under the camera or home
>    indicator.
> 10. **Touch action `manipulation`** on all buttons and inputs.
>     `touch-action: manipulation` eliminates the 300ms tap delay on older
>     mobile browsers and prevents double-tap-zoom on buttons.
> 11. **Custom focus ring** that works on both pointer and keyboard.
>     `:focus-visible` for keyboard, suppress on `:focus:not(:focus-visible)`.
> 12. **Custom scrollbar handling**: don't style scrollbars heavily —
>     `::-webkit-scrollbar` looks different from Firefox's `scrollbar-color`,
>     and they affect layout differently. Prefer natural scrollbars.
> 13. **System fonts as fallback only.** Always import a Google Font with
>     `display=swap`. System font stacks render Roboto on Android and SF
>     on iOS, which look meaningfully different. Use the same imported font
>     on all platforms for true consistency.
> 14. **Prefer `rem` and `clamp()`** over fixed `px` for typography. A
>     `clamp(1rem, 0.9rem + 0.4vw, 1.25rem)` body size adapts gracefully
>     to phone, tablet, and projector.
> 15. **Reduced motion**: respect `@media (prefers-reduced-motion: reduce)`
>     — disable spinners, transition animations.
>
> ### Two viewports matter
>
> - **Phone (≤480px wide)** — voter screens. Vertical, big primary action.
> - **Tablet & desktop (480–1280px)** — voter screens at larger comfortable
>   sizes; admin screens at presentable density.
> - **Projector (≥1280px wide)** — admin screens, especially
>   `#screen-admin-voting` (QR display) and `#screen-admin-results` (the
>   tally). These should feel CINEMATIC at scale, not just stretched out.
>
> ### Other constraints
>
> 1. **Do not rename or remove any HTML id or class.** The JS hooks them.
>    Full list below.
> 2. **No JS, no animations beyond CSS.** The reduced-motion media query
>    is already in place; keep it.
> 3. **Use the hero image** at the top of splash screens. It's a real DUPS
>    member photo loaded from `dups.club`. Treat it like a magazine cover.
> 4. **Accent the `#1` results row.** Make it feel like a podium — gold
>    accent, slightly larger, presentation-grade. Class hook: `.first-place`.
>
> ## Screens (every one is a `<section class="screen">` in `index.html`)
>
> - `#screen-splash` — Hero image, DUPS title, subtitle "Photo Contest",
>   role-pick card (Administrator / Voter radios + Continue button)
> - `#screen-admin-setup` — Big input "How many photos in this Vote?",
>   then confirm card "You have selected: X / Change / Confirm & Open Voting"
> - `#screen-admin-voting` — Projected screen. Big QR code, the join URL
>   beneath, live counts (Joined / Active / Voted), two ghost buttons
>   ("Rotate QR", "Lock room") and the big red "Count Votes Now" button.
>   Uses `.projector-grid > .qr-card + .projector-side > .stats-card + .actions-card`
>   layout.
> - `#screen-admin-results` — Ranked table with #1 row styled as a podium.
>   May show an amber-toned **cluster-warning card** (`#cluster-warning`,
>   class `.card.warning`) above the table with informational text about
>   IPs that produced multiple votes. Includes Download archive + Start
>   New Session. Table wrapped in `.results-wrap`.
> - `#screen-voter-wait` — Smaller hero + "Waiting for the Administrator…"
>   + spinner
> - `#screen-voter-vote` — Big number input, big Submit button, status
>   message area (`.status-text` flips `.ok` / `.error` classes)
> - `#screen-voter-closed` — "Voting Closed. Your final vote: N"
> - `#screen-error` — Generic disconnect screen, big Reload button
>
> ## Class hooks the JS uses (do not rename)
>
> ```
> .screen, .screen.active, .hidden
> .splash-hero, .splash-hero.small, .splash-image, .splash-overlay
> .splash-title, .splash-subtitle
> .role-card, .role-prompt, .role-option, .role-option input
> .page-header, .page-header.projector, .muted, .muted.small, .error-text
> .card, .card.center, .card.warning, .qr-card, .stats-card, .actions-card
> .projector-grid, .projector-side, .results-wrap, .results-actions
> .big-label, .big-text
> .btn, .btn.primary, .btn.danger, .btn.ghost, .btn.large
> .row, .stats-row, .stat-label, .stat-value
> .results-table, .results-table tr.first-place
> .results-table .col-rank, .col-photo, .col-votes, .col-bar, .bar
> .warning-label
> .status-text, .status-text.ok, .status-text.error
> .spinner
> ```
>
> ## IDs the JS uses (do not rename)
>
> `#role-admin, #role-voter, #role-continue, #admin-status, #voter-status,
> #role-error, #photo-count-input, #photo-count-submit, #photo-count-confirm,
> #photo-count-display, #photo-count-change, #photo-count-confirm-btn,
> #admin-photo-count, #qr-image, #qr-url, #joined-count, #voter-count,
> #vote-count, #rotate-qr-btn, #lock-room-btn, #count-votes-btn,
> #results-total, #results-body, #cluster-warning, #cluster-warning-text,
> #download-archive-btn, #new-session-btn, #voter-max, #vote-input,
> #vote-submit, #vote-status, #voter-final, #error-title, #error-message,
> #error-reload`
>
> ## What I want back
>
> A complete replacement `public/style.css` (~300-500 lines), plus (optional)
> up to 3 `<link>` lines added to `public/index.html` `<head>` for Google
> Fonts imports. Nothing else changes. Write modern CSS — custom properties,
> grid, flexbox, container queries if useful. No preprocessor, no Tailwind.
>
> Surprise me, but stay disciplined: this is a serious photography club's
> ballot, not a party game.
