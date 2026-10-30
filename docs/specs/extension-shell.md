# Spec: Aegis Browser Guard (Standalone Chromium MV3 Extension)

This spec covers **Aegis Browser Guard**, the standalone Chromium MV3 browser extension (`Aegis-BrowserGuard.zip`). It runs entirely inside the browser with **zero `.exe` dependencies** and **zero `nativeMessaging` permissions**.

## Architecture & Modules
1. **`static/manifest.template.json`** + **`scripts/build.mjs`** (esbuild, readable non-minified output -> `dist/extension/`; deterministic `key` from `static/extension-key.txt`).
   - Permissions: `offscreen`, `clipboardRead`, `clipboardWrite`, `notifications`, `storage`, `alarms`, `declarativeNetRequest` (no `nativeMessaging`).
   - Optional permissions: `history`, `management` (requested only when running Exposure Checkup).
   - Host permissions: `<all_urls>`.
   - Content scripts: `inpage.js` (MAIN world) and `content.js` (isolated world), both at `document_start`, `all_frames`, `match_about_blank`.
2. **`src/inpage/index.ts`** (MAIN-world wallet hooks):
   - Intercepts Wallet Standard (`wallet-standard:register-wallet` + `solana:signAndSendTransaction`, `solana:signTransaction`, `solana:signMessage`, `solana:signIn`) and legacy window providers (`window.solana`, `window.phantom.solana`, `window.solflare`, `window.backpack`, including dynamic two-step assignment on `window.phantom`).
   - Uses `ArrayBuffer.isView` for cross-realm `Uint8Array` compatibility, `crypto.getRandomValues` UUID fallback for plain `http://` pages, snapshots Wallet Standard `inputs` transaction bytes before forwarding, preserves unreadable batch entries (`unreadableCount`), and extracts `signIn` domain fields.
3. **`src/content/`** (isolated world):
   - `overlay.ts`: renders alerts inside a closed Shadow DOM; enforces `event.isTrusted` on actions.
   - Relays gate requests between `inpage.js` and the background service worker.
   - **Paste protection:** intercepts `paste`/`drop` in capture phase, runs `mightContainSecret()`, asks service worker (`detect`), blocks untrusted secret pastes with a site-trust option, or re-inserts cleanly.
   - **Recovery-phrase form warning:** warns once per page when >=4 BIP-39 words are typed into multi-input or textarea forms on untrusted origins.
   - **Address swap & lookalike checks:** records copied non-lookalike Solana addresses and warns on paste if swapped within 2 minutes or matching first/last 4 characters of a known address.
4. **`src/offscreen/`** (`offscreen.html` + `offscreen.ts`):
   - Polls clipboard every ~1s, stores only salted HMAC fingerprints in RAM, runs a 30s countdown when a 64-byte Solana secret key or BIP-39 phrase is copied, and overwrites with `[Aegis: cleared]` only if the clipboard was not already displaced.
   - Rejects any runtime message where `sender.tab` is present.
5. **`src/background/`**:
   - `service-worker.ts`: strict message router (validates `!sender.tab` on privileged `clip:*` / `review:*` / `ui:*` channels and `isAllowedRpcUrl` on RPC updates).
   - `clipboard-controller.ts`: manages offscreen lifecycle, badge countdown, Clear Now / +30s notifications, and optional `Win+V` reminder pointing to `ms-settings:clipboard`.
   - `review-manager.ts`: analyzes transactions/messages (including `signInDomain` mismatch and `unreadableCount` escalation) and opens `review.html` popup window (fail-closed on window close or 5-minute timeout).
   - `domains.ts`: bundled official Solana brand list, punycode/homograph + edit-distance + brand-keyword lookalike detection, and dynamic `declarativeNetRequest` blocklist with `priority: 2` session `ALLOW` rules covering subdomains.
   - `address-book.ts`: local recent-address ring buffer (cap 300, public addresses only) with copy-swap and vanity-poisoning detection.
6. **UI pages (`src/ui/`):**
   - `review.html`: SAFE / CAUTION / DANGER / UNVERIFIED banner, balance & authority diffs, findings, collapsible program/instruction/log details, Reject default focus, risk checkbox on DANGER.
   - `popup.html`: live protection toggles, clipboard timer controls, Settings & Exposure Checkup shortcuts.
   - `options.html`: 1-click free Solana RPC presets (`Solana Official Mainnet`, `PublicNode Mainnet`, `Solana Devnet`, `Offline Static Mode`) + HTTPS/localhost validation, trusted paste origins, Exposure Checkup (`history` + `management` scan), and manual 10-second **Windows 11 Notepad `TabState` Ghost Copy** guide.
   - `blocked.html`: lookalike/blocked domain interstitial with full query-string preservation and temporary session bypass.
   - `onboarding.html`: first-run walkthrough with permission explanations, `ms-settings:clipboard` shortcut, and 1-click no-key RPC preset selector.
