# Security Model & Architecture

## Threat Model & Design Principles

1. **Complete Air-Gap Between Browser & Local File Cleaner**:
   - **Aegis Browser Guard** (the Chrome/Brave/Edge extension) has **zero `nativeMessaging` permissions** and cannot launch or communicate with local executables or read local files.
   - **Aegis Clip Guard** (`aegis-clipguard.exe`) is a **standalone, portable Windows desktop app** with **zero network code, zero browser connection, and zero Windows Registry writes**. Even a total browser compromise cannot reach `aegis-clipguard.exe`, and `aegis-clipguard.exe` has no networking stack with which to exfiltrate anything.
2. **Zero-Server Cryptographic Detection (Zero Address False Positives)**:
   - Solana wallet addresses, program IDs, and pump.fun token contract addresses are **32 bytes**. Aegis never treats 32-byte values as secrets.
   - Solana secret keys are **64 bytes** (`[32-byte seed || 32-byte public key]`). Aegis derives the ed25519 public key of the first 32 bytes and checks byte-for-byte equality with the second 32 bytes (`~2^-256` false-positive rate; 64-byte transaction signatures never trigger false alarms).
   - Seed phrases are validated against the 2048-word BIP-39 English wordlist + SHA-256 checksum, and **never** derived into wallet addresses or keys.
3. **Memory & Display Hygiene**:
   - Decoded byte buffers are wiped immediately (`seed.fill(0)` in TypeScript, `Array.Clear(...)` in C#) inside `finally` blocks.
   - The clipboard poller keeps only a session-salted HMAC-SHA256 fingerprint (`fingerprint.ts`) in memory so it knows whether the clipboard changed; the random 32-byte key lives only in RAM and dies when the browser closes.
   - Clip Guard displays **masked previews only** (`7xKp…9Qm4` shortened *public* key, or `"12 words, starts with a…"`), sanitizes Notepad tab labels against BIP-39 word leaks, redacts secret-bearing filenames, and skips NTFS directory junctions/symlinks to prevent traversal loops.
4. **Hardened In-Page & UI Boundaries**:
   - `inpage.js` captures pristine built-ins at `document_start` before page scripts execute, handles cross-realm `ArrayBufferView` inputs, snapshots transaction bytes before review so getters cannot swap payloads after approval, and preserves receiver `this` bindings so wallets with `#private` class fields work seamlessly.
   - In-page Paste Guard banners render inside a `mode: 'closed'` Shadow Root and verify `event.isTrusted === true` on every user click.
   - Offscreen clipboard commands verify sender privilege (`!sender.tab`) so web content scripts cannot reconfigure or force-write the clipboard.
   - Transaction reviews open in an **extension-owned popup window** (`review.html`), completely outside the website's DOM, and enforce `https://` on remote RPC endpoints.

---

## Honest Scope & Known Limitations

Aegis significantly raises the bar against common Solana loss vectors, **but no tool can provide 100% protection**:

- **Already-compromised OS / info-stealers**: If malware is already running on your PC, it can read memory, browser profiles, or keystrokes directly. Aegis's Address Swap check can help *spot* a clipboard swapper, not remove malware.
- **Simulation-aware contracts**: An unknown on-chain program can inspect clock/slot state and behave differently when simulated vs executed on-chain. Aegis flags unknown and freshly deployed programs as a warning, even when simulation looks calm.
- **`signTransaction` held for later**: When a site asks for `signTransaction` (rather than `signAndSendTransaction`) or uses a **Durable Nonce**, on-chain state may change before the site broadcasts your signed transaction.
- **SSD wear-leveling**: Deleting a plaintext seed file or Notepad `.bin` cache removes it from normal file reads, but flash storage wear-leveling can retain blocks physically. **If a funded wallet's seed phrase or private key was ever saved in plaintext or synced to OneDrive/Dropbox/Google Drive, transfer funds to a freshly generated wallet.**

---

## Reporting Security Issues

If you find a security bug, bypass, or false negative in Aegis:
- Please open a GitHub Security Advisory on this repository (or file a public issue if no exploit details against live users are exposed).
- Include minimal reproduction steps using freshly generated throwaway test keys (**never** include real wallet keys or RPC API keys).
