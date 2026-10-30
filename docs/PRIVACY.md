# Privacy Policy

**Short version: Aegis has no servers. Your clipboard, files, browsing history, and keys never leave your computer.**

---

## What Stays 100% Local on Your Device

1. **Clipboard & Paste Checks**: Checked in-memory on your machine. Plaintext is never written to `chrome.storage`, disk, or logs, and never sent over the network.
2. **Ghost Copy Scan & Secret Sweep (Standalone Clip Guard)**: Runs inside `aegis-clipguard.exe` with **zero networking code, zero browser connection, and zero Windows Registry edits**. Only masked summaries (e.g., shortened public key `7xKp…9Qm4` or `"12 words, starts with a…"`) are displayed inside its local desktop window.
3. **Settings & Recent Public Addresses**: Stored strictly in `chrome.storage.local` on your device (`chrome.storage.sync` is never used, so nothing is uploaded to browser cloud sync).
4. **Optional Exposure Checkup**: If you grant the optional `history` or `management` permissions, visited hostnames and installed extension IDs are compared locally against bundled rules in memory and never transmitted anywhere.

---

## The Single Optional Network Connection (Your Solana RPC)

If you paste a Solana JSON-RPC endpoint (such as a free Helius URL) into **Settings → Solana RPC Endpoint**:
- When a website requests a wallet signature (or when you run a Public Wallet Exposure Checkup), Aegis sends standard Solana JSON-RPC requests (`getMultipleAccounts`, `simulateTransaction`, `getSlot`, `getTokenAccountsByOwner`) directly from your browser to **that RPC URL**.
- Those requests contain only public blockchain data (unsigned transaction bytes and public Solana addresses) with `credentials: 'omit'`.
- Your RPC provider's own privacy policy applies to standard RPC queries sent to their endpoint. Leaving the RPC URL blank disables all network requests completely (Aegis falls back to offline static instruction decoding).

