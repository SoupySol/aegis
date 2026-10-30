# Project $AEGIS: Aegis Sentinel (Browser Wallet Defense Shield)

## 1. Overview & Positioning
* **Token Ticker**: **$AEGIS** (Alternative: **$SHIELD**, **$PURGE**)
* **Token Name**: **Aegis Sentinel Protocol**
* **The High-IQ Rebrand (The Narrative)**:
  > *"Sub-DOM Execution Interceptor & Ephemeral Memory Purifier: Real-time SVM instruction decoding and client-side entropy sanitation for active DeFi operators."*

---

## 2. The Core Problem in the Trenches
Active Solana trench traders face 3 constant security vulnerabilities:
1. **Malicious Drainer Signatures**: Phishing sites tricking wallet adapters into confirming transactions containing hidden `TokenProgram.setAuthority` transfers or unsolicited SOL drains.
2. **Exposed Clipboard Keys**: Traders copy private keys or seed phrases to move between wallets or bots, leaving sensitive keys exposed in the clipboard buffer where malicious websites or background malware can silently read them.
3. **Phishing & Homoglyph Clones**: Sponsored Google ads and Twitter links sending users to lookalike domains (e.g. `raydīum.io`, `pumpfun-claims.cc`).

---

## 3. The 4 Defensive Modules (Built into a Lightweight Chrome/Brave Extension)

```
                            ┌─────────────────────────────────────────┐
                            │         $AEGIS SENTINEL EXTENSION       │
                            └────────────────────┬────────────────────┘
                                                 │
       ┌───────────────────────────────┬─────────┴─────────────┬───────────────────────────────┐
       ▼                               ▼                       ▼                               ▼
[1. Clipboard Purger]       [2. Transaction Interceptor]   [3. Phishing Shield]       [4. Memory Scrubber]
 Regex monitors clipboard.   Hooks window.solana.           Flags homoglyph URLs       Auto-purges browser
 Detects base58 keys /       Decodes instructions.          (e.g. raydium-app.cc)      cache of sensitive
 12-word seeds. Wipes in     Blocks 'setAuthority' &        before wallet connects.    dApp session tokens.
 20s with desktop alert.     hidden drainer transfers.
```

### Module 1: Autonomous Clipboard Sanitizer (Zero-Retention)
* **How It Works**: Content script monitors the browser's clipboard buffer.
* **Pattern Detection**:
  * **Solana Private Keys**: Base58 strings of 87–88 characters.
  * **Seed Phrases**: 12 or 24 BIP-39 mnemonic word strings.
  * **Raw Byte Arrays**: 64-byte keypair arrays (`[142, 59, 211, ...]`).
* **Action**:
  1. Displays an instant browser desktop notification:
     `"⚠️ SENSITIVE KEY DETECTED ON CLIPBOARD: Auto-purging in 20 seconds to prevent malware theft."`
  2. Automatically overwrites the clipboard buffer (`navigator.clipboard.writeText('')`) after 20 seconds.

### Module 2: Pre-Signing Transaction Decompiler (The Drainer Shield)
* **How It Works**: Injects an isolated hook into `window.solana.signTransaction` and `window.solana.signAndSendTransaction` before third-party dApps can trigger them.
* **Inspection Logic**:
  * Decodes raw instructions inside the serialized transaction before Phantom/Solflare opens.
  * **Red Flag 1**: Calls `TokenProgram.setAuthority` (attempting to steal ownership of token accounts).
  * **Red Flag 2**: Direct SOL transfer instructions to unverified addresses that are not recognized DEX pools.
  * **Red Flag 3**: Requests to close token accounts with rent destinations routed to an unknown third-party.
* **Action**:
  * Halts transaction execution immediately.
  * Triggers a full-screen red warning modal with exact decoded threat details:
    `"🛑 MALICIOUS TRANSACTION BLOCKED: Unsolicited authority reassignment detected. Transaction aborted."`

### Module 3: Homoglyph & Phishing Domain Cloak
* **How It Works**: Checks the active tab URL against a bundled whitelist of legitimate Solana DeFi platforms:
  * Pump.fun, Raydium, Jupiter, Photon, BullX, Axiom, Birdeye, DexScreener.
* **Action**:
  * Detects character substitution (homoglyphs) or unofficial TLDs pretending to be official DEXs.
  * Prevents the wallet connection handshake until explicitly bypassed by the user.

### Module 4: Ephemeral Memory Scrubber
* **How It Works**: Provides a 1-click **"Emergency Purge"** button in the extension popup.
* **Action**:
  * Instantly wipes `localStorage`, `sessionStorage`, and cached dApp session keys across all active Solana tabs.

---

## 4. Elastic Fee Scaling & Token Flywheel (Pump.fun)

* **Zero Upfront Cost**: The extension is free and open-source on GitHub and distributed directly via `.zip` on the website.
* **Micro-Fee Phase (10–25 SOL Volume)**:
  * Creator fees fund the live **"Threat Intelligence Radar"** displayed inside the extension popup, listing newly detected scam contracts and drainer domains.
* **High-Volume Phase (100+ SOL Volume)**:
  * **30% of Fees**: Automated market-buy of $AEGIS on Pump.fun (generating green candles on chart).
  * **20% of Fees**: On-chain bounties streamed to community members who submit verified zero-day drainer contracts to the threat database.
  * **50% of Fees**: Dev profit.

---

## 5. The Trader Edge & Viral Marketing
1. **Real Utility**: Degens keep this extension installed in their browsers 24/7 because it actively protects their trading bags.
2. **Viral Proofs**: Whenever the extension intercepts a drainer or wipes a sensitive key, the user gets a 1-click **"Share Proof to X"** button with pre-filled text:
   *"$AEGIS just intercepted a malicious drainer on a fake Raydium clone. Saved my wallet 14 SOL. 🛡️"*
3. **Token-Gated Perks**: Holding 25,000 $AEGIS unlocks real-time desktop push notifications for new malicious contracts detected across the Solana ecosystem.

