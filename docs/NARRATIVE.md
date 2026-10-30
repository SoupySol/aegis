# Why I Built Aegis (`$AEGIS`)

## 1. The Story (Founder Narrative)

With all the wallet drains and infostealer waves lately, most people still think hacks happen because someone cracked their wallet. Almost none of them do. Most wallets get emptied because of two quiet blind spots: **files Windows saves behind your back**, and **one rushed misclick on chain**.

The biggest blind spot is **Windows 11 Notepad**.

Think about how many times someone sets up a new Solana wallet, exports a burner key, or configures a trading bot and pastes the private key or seed phrase into Notepad for ten seconds. Then they close the tab **without saving** and assume it vanished.

On Windows 11, it didn't vanish. Windows 11 updated Notepad so open tabs survive a reboot. Every character typed or pasted into an unsaved tab gets written straight to disk inside hidden `.bin` cache files:

```text
%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState
```

Even if you clicked "Don't Save" or never saved the file at all, raw keys can sit in `TabState\*.bin` for months alongside **Windows Clipboard History (`Win+V`)** and **Sticky Notes** caches. If an infostealer ever touches that PC, or a folder gets backed up, that forgotten temp paste is sitting right there in plain text.

That is why clipboard and local cache cleanup became the centerpiece of Aegis:
- **In the browser**, Aegis watches your live clipboard locally. If you copy a real Solana private key or 12/24-word seed phrase, it clears it after 30 seconds (while ignoring token contract addresses so you can copy CAs all day without annoying alerts). It also blocks accidental secret pastes into websites and warns if malware swaps a copied wallet address before you paste it.
- **On Windows**, Aegis includes a separate offline desktop cleaner (`aegis-clipguard.exe`) with zero internet code and zero browser connection. You run it locally to scan and wipe secrets out of Windows 11 Notepad `TabState\*.bin`, `Win+V` history, Sticky Notes, and forgotten `.env` or `.txt` files.

The second half of the problem happens **on chain**: late-night misclicks and disguised signatures.

People move fast when trading. One wrong click on a fake claim page, a lookalike URL, or a disguised `Approve` transaction hands permanent token spending permission or account ownership to a drainer.

**Aegis has zero wallet connection.** You never connect a wallet to Aegis, never import a seed phrase, and never sign in to a server. Aegis simply sits in front of the wallet you already use (Phantom, Solflare, Backpack, OKX, Magic Eden, Coinbase Wallet), reads the unsigned bytes going into that wallet, and decodes their real intent before you sign:
- **Normal buys and sells** on recognized Solana DEXes pass straight through to your wallet with zero extra popups.
- **Approvals, wallet connects, sign-ins, and ownership changes** stop for a clear breakdown: exact domain and URL check, what token is being approved, whether the limit is capped or `UNLIMITED`, your current balance at risk, and what address gets permission.

The goal is simple: clean up the temp secrets Windows and clipboards leave behind, and make sure a single misclick never costs someone their wallet.

---

## 2. X / Twitter Launch Thread (Ready to Post)

**Post 1 (The Hook - Windows 11 Notepad)**
If you trade on Windows 11 and have ever pasted a private key or seed phrase into Notepad "just for a second" without saving, check your PC right now.

Press `Win + R` and paste:
`%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState`

Windows 11 silently writes unsaved Notepad tabs to `.bin` files on disk so tabs reopen after a restart. Even if you never clicked Save, old keys can still be sitting there.

**Post 2 (Why Recent Drains Keep Happening)**
Most recent wallet drains aren't sophisticated exploits. They come down to two everyday leaks people don't realize exist:

1. Temp copies left behind in Windows 11 Notepad `TabState`, `Win+V` clipboard history, or a live clipboard buffer.
2. One rushed misclick on a disguised `Approve` or lookalike site when your wallet popup doesn't show the real intent.

That's why I built Aegis (`$AEGIS`).

**Post 3 (Clipboard & Windows 11 Cleanup)**
First, Aegis cleans up the clipboard and temp-file side:

- Auto-clears copied private keys and seed phrases in 30s (uses Ed25519 + BIP-39 checks so copying token CAs never triggers false alarms)
- Blocks accidental key pastes into websites & catches clipboard address swaps
- Includes a standalone offline Windows cleaner (`aegis-clipguard.exe`) with 0 network code to scan and wipe Notepad `TabState\*.bin`, `Win+V`, and Sticky Notes

**Post 4 (Zero Wallet Connection - Stopping On-Chain Misclicks)**
Second, Aegis stops on-chain "accidents" before your wallet signs.

Aegis has **0 wallet connection**. You never connect your wallet to us or enter a key.

It sits locally in front of Phantom, Solflare, Backpack, OKX, etc., reads the unsigned payload heading into your wallet, and decodes what it actually does.

**Post 5 (Zero Trading Friction)**
We made sure it doesn't get in the way while trading:

- Normal DEX buys & sells pass straight through with zero popups
- Any `Approve` / spending allowance, wallet connect, sign-in, lookalike URL, or ownership transfer gets paused and broken down in plain English (exact token, exact limit or `UNLIMITED`, balance at risk, and spender)

**Post 6 (Open Source & Verifiable)**
Everything is open source, local-only, and ships as two isolated tools with zero backend servers:

1. Browser Guard extension (unminified JS, 0 `.exe`, 0 `nativeMessaging`)
2. Standalone Windows Clip Guard (0 network code, compiles in 2 seconds with Windows' built-in `csc.exe`)

Check your `TabState` folder, stay safe out there, and inspect the code yourself:
https://github.com/SoupySol/SoupySol

---

## 3. Short Bio / Launchpad Description (Pump.fun / Website Header)

Built after watching traders get drained by two blind spots nobody talks about: Windows 11 silently saving unsaved Notepad tabs (`TabState\*.bin`) + `Win+V` clipboard caches to disk, and rushed one-click wallet approvals on chain. Aegis has **0 wallet connection** and **0 backend servers**. It cleans copied keys from your clipboard in 30 seconds, wipes Windows 11 Notepad & clipboard ghost copies offline, and decodes every `Approve`, wallet connect, and signature inside Phantom, Solflare, Backpack, or OKX so one misclick never empties your wallet.

---

## 4. Key Talking Points (Quick Reference)

- **The Main Mover**: Windows 11 Notepad caches unsaved tabs to `LocalState\TabState\*.bin` in plain UTF-16LE. Anyone on Windows 11 can verify this on their own machine in 10 seconds with `Win + R`.
- **Why Clipboard Hygiene Matters**: Copying keys between wallets, bots, and `.env` files leaves live secrets in the clipboard buffer and `Win+V` history. Aegis clears live keys in 30 seconds (never flagging 32-byte token CAs), blocks pasting keys into sites, catches clipboard address-swappers, and wipes `TabState` + `Win+V` offline.
- **0 Wallet Connection**: Aegis is not a wallet and never connects to your wallet. It inspects the raw unsigned transaction or message bytes being passed into your existing wallet and decodes their true intent.
- **Built to Prevent Misclicks, Not Slow Down Trades**: Clean DEX buys and sells go straight to your wallet without a popup. Approvals, connects, lookalike sites, and account ownership transfers get flagged clearly before you can misclick.

