# AGENTS.md — Aegis Wallet Shield ($AEGIS) Developer & Agent Specification

Welcome, AI Agent (Cursor, Claude, Copilot, Devin, ChatGPT, Antigravity, Gemini).

This repository contains **Project Aegis ($AEGIS)**, a high-trust, open-source security shield designed specifically for Solana users. The project is architected with strict, mathematically verifiable isolation guarantees so that any human or AI agent can inspect, audit, fork, or extend it with 100% confidence.

---

## 1. High-Level Architecture: Two Completely Air-Gapped Tools

Aegis is composed of **two separate, air-gapped tools** that share zero runtime dependencies, zero inter-process communication (IPC), and zero native messaging bridges:

```
+-----------------------------------------------------------------------------------+
|                                   PROJECT AEGIS                                   |
+-----------------------------------------+-----------------------------------------+
| TOOL 1: Aegis Browser Guard             | TOOL 2: Aegis Clip Guard                |
| (Manifest V3 Browser Extension)         | (Standalone Windows Desktop C# App)     |
| Location: /extension                    | Location: /clipguard-helper             |
|                                         |                                         |
| * Passive pre-wallet transaction gate   | * Air-gapped Windows desktop cleaner    |
| * Intercepts Wallet Standard & window   | * Cleans unsaved Notepad 11 TabState    |
| * Decodes instructions before signing   | * Cleans Win+V clipboard history        |
| * Zero private keys, zero wallet seed   | * Cleans Sticky Notes SQLite database   |
| * ZERO .exe, ZERO nativeMessaging       | * ZERO network code, ZERO registry edit |
| * Network restricted solely to rpc.ts   | * Compiles with Windows built-in csc    |
+-----------------------------------------+-----------------------------------------+
```

### Tool 1: Aegis Browser Guard (MV3 Extension)
* **What it is**: A pure client-side browser extension (Chrome, Brave, Edge) that sits **between the dApp and the user's existing wallet** (Phantom, Solflare, Backpack, OKX, etc.).
* **Zero Wallet Connection**: Aegis does **not** connect to dApps as a wallet and has **no private keys**. It transparently wraps the standard wallet interfaces in the page (`@wallet-standard/base` and legacy `window.solana`), intercepting `signTransaction`, `signAndSendTransaction`, `signMessage`, and `signIn` calls **before** the wallet popup appears.
* **Intelligent Fast-Path vs. Review**: Clean DEX token swaps on recognized AMMs (Jupiter, Raydium, pump.fun, Meteora, etc.) pass straight through to the wallet without popup noise (avoiding alert fatigue). Any transaction requesting token delegate approvals (`Token:Approve`), account owner reassignment (`System:Assign`), close authority reassignments, durable nonces, or draining transfers is intercepted and surfaced in an isolated popup review window (`review.html`).
* **Paste Guard**: Synchronously intercepts clipboard paste/drop events in the capture phase. If a user pastes a private key or 12/24-word recovery phrase onto an untrusted website, Aegis blocks the paste immediately.

### Tool 2: Aegis Clip Guard (Standalone Windows Desktop App)
* **What it is**: A portable, air-gapped Windows desktop utility (`aegis-clipguard.exe`) written in C# (.NET Framework 4.8) that scans and wipes "ghost copies" of crypto secrets silently auto-saved by Windows.
* **Targets**:
  1. **Windows 11 Notepad TabState**: Windows 11 Notepad auto-saves open unsaved tabs to `%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState\*.bin` even if the user never presses Save.
  2. **Windows Clipboard History (Win+V)**: Pasted seed phrases remain in the Win+V ring buffer across applications.
  3. **Microsoft Sticky Notes**: SQLite database and WAL logs containing unencrypted desktop notes.
  4. **Local Folders**: Deep scanner for `.env`, desktop files, and screenshots.
* **Zero External Downloads**: Compiles in 2 seconds using Windows' built-in C# compiler (`csc.exe` in `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`). Zero NuGet packages, zero external DLLs, zero installation.
* **Strict Guarantees**: Zero network APIs, zero Windows Registry writes, zero browser hooks.

---

## 2. Strict Architectural Constraints & Budgets (Agent Invariants)

When modifying or extending this codebase, you **MUST** uphold these non-negotiable invariants:

| Constraint | Enforcement Rule | Verification Command |
|---|---|---|
| **Bundle Size Budget** | `content.js` and `inpage.js` **MUST stay strictly under 30 KB** (currently ~19 KB and ~29 KB). They run on every page navigation; keeping them featherweight prevents performance degradation. | `node scripts/build.mjs` |
| **Network Boundary** | Outbound network calls (`fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`) exist **ONLY** in `extension/src/background/analysis/rpc.ts`. No other extension file or desktop C# file may perform network I/O. | `powershell scripts/verify-security.ps1` |
| **Air-Gap Separation** | The browser extension must **NEVER** declare `nativeMessaging` permission or call `chrome.runtime.connectNative`. Browser Guard and Clip Guard remain completely isolated. | `powershell scripts/verify-security.ps1` |
| **Zero Registry Access** | Clip Guard C# source must contain **ZERO** references to `Microsoft.Win32.Registry`, `Registry.CurrentUser`, or `RegistryKey`. | `powershell scripts/verify-security.ps1` |
| **No Dynamic Code** | Zero `eval()`, zero `new Function()`, zero remote `<script>` tags in HTML. | `powershell scripts/verify-security.ps1` |
| **Memory Hygiene** | Raw byte buffers containing secrets or tab data must be wiped immediately using `Array.Clear` (C#) or scoped closures with explicit zeroing. | Code review & tests |
| **Annotated Source Headers** | Every `.ts` and `.cs` file **MUST** start with a block comment containing `PURPOSE:` and `ACCESS:`. | `powershell scripts/verify-security.ps1` |

---

## 3. Step-by-Step Extensibility Recipes

### Recipe 1: How to Add a New Solana DEX or Program to `known-programs.ts`

To register a new DEX or program ID so Aegis can label it and recognize clean swaps:

1. **Open `extension/src/shared/known-programs.ts`**:
   Add the program ID constant:
   ```typescript
   export const NEW_DEX_PROGRAM_ID = 'YourProgramID1111111111111111111111111111111';
   ```

2. **Register in `KNOWN_PROGRAMS` dictionary**:
   Assign its friendly display name and category (`'dex'`, `'core'`, `'token'`, `'nft'`, or `'utility'`):
   ```typescript
   export const KNOWN_PROGRAMS: Readonly<Record<string, KnownProgram>> = {
     // ... existing entries ...
     [NEW_DEX_PROGRAM_ID]: { name: 'MyProtocol AMM', category: 'dex' },
   };
   ```

3. **Verify Helper Functions**:
   Because `isDexProgram(id)` checks `KNOWN_PROGRAMS[id]?.category === 'dex'`, adding it with category `'dex'` automatically integrates it into the clean buy/sell swap detection engine!

4. **Add Unit Tests in `extension/tests/unit/analysis/wire-and-decoders.test.ts`**:
   Confirm `knownProgram(NEW_DEX_PROGRAM_ID)` returns the expected name and category.

---

### Recipe 2: How to Add a New Transaction Analysis Rule in `rules.ts`

Aegis analyzes transaction instructions and simulated state transitions in `extension/src/background/analysis/rules.ts`.

1. **Understand `RuleInput` and `Finding`**:
   `RuleInput` provides:
   * `instructions`: Array of `DecodedIx` (type, program, params, inner flag).
   * `balanceChanges`: Pre/post SOL and token balance changes per owner.
   * `authorityChanges`: Consolidated wallet, token, stake, or program ownership transfers.
   * `simulation`: Simulation success, compute units consumed, error logs.
   * `wallet`: Public key of the user's active wallet.

2. **Define Finding Definition**:
   Findings use standard severities:
   * `'critical'` / `'high'`: Escalates verdict to `'DANGER'`, blocks fast-pathing, requires red warning in review modal.
   * `'medium'` / `'low'`: Escalates verdict to `'CAUTION'` or `'UNVERIFIED'`.
   * `'info'` / `'safe'`: Informational details.

3. **Implement Rule Logic in `evaluateTransactionRules`**:
   ```typescript
   // Example: Flag transactions executing an unauthorized instruction type
   for (const ix of instructions) {
     if (ix.type === 'customProgram:dangerousAction' && ix.params.target === wallet) {
       emit(
         'dangerous-custom-action',
         'critical',
         'Unauthorized Account Manipulation',
         `Program ${shortAddr(ix.programId)} attempts to modify restricted settings on your account.`,
       );
     }
   }
   ```

4. **Add Finding ID to `BLOCKING_SWAP_FINDING_IDS` in `review-manager.ts`**:
   If this rule should prevent a transaction from being fast-pathed as a clean DEX swap, add the rule ID to `BLOCKING_SWAP_FINDING_IDS` in `extension/src/background/review-manager.ts`.

5. **Add Test Vectors**:
   Create a test case in `extension/tests/unit/analysis/simulate-and-rules.test.ts`.

---

### Recipe 3: How to Add New Decoders or Account Parsers

1. **Add Instruction Decoder in `extension/src/background/analysis/decoders.ts`**:
   * Decoders parse raw `Uint8Array` instruction data and account indices using `ByteReader` (from `./bytes.ts`).
   * **Rule of Robustness**: A decoder **must NEVER throw**. Catch index out-of-range errors and return a structured fallback (`{ type: 'myprog:unparseable', ... }`).
   ```typescript
   function decodeMyProgramInstruction(
     data: Uint8Array,
     accounts: string[],
   ): DecodedIx {
     const r = new ByteReader(data);
     const discriminator = r.u8();
     if (discriminator === 0) {
       const amount = r.u64().toString();
       return {
         programId: MY_PROGRAM_ID,
         programName: 'My Program',
         type: 'myprog:deposit',
         name: 'Deposit Funds',
         summary: `Deposit ${amount} lamports`,
         params: { amount, destination: accounts[1] ?? '' },
         accounts,
       };
     }
     return {
       programId: MY_PROGRAM_ID,
       programName: 'My Program',
       type: 'myprog:unknown',
       name: 'Unknown Instruction',
       summary: 'Unknown action',
       params: {},
       accounts,
     };
   }
   ```

2. **Add Account Parser in `extension/src/background/analysis/accounts.ts`**:
   * Parsers decode RPC account binary data returned by `getMultipleAccounts` or `simulateTransaction`.
   * Return a strongly-typed info object or `null` if the data does not match the layout.

---

### Recipe 4: How to Extend Windows Ghost-Copy Cleaner in `clipguard-helper/src/Sources/`

To add a new cache source to Clip Guard (e.g. scanning a messaging app or IDE cache for leaked seeds):

1. **Create Source File in `clipguard-helper/src/Sources/YourSource.cs`**:
   Follow the mandatory security header format:
   ```csharp
   // ---------------------------------------------------------------------------
   // YourSource.cs
   // PURPOSE:  Scans <App Name> local cache for auto-saved crypto secrets.
   // ACCESS:   Reads local files (FileShare.ReadWrite) in <Path>.
   // NEVER:    No network. No registry edits. Never stores raw secrets.
   // ---------------------------------------------------------------------------
   using System;
   using System.Collections.Generic;
   using System.IO;
   using Aegis.ClipGuard.Detection;
   using Aegis.ClipGuard.Model;

   namespace Aegis.ClipGuard.Sources
   {
       public static class YourSource
       {
           public const string LocationType = "your-app-cache";

           public static List<Finding> Scan()
           {
               List<Finding> findings = new List<Finding>();
               string folder = Path.Combine(
                   Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                   "YourApp", "Cache");
               if (!Directory.Exists(folder)) return findings;

               // Use FileShare.ReadWrite | FileShare.Delete so running apps are never locked
               // Read data into buffer, decode runs, run SecretDetector.DetectAll()
               // Wipe raw buffers with Array.Clear(buf, 0, buf.Length)
               return findings;
           }
       }
   }
   ```

2. **Integrate into `GhostScan.cs`**:
   Call your new source from `GhostScan.Run()` alongside `ClipboardHistory`, `NotepadTabs`, and `StickyNotes`.

3. **Verify Zero-Network Check**:
   Run `clipguard-helper\tools\check-no-network.ps1` to verify the new file contains no forbidden socket or HTTP APIs.

---

## 4. Key Design Patterns to Understand

### V8 Proxy Invariant Handling
In `extension/src/inpage/index.ts`:
JavaScript engines (V8) enforce strict ECMAScript invariants (§10.5.8 `[[Get]]` and §10.5.14 `[[GetOwnProperty]]`). If a proxy directly wraps an object that has been frozen (`Object.freeze(wallet)`), any proxy trap attempting to return a wrapped method throws a fatal `TypeError`:
`"property 'x' is a read-only and non-configurable data property on the proxy target but the proxy did not return its actual value"`.

**The Aegis Solution**:
Aegis constructs `new Proxy({} as T, ...)`. The shadow target `{}` is extensible and has no non-configurable properties. All operations are dynamically delegated to the `real` wallet target via `Reflect.get(real, p, real)`. This completely eliminates proxy invariant crashes on frozen wallets across Solflare, Phantom, and Wallet Standard.

### Closed Shadow DOM Click Isolation
In `extension/src/content/overlay.ts`:
1. `mode: 'closed'`: Attaches the warning overlay via `host.attachShadow({ mode: 'closed' })`. The host element's `.shadowRoot` evaluates to `null` for page scripts, preventing rogue dApps from traversing or querying the alert DOM.
2. `event.isTrusted`: Action buttons (e.g. "Allow on this site") explicitly check `if (!event.isTrusted) return;`. In modern browsers, synthetic events dispatched via `dispatchEvent(new MouseEvent('click'))` have `isTrusted === false`. Only physical hardware clicks have `isTrusted === true`. Malicious scripts cannot programmatically click through security warnings.

### Non-Blocking FileShare Concurrency
In `clipguard-helper/src/Sources/NotepadTabs.cs`:
Windows 11 Notepad auto-saves open tabs to `TabState\*.bin` in the background. Opening these files with default exclusive locks (`FileShare.None`) causes Windows to throw `ERROR_SHARING_VIOLATION (0x20)` in Notepad.exe, resulting in crashed auto-saves or corrupted files. Clip Guard uses `FileShare.ReadWrite | FileShare.Delete` to read snapshots concurrently without ever locking Notepad.

### Ed25519 Public Key Verification (RFC 8032)
In `clipguard-helper/src/Crypto/Ed25519PublicKey.cs`:
On Solana, transaction signatures are 64 bytes (88 Base58 chars), and public addresses are 32 bytes (44 Base58 chars). If a scanner flags every high-entropy 64-byte string as a "private key", it generates huge numbers of false alarms on normal transaction logs.
Aegis confirms a 64-byte value is a genuine exportable Solana private key by taking the first 32 bytes (the seed), deriving the Ed25519 public key via curve point scalar multiplication ($P = s \cdot B$), and checking in constant-time whether the derived key matches the second 32 bytes. The probability of random data matching is 1 in $2^{256}$.

---

## 5. Build, Test, and Verification Workflow

Always verify your changes with the one-click build script:

```bat
REM From the repository root:
build.bat
```

What `build.bat` executes:
1. `npm run build` in `extension/` (builds `dist/extension` and verifies bundle budgets < 30 KB).
2. `npx tsc --noEmit` and `npm test` (vitest unit test suite).
3. `clipguard-helper\build.bat` (compiles `aegis-clipguard.exe` using built-in `csc.exe`).
4. `clipguard-helper\tests\run-tests.bat` (runs detector corpus parity, Ed25519 vectors, synthetic TabState scans, and QA boundary stress tests).
5. `powershell scripts/verify-security.ps1` (verifies zero-network allowlist, zero eval, zero nativeMessaging, zero registry access, and annotated headers).
6. Packages release archives into `dist/` and writes `SHA256SUMS.txt`.

---

## 6. Ready-to-Use Prompts for AI Agents

Copy and paste these prompts directly into your AI coding tool:

### Prompt A: Add a New Solana DEX or AMM
> "Add support for [DEX Name] (Program ID: [Address]) to `aegis-wallet-shield`.
> 1. Register the program ID in `extension/src/shared/known-programs.ts` with category `'dex'`.
> 2. Ensure `isDexProgram()` recognizes it so clean buy/sell swaps can fast-path.
> 3. Add a unit test in `extension/tests/unit/analysis/wire-and-decoders.test.ts`.
> 4. Run `build.bat` and confirm all tests and security checks pass with bundle sizes < 30 KB."

### Prompt B: Add a New Security Detection Rule
> "Create a new transaction analysis rule in `extension/src/background/analysis/rules.ts` that detects [Dangerous Condition].
> 1. Inspect transaction instructions and simulated account state.
> 2. Emit a finding with appropriate severity (`'critical'` or `'high'`).
> 3. Add the finding ID to `BLOCKING_SWAP_FINDING_IDS` in `extension/src/background/review-manager.ts` if it should prevent fast-pathing.
> 4. Add test fixtures and unit tests in `extension/tests/unit/analysis/simulate-and-rules.test.ts`.
> 5. Run `build.bat` and verify all tests pass."

### Prompt C: Run Full Trust & Zero-Exfiltration Audit
> "Run a complete security audit on `aegis-wallet-shield`:
> 1. Check every `.ts` and `.cs` file for network calls, confirm only `rpc.ts` contains `fetch()`.
> 2. Verify zero nativeMessaging permissions in `manifest.template.json` and zero `connectNative` calls.
> 3. Verify zero Windows Registry access in `clipguard-helper/src/`.
> 4. Verify memory zeroing with `Array.Clear` across all secret detection and file reading paths.
> 5. Run `scripts\verify-security.ps1` and report the findings."
