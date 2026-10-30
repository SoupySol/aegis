# Aegis: Phase 0 Spike Report

Phase 0 checks that the risky technical assumptions in the plan hold before the real extension is built.
Everything here is **local only**: no servers, no data export, and all keys used in tests are throwaway values generated from random bytes.

## Results

| # | Spike | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 1 | Offscreen clipboard read + countdown clear (MV3) | ✅ **Passed** | `e2e-spike.mjs`: secret detected within about 1s, badge countdown ran, clipboard cleared at 0, contract address ignored |
| 2 | Pause wallet sign requests **before** the wallet runs (Wallet Standard) | ✅ **Passed (mock wallet)** | Rejection returned code 4001 and the wallet never ran; approval forwarded; private `#fields` intact |
| 2b | Same, with **real Phantom on pump.fun** | ⏳ Manual test needed | Load `dist/spike` (steps below) |
| 3 | Simulation latency on Helius | ⏳ Waiting for Helius key | n/a |
| 4 | Windows clipboard history (Win+V) API from a normal desktop process | ✅ **API reachable** | `spike4-clipboard-history.ps1` returned a proper status (`ClipboardHistoryDisabled`), not access denied. History is **off** on this PC, so reading items wasn't exercised |
| 4b | Windows 11 Notepad saved-tab scan | ⚠️ Can't test on this PC | This machine runs **Windows 10 Home**. The tabbed Notepad is Windows 11 only. Needs a Win11 machine/VM or captured test fixtures |
| ✚ | Paste guard (bonus) | ✅ **Passed** | Test key paste blocked before the page saw it; contract address paste allowed |
| ✚ | Detector unit tests | ✅ **21/21** | `npm test`: zero false positives on addresses, CAs, tx signatures, random 64-byte values; every key format and seed length detected |
| 5 | **Clip Guard in C# with the compiler built into Windows** | ✅ **Passed** | `spike5-csharp-builtin`: built with `csc.exe` (no downloads), 7 KB exe; Win+V API ✅; offline OCR engine ✅ (en-US) |
| 5b | ed25519 key check in C# (.NET 4.8 has none built in) | ✅ **301/301** | `clipguard-helper/tests/run-tests.bat`: matches @noble/curves + RFC 8032 vector, ~2 ms per check, bit-flipped keys rejected |

## Findings to carry into Phase 1
- **Content-script size:** the paste guard bundle is about 95 KB because it includes the crypto + word list, and it runs in every frame. Phase 1 will use a tiny pre-filter in the page and send only real candidates to the background for the full check.
- **Clip Guard switched from Rust to C# 5 / .NET Framework 4.8**, built with the compiler inside Windows. No toolchain is needed for users, self-builders, or development.
- Windows clipboard history being off on this PC is the safest setting. Full Guard will report it as "✅ protected".

## How to run
```powershell
cd aegis-wallet-shield\extension
npm install
npm test             # detector unit tests
npm run spike:e2e    # builds dist/spike and runs the automated browser checks (headless, isolated profile)
powershell -ExecutionPolicy Bypass -File ..\spikes\spike4-clipboard-history.ps1   # Win+V API check (metadata only)
```

## Manual test 2b: real Phantom on pump.fun
1. `npm run build:spike`
2. In Chrome or Brave, open `chrome://extensions` → turn on **Developer mode** → **Load unpacked** → select `aegis-wallet-shield\extension\dist\spike`.
3. Open pump.fun, open DevTools (F12) → Console. You should see `[Aegis spike] inpage hooks installed` and `Wallet Standard wallet wrapped: Phantom`.
4. Start a small buy. **Before Phantom opens**, a browser dialog should say "Intercepted BEFORE your wallet opened". Click **Cancel**: pump.fun should show the request as rejected and Phantom should never open. Repeat and click **OK**: Phantom opens normally.
5. Remove the spike extension afterwards (it's a dev build).

