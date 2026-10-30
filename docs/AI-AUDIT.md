# Audit & Build Aegis with Any AI Assistant

Don't want to read TypeScript and C# yourself, and don't want to trust prebuilt binaries? Point **any** AI coding tool (Google Antigravity, Claude Code, Cursor, GitHub Copilot, ChatGPT, or Gemini) at this folder and paste the prompts below.

---

## Prompt 1 — Full Security, Isolation & Data-Exfiltration Audit

> ```text
> Audit the `aegis-wallet-shield` repository thoroughly before I use it.
> 1. Search every `.ts`, `.js`, `.mjs`, `.html`, `.cs`, `.ps1`, and `.bat` file for network calls (`fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, `System.Net`, `HttpClient`, `WebClient`, `Sockets`, external `<script>`/`<img>`/`<link>` URLs, or `Process.Start`). List every single occurrence with file path and line number.
> 2. Verify complete isolation between the two tools: confirm the browser extension has NO `nativeMessaging` permission or `connectNative` calls, and confirm `clipguard-helper` has ZERO network APIs and ZERO Windows Registry writes.
> 3. Trace every place clipboard text, pasted text, Notepad `.bin` files, Sticky Notes, or swept local files are read. Confirm whether raw secret keys or BIP-39 words can ever be written to `chrome.storage`, disk, console logs, UI labels, or network requests.
> 4. Give me a blunt verdict: can any recovery phrase or private key leave my computer or be stored unmasked? Flag anything questionable with exact file and line numbers.
> ```

---

## Prompt 2 — Permission & Windows API Review

> ```text
> Read `extension/static/manifest.template.json` and `clipguard-helper/src/`.
> Explain every Chrome extension permission (`clipboardRead`, `clipboardWrite`, `offscreen`, `declarativeNetRequest`, `<all_urls>`, optional `history` and `management`) and every Windows/WinRT API Clip Guard calls (`Clipboard`, `FileSystemWatcher`, `OcrEngine`, `System.Windows.Forms`).
> For each one, verify how it is used in the code and tell me whether its scope is minimal and justified.
> ```

---

## Prompt 3 — Have Your AI Compile & Verify Everything Locally for You

> ```text
> Build `aegis-wallet-shield` from source on my Windows machine and verify all safety checks:
> 1. Run `powershell -ExecutionPolicy Bypass -File scripts/verify-security.ps1` and confirm zero unauthorized network calls, zero nativeMessaging bridges, and zero Registry writes.
> 2. Run `clipguard-helper\build.bat` and `clipguard-helper\tests\run-tests.bat` using Windows' built-in C# compiler (`csc.exe`) and report the test results.
> 3. In `extension/`, run `npm ci`, `npm run build`, `npx tsc --noEmit`, and `npm test`.
> 4. Show me the exact folder path to load into `chrome://extensions` -> "Load unpacked", and the path to the standalone `aegis-clipguard.exe` desktop cleaner.
> ```

---

## Grep Tags Built Into the Codebase

Every sensitive line in Aegis is tagged so humans and AI assistants can grep the whole codebase in one second:

```powershell
Select-String -Path extension\src\**\*.ts, clipguard-helper\src\**\*.cs -Pattern "AEGIS-(NETWORK|PERMISSION|SECURITY):"
```

- `AEGIS-NETWORK:` — outbound network requests (appears **only** in `extension/src/background/analysis/rpc.ts`).
- `AEGIS-PERMISSION:` — browser or OS API calls touching clipboard, process check, or file cleanup.
- `AEGIS-SECURITY:` — memory zeroing, shadow DOM isolation, `event.isTrusted` enforcement, and sender privilege checks.
