# Don't Trust Us — Verify Aegis Yourself

Wallet safety software asks for high-trust permissions (clipboard cleanup and pre-wallet transaction previews). You should **never** take any developer's word for it.

Here are **four ways to verify Aegis**, ordered from 10 seconds to a full from-source build:

---

## Level 1: Check the SHA-256 File Hash (10 seconds)

Compare the files you downloaded against `SHA256SUMS.txt` from the official GitHub Release:

```powershell
Get-FileHash .\Aegis-BrowserGuard.zip, .\Aegis-ClipGuard-Windows.zip -Algorithm SHA256
```

Verify that every character matches `SHA256SUMS.txt`.

---

## Level 2: Verify GitHub Build Provenance Attestation (30 seconds)

Tagged releases are built by the public GitHub Actions workflow in [`.github/workflows/ci-and-release.yml`](../.github/workflows/ci-and-release.yml) and cryptographically attested by GitHub:

```powershell
gh attestation verify Aegis-ClipGuard-Windows.zip --repo <owner>/aegis-wallet-shield
```

This proves the `.zip` and `.exe` came directly from an unedited public CI run on the exact commit in this repository — not from a developer's laptop.

---

## Level 3: Run the Automated Local Security & Isolation Audit (15 seconds)

Clone this repository and run our standalone static audit script in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\verify-security.ps1
```

`verify-security.ps1` inspects every source file and fails immediately if:
1. Any extension `.ts` file calls `fetch`, `XMLHttpRequest`, `WebSocket`, or `sendBeacon` outside files explicitly marked `AEGIS-NETWORK:` (only [`extension/src/background/analysis/rpc.ts`](../extension/src/background/analysis/rpc.ts)).
2. Any extension file uses `eval()`, `new Function()`, remote `<script>` tags, or `nativeMessaging` / `connectNative` bridges.
3. Any Clip Guard `.cs` file references `System.Net`, `Sockets`, `HttpClient`, `WebClient`, `WebRequest`, `http://` / `https://` URLs, or `Microsoft.Win32.Registry`.
4. Any source file is missing its `PURPOSE:` / `ACCESS:` transparency header.

You can also have any AI coding assistant audit the entire codebase for you using the ready-to-paste prompts in [AI-AUDIT.md](AI-AUDIT.md).

---

## Level 4: Read the Non-Minified Bundle or Compile Clip Guard Locally (2 seconds)

- **Browser Extension**: Our build script ([`extension/scripts/build.mjs`](../extension/scripts/build.mjs)) runs `esbuild` with `minify: false`. Open `dist/extension/background.js`, `content.js`, `inpage.js`, or `offscreen.js` in Notepad — every variable name and `// AEGIS-*` comment is human-readable.
- **Standalone Clip Guard `.exe`**: Windows 10 and Windows 11 ship with Microsoft's C# compiler (`csc.exe`) built into `%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`. You do **not** need Visual Studio, Rust, or any SDK download. Simply double-click:
  ```text
  clipguard-helper\build.bat
  ```
  In ~2 seconds, your own copy of Windows compiles `clipguard-helper\bin\aegis-clipguard.exe` directly from the `.cs` files you can read.
