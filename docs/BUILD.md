# Building Aegis from Source

Aegis is designed so **any Windows 10 or Windows 11 user can compile it locally** without installing Visual Studio, Rust, C++ build tools, or giant SDKs.

---

## Prerequisites

| Component | Requirement | Why |
| :--- | :--- | :--- |
| **Standalone Clip Guard (`aegis-clipguard.exe`)** | **Nothing to install** on Windows 10/11 | Compiled by `%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`, which ships inside every copy of Windows 10 & 11 |
| **Browser Extension (`dist/extension/`)** | [Node.js LTS](https://nodejs.org/) (`v20+`, or `winget install OpenJS.NodeJS.LTS`) | Bundles TypeScript modules into readable, non-minified ES modules via `esbuild` |

---

## Option 1: Build Everything in One Click (`build.bat`)

From the repository root (`aegis-wallet-shield\`):

```bat
build.bat
```

Or in PowerShell:

```powershell
.\scripts\build.ps1 -InstallDeps
```

This runs all 5 steps:
1. Installs locked npm packages (`npm ci`) if needed.
2. Bundles the MV3 extension into `extension\dist\extension` (`minify: false` so output stays readable) and runs `tsc --noEmit` + Vitest unit tests.
3. Compiles standalone `clipguard-helper\bin\aegis-clipguard.exe` with Windows' built-in `csc.exe` and runs the full C# unit + stress test suites (`301` ed25519 vectors + `227` shared secret-detector corpus cases + synthetic Ghost Copy & NTFS junction/seam stress tests).
4. Runs `scripts\verify-security.ps1` (enforcing the network allowlist, zero `nativeMessaging` bridge, zero network in Clip Guard, and zero Registry writes).
5. Writes `dist\Aegis-BrowserGuard.zip`, `dist\Aegis-ClipGuard-Windows.zip`, `dist\aegis-clipguard.exe`, and `dist\SHA256SUMS.txt`.

---

## Option 2: Build Only Standalone Clip Guard (Zero Installs Needed)

Even on a brand-new Windows PC without Node.js installed, you can compile and test `aegis-clipguard.exe` immediately:

```bat
cd clipguard-helper
build.bat
tests\run-tests.bat
```

Output binary: `clipguard-helper\bin\aegis-clipguard.exe` (double-click to open the desktop window, or run `aegis-clipguard.exe --ghost-scan` in a terminal).

---

## Option 3: Build & E2E-Test Only the Browser Extension

```powershell
cd extension
npm ci
npm run build
npm test
npx playwright install chromium
node tests/e2e/e2e.mjs
node tests/e2e/e2e-qa-deep.mjs
```

Unpacked extension output: `extension\dist\extension\`.
