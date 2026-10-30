# Extending & Forking Project Aegis ($AEGIS)

This guide is written for developers and organizations who want to **fork Project Aegis**, build custom white-label editions, implement enterprise transaction rules, or adapt the architecture for their own communities.

---

## 1. Overview & Trust Philosophy

Aegis is built around a single foundational premise: **security software must be radically transparent and mathematically auditable**.

Crypto users and security auditors are rightly suspicious of extensions that request invasive permissions, bundle obfuscated minified scripts, connect to closed backend servers, or execute background daemons. Aegis was engineered from day one to achieve the **highest trust score possible** on GitHub, VirusTotal, and Chrome Web Store static analysis scanners:

1. **Zero Minification or Code Obfuscation**: All builds in `dist/` remain clean, readable TypeScript and C#. Reviewers and auditors can read the exact code that runs on their machines without decompilers.
2. **Zero Backend Telemetry**: Aegis has no analytics, no tracking beacons, no Sentry, and no database. The extension talks **only** to public Solana RPC nodes to simulate transactions before signing.
3. **Strict Air-Gap Separation**: The browser extension and the Windows desktop cleanup app are 100% independent. The extension contains **zero** `nativeMessaging` permissions and **zero** binary bridges.
4. **Deterministic Builds & Icon Generation**: All PNG icons are generated mathematically at build time using Node's built-in `zlib`—there are zero opaque binary blobs committed to git.
5. **Standardized PURPOSE / ACCESS Headers**: Every source file carries a standardized header explaining its exact purpose, permissions, and security invariants.

---

## 2. White-Labeling & Branding Customization

### Renaming the Extension
1. **Manifest Template (`extension/static/manifest.template.json`)**:
   Modify `name`, `short_name`, and `description`:
   ```json
   {
     "name": "YourBrand Wallet Shield",
     "short_name": "YourBrand",
     "description": "Pre-wallet transaction preview and clipboard protection for Solana."
   }
   ```
2. **Package Configuration (`extension/package.json`)**:
   Update `name`, `version`, and `author`.

### Customizing Icons & Heraldry
Aegis does not store static image files in the repository. Instead, `extension/scripts/build.mjs` mathematically generates crisp, multi-scale RGBA PNG icons (`icon16.png`, `icon48.png`, `icon128.png`) using 16x supersampled polygon ray-casting and pure Node `zlib.deflateSync`.

To change the icon design or colors:
1. Open `extension/scripts/build.mjs`.
2. Inspect `sampleShieldPixel(nx, ny)` (lines 162–191).
3. Adjust the color ramps:
   - Outer metallic rim: Modify the RGB calculation (currently emerald green `#10B981`).
   - Core body: Adjust the obsidian facet colors.
   - Monogram: Replace `pointInLetterA` with your project's letterform polygon or emblem coordinates.
4. Running `node scripts/build.mjs` automatically regenerates all three icons in `dist/extension/`.

### Deterministic Extension Public Key & ID
In Chromium-based browsers, an unpacked extension's ID is derived from its public key. If the key changes, the extension ID changes, which can reset local settings.
* The fixed key is stored in `extension/static/extension-key.txt`.
* To generate your own permanent key:
  ```bash
  # Generate a 2048-bit RSA private key
  openssl genrsa 2048 | openssl rsa -pubout -outform DER | openssl base64 -A > extension/static/extension-key.txt
  ```
* `build.mjs` will automatically inject this key into `dist/extension/manifest.json` on every build.

### UI Themes & Visual Styles
* **Popup & Review Windows**: Styles are located in `extension/src/ui/styles.css`.
* Colors follow a high-contrast dark cyberpunk palette (`#0B0F17`, `#0E131B`, emerald `#10B981`, amber `#F59E0B`, crimson `#EF4444`).
* All UI layouts are pure HTML/CSS with zero external CSS frameworks (no Tailwind or Bootstrap runtime overhead).

---

## 3. Adding Custom Enterprise Policies & Network Rules

Organizations deploying Aegis for internal teams (trading desks, treasuries, hedge funds) can enforce corporate security policies:

### 1. Enforcing a Dedicated Corporate RPC
In `extension/src/shared/settings.ts`:
Modify `DEFAULT_MAINNET_RPC_URL` or lock the settings so users cannot select third-party public endpoints:
```typescript
export const DEFAULT_MAINNET_RPC_URL = 'https://solana-rpc.internal.yourfirm.com';
export const FALLBACK_MAINNET_RPC_URL = 'https://solana-rpc-backup.internal.yourfirm.com';
```

### 2. Whitelisting Internal Programs & Multisigs
In `extension/src/shared/known-programs.ts`:
Add your company's smart contracts, Squads multisigs, or internal staking programs to `KNOWN_PROGRAMS`:
```typescript
export const FIRM_TREASURY_VAULT = 'VaultAddress111111111111111111111111111111';

export const KNOWN_PROGRAMS: Readonly<Record<string, KnownProgram>> = {
  // ...
  [FIRM_TREASURY_VAULT]: { name: 'Acme Treasury Vault', category: 'core' },
};
```

### 3. Restricting High-Value Transfers or Requiring Mandatory Review
In `extension/src/background/review-manager.ts`:
You can adjust the fast-path conditions in `isCleanBuyOrSellSwap`. For example, to require human review for any transaction transferring more than 5 SOL regardless of DEX routing:
```typescript
// Inside isCleanBuyOrSellSwap():
const solChange = tx.balanceChanges.find(b => b.asset === 'SOL');
if (solChange && BigInt(solChange.rawChange) < -5_000_000_000n) {
  return false; // Force interactive review modal for trades > 5 SOL
}
```

---

## 4. Extending Clip Guard (Windows Desktop Cleaner)

`clipguard-helper` is designed to be a standalone, self-contained C# utility compiled directly by Windows' built-in `csc.exe` (.NET 4.8).

### Adding New Ghost Copy Scan Locations
To add scanning support for an additional desktop application (e.g. Telegram Desktop cache, Slack local cache, or developer IDE state):

1. **Create a Source File**: Create `clipguard-helper/src/Sources/YourApp.cs`.
2. **Implement Non-Blocking File Reading**:
   Always open files with `FileShare.ReadWrite | FileShare.Delete` so the target application is never blocked:
   ```csharp
   using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
   {
       // Read and decode text runs...
   }
   ```
3. **Execute Secret Detection**:
   Pass extracted text to `SecretDetector.DetectAll(extractedText)`.
4. **Wipe Raw Memory Buffers**:
   Always call `Array.Clear(buffer, 0, buffer.Length)` in a `finally` block to prevent lingering plaintext secrets in RAM.
5. **Register in `GhostScan.cs`**:
   Add a call to your scanner in `GhostScan.Run()`.

---

## 5. Maximizing Trust Score on GitHub & Security Scanners

When releasing your fork to the public, following these practices ensures maximum trust:

### 1. Maintain the Zero-Network Constraint
Keep outbound network requests strictly isolated to `extension/src/background/analysis/rpc.ts`. If an auditor runs:
```powershell
Select-String -Path extension\src\**\*.ts -Pattern "\b(fetch|XMLHttpRequest|WebSocket)\b"
```
It should report **only** `rpc.ts`.

### 2. Retain Security Headers
Every source file should keep its `PURPOSE:` and `ACCESS:` documentation block. Automated security checkers (including `scripts/verify-security.ps1`) verify these headers to ensure code traceability.

### 3. Provide One-Click Reproducible Builds
Include `build.bat` and `scripts/build.ps1` in your repository. When users clone your fork, they should be able to run `build.bat` and produce byte-identical releases with matching SHA-256 sums without having to install complicated toolchains.

### 4. Code Signing (Optional)
If your organization owns an Authenticode code-signing certificate:
```cmd
signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a dist\aegis-clipguard.exe
```
This removes the Windows SmartScreen "Unknown Publisher" prompt on fresh downloads. If unsigned, provide clear instructions pointing users to compile directly via `csc.exe` using `clipguard-helper\build.bat`.

---

## 6. Build and Verification Reference

Run the complete test and verification suite:

```bat
build.bat
```

For custom builds without running the full unit test suite during rapid prototyping:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -SkipTests
```

To run only the static security audit:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify-security.ps1
```
