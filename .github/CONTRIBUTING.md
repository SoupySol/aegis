# Contributing to Project Aegis ($AEGIS)

Thank you for your interest in contributing to **Project Aegis**! Aegis is an open-source, local-first security layer designed to protect Solana traders, developers, and crypto users against clipboard manipulation, lookalike addresses, malicious transaction simulations, and accidental seed phrase leakage.

Because Aegis protects user funds and sensitive crypto operations, we maintain exceptionally high security, code quality, and transparency standards.

---

## Code of Conduct

All contributors, maintainers, and community members are expected to uphold the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Please treat everyone with respect and kindness.

---

## Repository Architecture

The repository is organized into distinct, air-gapped components:

```
aegis-wallet-shield/
├── extension/          # Aegis Browser Guard (Manifest V3, TypeScript, esbuild)
│   ├── src/background/ # Service worker, transaction simulation & rule engine
│   ├── src/inpage/     # Injected provider proxy & Wallet Standard interceptor
│   ├── src/content/    # Content script & Paste Guard closed-shadow-root banner
│   ├── src/offscreen/  # Offscreen document for clipboard hash poller
│   ├── src/review/     # Extension-owned review popup window UI
│   └── tests/          # Vitest unit tests & Playwright E2E suites
├── clipguard-helper/   # Aegis Clip Guard (C# .NET 8 portable Windows desktop app)
│   ├── src/            # Standalone zero-network clipboard cleaner & file scanner
│   └── tests/          # Unit test suite for C# scanner & regex engines
├── scripts/            # Build automation & automated security verification harnesses
├── docs/               # Technical specs, threat model, permissions, and audit docs
└── shared-fixtures/    # Test attack vectors, lookalikes, and known benign/malicious payloads
```

---

## Development Setup

### Prerequisites
- **Node.js**: v20+ or v22 LTS
- **npm**: v10+
- **.NET 8.0 SDK**: (Required if working on `clipguard-helper/`)
- **PowerShell Core (pwsh)** or **Windows PowerShell**: (For running build and verification scripts)

### Getting Started

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SoupySol/aegis.git
   cd aegis
   ```

2. **Install extension dependencies**:
   ```bash
   cd extension
   npm install
   ```

3. **Build the extension**:
   ```bash
   npm run build
   ```
   Built extension artifacts are output to `extension/dist/extension/`.

4. **Load into Browser for Manual Testing**:
   - Open Chrome, Brave, or Edge.
   - Navigate to `chrome://extensions/`.
   - Enable **Developer mode** (top right).
   - Click **Load unpacked** and select `extension/dist/extension/`.

---

## Verification & Testing

Before submitting any code changes, verify that all test suites and automated security scanners pass cleanly:

### 1. Extension Unit Tests
Run the fast Vitest unit test suite (100+ tests covering decoders, rules, domain lookalikes, secret detectors, and wire parsers):
```bash
cd extension
npm test
```

### 2. Extension End-to-End Suites
Run the Playwright E2E suites (verifies real Chromium extension loading, mock dApp interactions, Paste Guard isolation, and deep QA adversarial probes):
```bash
cd extension
npx playwright install chromium   # If not already installed
npm run test:e2e
node tests/e2e/e2e-qa-deep.mjs
```

### 3. Clip Guard .NET Tests (Windows)
```bash
cd clipguard-helper
dotnet test tests/AegisClipGuard.Tests.csproj
```

### 4. Repository Security Verification Harness
Run the automated 8-invariant security audit script:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify-security.ps1
```
This script validates:
- [x] Extension network allowlist (strictly `extension/src/background/analysis/rpc.ts`)
- [x] Zero `eval()`, `new Function()`, or dynamic `<script>` execution
- [x] Extension is 100% isolated from native processes (zero `nativeMessaging`)
- [x] Clip Guard desktop application contains zero network code (`check-no-network.ps1`)
- [x] Clip Guard source contains zero Windows Registry writes or reads
- [x] All `.ts` and `.cs` source files carry structured `@purpose` and `@access` headers
- [x] No `.env` files committed
- [x] No hardcoded RPC keys or private keys in source

### 5. Dependency Audit
Ensure dependencies contain zero known vulnerabilities:
```bash
cd extension
npm audit
```

### 6. Full Release Build Verification
To execute the complete pipeline (deps, builds, tests, zip archives, SHA256 checksums):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -InstallDeps
```

---

## Non-Negotiable Security Invariants

All contributions must strictly respect these design invariants:

1. **Air-Gap Separation**: The browser extension and the desktop helper must never be bridged via `nativeMessaging`, local webservers, or shared storage.
2. **Zero Involuntary Network Calls**: The browser extension must never phone home, send telemetry, or connect to remote servers other than the RPC endpoint explicitly configured for transaction simulation.
3. **Clip Guard Zero-Network Guarantee**: The Windows desktop helper has zero networking capabilities. It cannot make HTTP/socket calls and cannot write to the Windows Registry.
4. **Memory Hygiene**: Any buffer holding private keys or seed words must be zeroized in `finally` blocks (`seed.fill(0)` / `Array.Clear()`).
5. **No Blind Dependency Bloat**: We maintain a lean dependency tree using audited crypto libraries (`@noble/curves`, `@scure/bip39`, `@scure/base`). Do not introduce runtime dependencies into the browser bundle without maintainer discussion.
6. **Mandatory Header Comment**: Every `.ts` and `.cs` source file must start with a comment block detailing file purpose, network access, and security invariants.

---

## Pull Request Guidelines

1. **Create a branch**: Fork the repository and create a feature branch (`git checkout -b feature/my-feature`).
2. **Commit hygiene**: Write clear, descriptive commit messages. Ensure line endings conform to `.gitattributes`.
3. **Fill the PR template**: Complete all sections of the [Pull Request Template](pull_request_template.md).
4. **CI Green**: Verify that all CI checks (linting, tests, security verifications, and CodeQL scanning) pass.
5. **No Secrets**: Never include real private keys, seed phrases, or production API keys in commits, test fixtures, or PR discussions. Use dummy/synthetic keys only.

Thank you for helping keep the Solana ecosystem safe!
