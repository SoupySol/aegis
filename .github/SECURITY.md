# Security Policy

Project Aegis ($AEGIS) is dedicated to protecting Solana traders and users from clipboard hijackers, address-poisoning attacks, malicious transaction simulations, and accidental seed phrase leakage.

We take the security and integrity of Aegis extremely seriously. Because Aegis is designed as an adversarial defense layer for digital assets, we encourage responsible disclosure of any vulnerabilities, bypasses, or unexpected behavior.

---

## Supported Versions

Security updates and patches are actively provided for the following versions:

| Version | Supported          | Status                                 |
| ------- | ------------------ | -------------------------------------- |
| 0.1.x   | :white_check_mark: | Current active release                 |
| < 0.1   | :x:                | Pre-release prototypes (unsupported)   |

---

## Reporting a Vulnerability

> [!IMPORTANT]
> **DO NOT file public GitHub issues for undisclosed security vulnerabilities.**
> Publicly disclosing a live vulnerability puts community users and their funds at risk.

### 1. Preferred Method: GitHub Private Vulnerability Reporting
Please report security vulnerabilities privately via GitHub Security Advisories:
1. Navigate to the **Security** tab of the Aegis repository.
2. Select **Advisories** under "Security overview".
3. Click **Report a vulnerability** to open a private advisory draft.

This ensures all details remain confidential while the maintainers triage, patch, and coordinate a release.

### 2. Alternative Contact
If you cannot use GitHub Security Advisories, contact the core team privately:
- **Email**: `security@projectaegis.io` (or maintainer contact listed on repository profile)
- Subject: `[SECURITY] Vulnerability Report: Aegis <Component>`

---

## What to Include in Your Report

To help us triage and resolve your report quickly, please provide:
1. **Affected Component**:
   - `extension/` (Aegis Browser Guard: inpage gate, paste guard, transaction simulation/review, offscreen poller)
   - `clipguard-helper/` (Aegis Clip Guard: Windows desktop cleaner and scanner)
   - Build scripts / CI workflow (`scripts/`, `.github/workflows/`)
2. **Vulnerability Type**:
   - In-page isolation bypass, prototype pollution, cross-origin/cross-realm leak
   - Clipboard regex / BIP-39 detector false negative or bypass
   - Transaction decoder desync or TOCTOU payload substitution
   - Unauthorized network communication or policy violation
3. **Reproduction Steps**:
   - Clear, step-by-step instructions or test script.
   - **CRITICAL**: Use **throwaway testnet/devnet keys or freshly generated dummy keys only**. Never transmit or include keys, seed phrases, or credentials associated with funded wallets.
4. **Impact Assessment**:
   - Realistic assessment of what an attacker could achieve.
5. **Proposed Fix** (optional):
   - Suggested patch or code diff if available.

---

## Response & Disclosure Process

- **Initial Triage**: We acknowledge receipt within **48 hours** and provide an initial severity assessment.
- **Investigation & Patch**: We work collaboratively with the reporter to investigate, write regression tests, and develop a patch.
- **Coordination**: We coordinate a release date and credit the researcher in release notes (unless anonymity is requested).
- **Public Disclosure**: A public security advisory is published once the fix is deployed and users have had sufficient time to update.

---

## Architecture & Threat Model

For an in-depth breakdown of Aegis's zero-network boundary, memory wiping, air-gap separation, and honest limitations, please consult the complete architectural document:
- [Security Model & Architecture (docs/SECURITY.md)](../docs/SECURITY.md)
- [Privacy Policy & Network Invariants (docs/PRIVACY.md)](../docs/PRIVACY.md)
- [Verification Guide (docs/VERIFY.md)](../docs/VERIFY.md)
