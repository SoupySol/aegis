## Description
<!-- Provide a clear, concise summary of the changes in this pull request -->

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Security hardening / invariant enhancement
- [ ] Performance improvement
- [ ] Documentation update
- [ ] CI/CD or build automation update

## Affected Components
- [ ] `extension/` (Browser Guard: inpage, content, background, offscreen, review popup)
- [ ] `clipguard-helper/` (Clip Guard: Windows desktop cleaner & scanner)
- [ ] `scripts/` (Build & security verification automation)
- [ ] `docs/` (Architecture, security, specifications)
- [ ] `shared-fixtures/` (Test vectors & adversarial attack cases)

---

## Security & Architecture Checklist
> [!IMPORTANT]
> All pull requests must satisfy Project Aegis's core security invariants prior to merge.

- [ ] **No Secrets**: Verified no real private keys, seed phrases, or production API tokens are present in commits, diffs, or test files.
- [ ] **Headers Verified**: All new or modified `.ts` and `.cs` files include the required `@purpose` / `@access` header comment block.
- [ ] **Network Allowlist**: Extension does not make network calls outside `extension/src/background/analysis/rpc.ts`.
- [ ] **No Native Messaging**: Manifest does not request or use `nativeMessaging` permission.
- [ ] **Clip Guard Offline Guarantee**: Desktop helper introduces no network dependencies (`System.Net`, HTTP, sockets) and zero Windows Registry access.
- [ ] **Memory Hygiene**: Decoded secret buffers and seed phrases are explicitly wiped (`seed.fill(0)` / `Array.Clear()`) in `finally` blocks.
- [ ] **No eval()**: No use of `eval()`, `new Function()`, or dynamic remote script injection.

---

## Verification & Testing
Please check the verification steps performed:

- [ ] `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify-security.ps1` passes (8/8 checks)
- [ ] `cd extension && npm audit` reports 0 vulnerabilities
- [ ] `cd extension && npm test` passes (unit tests)
- [ ] `cd extension && npm run test:e2e` passes (Playwright E2E)
- [ ] `cd extension && node tests/e2e/e2e-qa-deep.mjs` passes (deep QA adversarial suite)
- [ ] `cd clipguard-helper && dotnet test tests/AegisClipGuard.Tests.csproj` passes (if C# modified)

---

## Related Issues
<!-- Link related issues using GitHub keywords, e.g. Fixes #123 -->
Fixes #
