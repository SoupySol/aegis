# Outbound Network Map (`AEGIS-NETWORK`)

Aegis operates **zero backend servers, zero analytics, zero crash reporting, and zero telemetry**.

Every outbound network call in the entire repository is tagged with `// AEGIS-NETWORK:` and verified on every build by [`scripts/verify-security.ps1`](../scripts/verify-security.ps1).

---

## 1. Clip Guard Windows Helper (`clipguard-helper/`)

**Outbound network requests: ZERO.**

- Clip Guard does not import `System.Net`, `Sockets`, `HttpClient`, `WebClient`, or `WebRequest`, and never opens URLs.
- [`clipguard-helper/tools/check-no-network.ps1`](../clipguard-helper/tools/check-no-network.ps1) fails the build if any networking namespace or `http://` / `https://` string is introduced in `clipguard-helper/src/`.

---

## 2. Aegis Browser Extension (`extension/`)

**Outbound network requests: 1 module only — [`extension/src/background/analysis/rpc.ts`](../extension/src/background/analysis/rpc.ts).**

| Caller File | Destination | When Called | Data Sent | Credentials / Cookies |
| :--- | :--- | :--- | :--- | :--- |
| `extension/src/background/analysis/rpc.ts` (`createRpcClient`) | Public Solana Mainnet JSON-RPC (`https://api.mainnet-beta.solana.com`, with automatic rate-limit failover to `https://solana.publicnode.com`). | Only when a website asks your browser wallet to sign a transaction (`getMultipleAccounts`, `simulateTransaction`, `getSlot`). Connect & `signMessage` previews make **zero** network calls. | Public on-chain data only: unsigned transaction bytes proposed by the website and public account addresses referenced in the transaction. | `credentials: 'omit'`, `cache: 'no-store'` |

### What Is NEVER Sent Over the Network
- Clipboard contents, pasted text, or typed form words
- Seed phrases, private keys, or session fingerprints
- File paths, Notepad tab labels, or Secret Sweep findings
- Browser history URLs or installed extension lists

