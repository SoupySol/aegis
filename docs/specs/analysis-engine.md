# Spec: Transaction Preview Engine

Part of **Aegis Browser Guard**, an open-source wallet-safety browser extension. When a website asks the user's wallet to sign, Aegis decodes and previews the transaction in plain language before the wallet opens. The engine only sees serialized transaction bytes and public Solana JSON-RPC responses.

## Location
- Source: `extension/src/background/analysis/`
- Known program list: `extension/src/shared/known-programs.ts`
- Tests: `extension/tests/unit/analysis/`
- Contract: `extension/src/shared/analysis-types.ts`

## Public API (`analysis/index.ts`)
- `analyzeTransactions(req: AnalyzeTransactionsRequest, opts: { rpc: RpcClient | null }): Promise<AnalysisReport>`
- `analyzeMessage(req: AnalyzeMessageRequest): AnalysisReport`
- `createRpcClient(url: string, fetchImpl?: typeof fetch): RpcClient`: JSON-RPC 2.0, ~8s timeout, tagged `// AEGIS-NETWORK:` (the single network call site in the entire extension). Enforces `https://` (or `http://localhost` / `127.0.0.1`).

## Wire & Message Decoder Constraints
- Zero runtime dependency on `@solana/web3.js` in `src/`.
- Custom wire-format decoder supporting **`legacy`**, **`v0`** (with Address Lookup Tables), and **`v1` (SIMD-0385)** transactions (`0x81` version prefix, 16-byte transaction config mask, variable config values, inline static keys + instructions, no LUTs).
- Lookup tables (`v0`): resolved via `getMultipleAccounts` (`base64`), 56-byte header + 32-byte addresses, ordered `[static, writableLookups, readonlyLookups]`.

## Instruction Decoders & Known Programs
- Decoders: System, SPL Token, Token-2022 (including `TransferCheckedWithFee` disc 26/1), Stake, Upgradeable Loader (verifying `acct.owner === BPF_UPGRADEABLE_LOADER_ID`), Compute Budget (ceiling division on `microLamports`), Associated Token Account, Memo.
- Known programs: Core Solana programs plus Pump.fun, PumpSwap, Raydium (AMM v4, CPMM, CLMM), Jupiter v6, Meteora DLMM, Orca Whirlpool, Metaplex Token Metadata, and official Jito tip accounts.

## Preview via Simulation
1. Fetch pre-state of `[wallet + writable accounts]` via `getMultipleAccounts`, automatically falling back from 100-key chunks to 10-key chunks for public RPCs with stricter batch caps (such as `https://solana.publicnode.com`).
2. Prioritize user-owned writable token accounts and restrict `simulateTransaction.accounts.addresses` to accounts present in the transaction's account key list (preventing Agave `-32602` rejections).
3. Call `simulateTransaction` with `sigVerify: false`, `replaceRecentBlockhash: true`, `commitment: 'processed'`, `innerInstructions: true`, and `accounts` (`base64`).
4. Diff pre/post SOL balances, token balances per mint, token account owner/delegate/close authorities, wallet account owner (`Assign`), and Token-2022 mint extensions (permanent delegate, transfer hook, transfer fee, freeze authority).

## Rules -> Findings
- **Critical (`DANGER`):** Wallet `Assign` / owner change; token account owner change; wallet-authorized stake authority or upgrade authority change; multi-token drain without meaningful inflow (>= 0.01 SOL after subtracting reclaimed rent from closed user ATAs); transaction bytes disguised inside `signMessage`.
- **High (`DANGER`):** >90% SOL drain without inflow; Trojan micro-swap paired with large direct `system:transfer` to an unknown EOA; unrevoked token `Approve` delegate; close authority change; `CloseAccount` rent sent to third party; lookalike destination address; Token-2022 permanent delegate on received mint; SIWS domain mismatch.
- **Medium (`CAUTION`):** wallet-authorized durable nonce advance; recently deployed unknown program; priority fee > 0.05 SOL; freeze authority / transfer hook / transfer fee on received mint; binary/missing `signMessage` payload.
- **Safe exemptions:** official Jito tip transfers, aggregate small router/fee transfers (<= 2% of swap value), wSOL closes back to the wallet, partially signed Pump.fun token creation transactions.
