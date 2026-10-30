# Aegis Rules Specification Reference

This document provides the complete rule mapping used by Aegis's transaction analysis engine in `extension/src/background/analysis/rules.ts` and `clipguard-helper/src/Detection/SecretDetector.cs`.

---

## 1. On-Chain Threat Ruleset

| Rule ID | Severity | Program ID / Instruction | Threat Description & Trigger Condition | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| `wallet-owner-reassignment` | **Critical** | `11111111111111111111111111111111` (`System: Assign`, `AssignWithSeed`, `CreateAccount`) | Changes account owner of the connected wallet pubkey from System Program to a third-party program. | Verdict: `DANGER`. Locks approval button until explicit risk checkbox is clicked. |
| `token-account-owner-change` | **Critical** | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` (`Token: SetAuthority(AccountOwner)`) | Reassigns full permanent ownership of a user token account to an unrecognized address. | Verdict: `DANGER`. Surfaces account balance at risk. |
| `stake-authority-change` | **Critical** | `Stake11111111111111111111111111111111111111` (`Stake: Authorize`) | Transfers stake or withdrawal authority over a stake account. | Verdict: `DANGER`. |
| `program-upgrade-authority-change` | **Critical** | `BPFLoaderUpgradeab1e11111111111111111111111` (`UpgradeableLoader: SetAuthority`) | Replaces the upgrade authority of an on-chain program. | Verdict: `DANGER`. |
| `multi-token-drain` | **Critical** | Simulation balance diff / decoded token transfers | Two or more distinct token accounts have negative outflows with zero incoming tokens and < 0.01 SOL inflow. | Verdict: `DANGER`. |
| `message-is-transaction` | **Critical** | Off-chain `signMessage` or `signIn` | Raw message bytes decode successfully as a serialized legacy, v0, or bare transaction message. | Verdict: `DANGER`. Disguised transaction alert. |
| `lingering-delegate-approval` | **High** | `Token: Approve`, `Token: ApproveChecked` | Grants an active spending allowance (`amount > 0`) to an unrecognized address that remains open after execution. | Flagged as `UNLIMITED` if `>= 2^63 - 1`. Shows token, limit, and current balance. |
| `sol-drain-over-90pct` | **High** | Simulation balance diff | Transaction transfers out > 90% of current wallet SOL with zero incoming tokens. | Verdict: `DANGER`. |
| `close-account-foreign-destination` | **High** | `Token: CloseAccount` | Reclaims token account rent deposit but routes the SOL to an address other than the wallet. | Verdict: `DANGER`. Flagged as Rent Redirect. |
| `lookalike-destination` | **High** | Any transfer / ATA create destination | Recipient address has matching first 4 and last 4 characters to user's wallet, but different middle bytes (address poisoning). | Verdict: `DANGER`. |
| `received-mint-permanent-delegate` | **High** | Token-2022 mint TLV extension | Incoming token specifies a permanent delegate authority that can seize or burn tokens at any time. | Verdict: `DANGER`. |
| `siws-domain-mismatch` | **High** | Sign-In With Solana header | Claimed domain in message (e.g. `jup.ag`) does not match the active webpage origin host. | Verdict: `DANGER`. |
| `siws-uri-mismatch` | **High** | Sign-In With Solana URI field | URI in message points to an external destination host. | Verdict: `DANGER`. |
| `unreadable-transaction-input` | **High** | Batch signing (`signAllTransactions`) | One or more transaction objects in a batch fail to serialize or cannot be decoded. | Verdict: `DANGER`. Prevents Trojan batch hiding. |
| `lookalike-domain` | **High** | Webpage origin URL | Domain is a Punycode homograph, confusable typosquat, or brand + lure keyword combination. | Verdict: `DANGER`. "Lookalike warning!" badge. |
| `received-mint-freeze-authority` | **Medium** | Mint account header | Non-standard token mint has active freeze authority enabled. | Verdict: `CAUTION`. |
| `received-mint-transfer-extension` | **Medium** | Token-2022 mint TLV extension | Incoming token charges built-in transfer fee or invokes custom transfer hook program. | Verdict: `CAUTION`. |
| `durable-nonce` | **Medium** | `System: AdvanceNonceAccount` | Transaction uses durable nonce instead of standard recent blockhash. Valid indefinitely until nonce advances. | Verdict: `CAUTION`. |
| `unknown-program-recent` | **Medium** | Program accounts | Invokes unverified program deployed within the last ~24 hours (216,000 slots). | Verdict: `CAUTION`. |
| `high-priority-fee` | **Medium** | `ComputeBudget` / `v1` config | Priority fee exceeds 0.05 SOL (50,000,000 lamports). | Verdict: `CAUTION`. |
| `insecure-http-origin` | **Medium** | Gate request origin | Wallet connection attempted over unencrypted HTTP (non-localhost). | Verdict: `CAUTION`. |
| `unknown-program` | **Low** | Program accounts | Invokes program not present on Aegis's recognized program catalog. | Info notice. |
| `normal-swap` | **Safe** | Recognized Solana DEX programs | Verified swap with zero approvals, zero authority changes, and genuine asset exchange. | Fast-path: passes directly to wallet with 0 popups. |

---

## 2. Recognized Solana DEX Programs (Benign Swap Allowlist)

Transactions routing exclusively through these programs with zero approvals or drain patterns are fast-pathed:
- **Pump.fun**: `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P`
- **PumpSwap AMM**: `pAMMT7dfScrt5VcaLyAMm4sVsNu1moxkxAAmxXUupdH`
- **Jupiter v6**: `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4`
- **Jupiter v4**: `JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB`
- **Raydium AMM v4**: `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8`
- **Raydium CPMM**: `CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C`
- **Raydium Concentrated Liquidity (CLMM)**: `CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK`
- **Meteora Dynamic Pools**: `Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB`
- **Meteora DLMM**: `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPpuX`
- **Orca Whirlpools**: `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc`
- **Phoenix**: `PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY`
- **Moonshot**: `MSHOTybmPnbpHz4S5AAtwEkSW9yJ9CjCjZ9Q2rN1Bup`
- **Sanctum S-Controller**: `5ocnV1qiCgaQR8Jb8xWnVbApNzpWCDfhjqkgtByKAwp`
- **DFlow**: `DFLow4tEbM7HmsQscH1a1dpB24i5y5V6N6hQ9P8jN1b`

