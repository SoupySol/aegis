/**
 * known-programs.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Static list of well-known Solana program IDs, a few well-known
 *           accounts (Jito tip accounts, wSOL / stablecoin mints) and their
 *           human-readable names. Used by the transaction preview engine to
 *           label programs and to decide what counts as "known".
 *
 * ACCESS:   Constant data only.
 *
 * NEVER:    - No network. No storage. No logic beyond lookups.
 *           - Only IDs we are sure of are listed. Anything doubtful is marked
 *             `// VERIFY` so a maintainer can confirm it against an explorer.
 *           - Being "known" only means "we can name it"; it is never treated
 *             as proof that a transaction is safe on its own.
 * ---------------------------------------------------------------------------
 */

export type ProgramCategory =
  | 'core' // native / runtime programs
  | 'token' // SPL token family
  | 'dex' // swaps, AMMs, aggregators, bonding curves
  | 'nft' // NFT / metadata programs
  | 'utility';

export interface KnownProgram {
  name: string;
  category: ProgramCategory;
}

export const SYSTEM_PROGRAM_ID = '11111111111111111111111111111111';
export const TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const TOKEN_2022_PROGRAM_ID = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const ASSOCIATED_TOKEN_PROGRAM_ID = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
export const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
export const MEMO_V1_PROGRAM_ID = 'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo';
export const COMPUTE_BUDGET_PROGRAM_ID = 'ComputeBudget111111111111111111111111111111';
export const STAKE_PROGRAM_ID = 'Stake11111111111111111111111111111111111111';
export const VOTE_PROGRAM_ID = 'Vote111111111111111111111111111111111111111';
export const BPF_UPGRADEABLE_LOADER_ID = 'BPFLoaderUpgradeab1e11111111111111111111111';
export const BPF_LOADER_2_ID = 'BPFLoader2111111111111111111111111111111111';
export const BPF_LOADER_1_ID = 'BPFLoader1111111111111111111111111111111111';
export const LOADER_V4_ID = 'LoaderV411111111111111111111111111111111111';
export const ADDRESS_LOOKUP_TABLE_PROGRAM_ID = 'AddressLookupTab1e1111111111111111111111111';
export const CONFIG_PROGRAM_ID = 'Config1111111111111111111111111111111111111';
export const ED25519_PROGRAM_ID = 'Ed25519SigVerify111111111111111111111111111';
export const SECP256K1_PROGRAM_ID = 'KeccakSecp256k11111111111111111111111111111';

export const PUMP_FUN_PROGRAM_ID = '6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P';
export const PUMP_SWAP_PROGRAM_ID = 'pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA';
export const RAYDIUM_AMM_V4_PROGRAM_ID = '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8';
export const RAYDIUM_CPMM_PROGRAM_ID = 'CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C';
export const RAYDIUM_CLMM_PROGRAM_ID = 'CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK';
export const RAYDIUM_ROUTING_PROGRAM_ID = 'routeUGWgWzqBWFcrCfv8tritsqukccJPu3q5GPP3xS';
export const RAYDIUM_LAUNCHLAB_PROGRAM_ID = 'LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj';
export const JUPITER_V6_PROGRAM_ID = 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4';
export const JUPITER_V4_PROGRAM_ID = 'JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB';
export const METEORA_DLMM_PROGRAM_ID = 'LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo';
export const METEORA_POOLS_PROGRAM_ID = 'Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB';
export const METEORA_DAMM_V2_PROGRAM_ID = 'cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG';
export const METEORA_DBC_PROGRAM_ID = 'dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN';
export const ORCA_WHIRLPOOL_PROGRAM_ID = 'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc';
export const PHOENIX_PROGRAM_ID = 'PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY';
export const OPENBOOK_V2_PROGRAM_ID = 'opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb';
export const LIFINITY_V2_PROGRAM_ID = '2wT8Yq49kHgDzXuPxZSaeLaH1qbmGXtEyPy64bL7aD3c';
export const MOONSHOT_PROGRAM_ID = 'MoonCVVNZFSYkqNXP6bxHLPL6QQJiMagDL3qcqUQTrG';
export const SANCTUM_ROUTER_PROGRAM_ID = 'stkitrT1Uoy18Dk1fTrgPw8W6MVzoCfYoAFT4MLsmhq';
export const DFLOW_SWAP_PROGRAM_ID = 'DF1ow4tspfHX9JwWJsAb9epbkA8hmpSEAtxXy1V27QBH';
export const OKX_DEX_ROUTER_PROGRAM_ID = '6m2CDdhRgxpH4WjvdzxAYbGxwdGUz5MziiL5jek2kBma';
export const METAPLEX_TOKEN_METADATA_PROGRAM_ID = 'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s';

export const WSOL_MINT = 'So11111111111111111111111111111111111111112';
export const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
export const USDT_MINT = 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB';
export const JUP_MINT = 'JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN';
export const BONK_MINT = 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263';
export const RAY_MINT = '4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R';
export const MSOL_MINT = 'mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So';
export const JITOSOL_MINT = 'J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn';
export const PYUSD_MINT = '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo';

export const KNOWN_PROGRAMS: Readonly<Record<string, KnownProgram>> = {
  // Core runtime programs
  [SYSTEM_PROGRAM_ID]: { name: 'System Program', category: 'core' },
  [COMPUTE_BUDGET_PROGRAM_ID]: { name: 'Compute Budget', category: 'core' },
  [STAKE_PROGRAM_ID]: { name: 'Stake Program', category: 'core' },
  [VOTE_PROGRAM_ID]: { name: 'Vote Program', category: 'core' },
  [BPF_UPGRADEABLE_LOADER_ID]: { name: 'Upgradeable Loader', category: 'core' },
  [BPF_LOADER_2_ID]: { name: 'BPF Loader 2', category: 'core' },
  [BPF_LOADER_1_ID]: { name: 'BPF Loader (deprecated)', category: 'core' },
  [LOADER_V4_ID]: { name: 'Loader v4', category: 'core' },
  [ADDRESS_LOOKUP_TABLE_PROGRAM_ID]: { name: 'Address Lookup Table', category: 'core' },
  [CONFIG_PROGRAM_ID]: { name: 'Config Program', category: 'core' },
  [ED25519_PROGRAM_ID]: { name: 'Ed25519 SigVerify', category: 'core' },
  [SECP256K1_PROGRAM_ID]: { name: 'Secp256k1 SigVerify', category: 'core' },

  // Token family
  [TOKEN_PROGRAM_ID]: { name: 'SPL Token', category: 'token' },
  [TOKEN_2022_PROGRAM_ID]: { name: 'Token-2022', category: 'token' },
  [ASSOCIATED_TOKEN_PROGRAM_ID]: { name: 'Associated Token Account', category: 'token' },
  [MEMO_PROGRAM_ID]: { name: 'Memo', category: 'utility' },
  [MEMO_V1_PROGRAM_ID]: { name: 'Memo (v1)', category: 'utility' },

  // Trading / DEX / Aggregators
  [PUMP_FUN_PROGRAM_ID]: { name: 'Pump.fun', category: 'dex' },
  [PUMP_SWAP_PROGRAM_ID]: { name: 'PumpSwap', category: 'dex' },
  [RAYDIUM_AMM_V4_PROGRAM_ID]: { name: 'Raydium AMM v4', category: 'dex' },
  [RAYDIUM_CPMM_PROGRAM_ID]: { name: 'Raydium CPMM', category: 'dex' },
  [RAYDIUM_CLMM_PROGRAM_ID]: { name: 'Raydium CLMM', category: 'dex' },
  [RAYDIUM_ROUTING_PROGRAM_ID]: { name: 'Raydium Routing', category: 'dex' },
  [RAYDIUM_LAUNCHLAB_PROGRAM_ID]: { name: 'Raydium LaunchLab', category: 'dex' },
  [JUPITER_V6_PROGRAM_ID]: { name: 'Jupiter v6', category: 'dex' },
  [JUPITER_V4_PROGRAM_ID]: { name: 'Jupiter v4', category: 'dex' },
  [METEORA_DLMM_PROGRAM_ID]: { name: 'Meteora DLMM', category: 'dex' },
  [METEORA_POOLS_PROGRAM_ID]: { name: 'Meteora Dynamic Pools', category: 'dex' },
  [METEORA_DAMM_V2_PROGRAM_ID]: { name: 'Meteora DAMM v2', category: 'dex' },
  [METEORA_DBC_PROGRAM_ID]: { name: 'Meteora Bonding Curve', category: 'dex' },
  [ORCA_WHIRLPOOL_PROGRAM_ID]: { name: 'Orca Whirlpool', category: 'dex' },
  [PHOENIX_PROGRAM_ID]: { name: 'Phoenix DEX', category: 'dex' },
  [OPENBOOK_V2_PROGRAM_ID]: { name: 'OpenBook v2', category: 'dex' },
  [LIFINITY_V2_PROGRAM_ID]: { name: 'Lifinity v2', category: 'dex' },
  [MOONSHOT_PROGRAM_ID]: { name: 'Moonshot', category: 'dex' },
  [SANCTUM_ROUTER_PROGRAM_ID]: { name: 'Sanctum Router', category: 'dex' },
  [DFLOW_SWAP_PROGRAM_ID]: { name: 'DFlow Swap', category: 'dex' },
  [OKX_DEX_ROUTER_PROGRAM_ID]: { name: 'OKX DEX Router', category: 'dex' },

  // NFTs / metadata
  [METAPLEX_TOKEN_METADATA_PROGRAM_ID]: { name: 'Metaplex Token Metadata', category: 'nft' },
};

/** Jito block-engine tip accounts (mainnet). Transfers to these are tips, not payments. */
export const JITO_TIP_ACCOUNTS: ReadonlySet<string> = new Set([
  '96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5',
  'HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe',
  'Cw8CFyM9FkoMi7K7Crf6HNQqf4uEMzpKw6QNghXLvLkY',
  'ADaUMid9yfUytqMBgopwjb2DTLSokTSzL1zt6iGPaS49',
  'DfXygSm4jCyNCybVYYK6DwvWqjKee8pbDmJGcLWNDXjh',
  'ADuUkR4vqLUMWXxW9gh6D6L8pMSawimctcNZ5pGwDcEt',
  'DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL',
  '3AVi9Tg9Uo68tJfuvoKvqKNWKkC5wPdSSdeBnizKZ6jT',
]);

/**
 * Widely used, centrally issued mints whose freeze authority is expected and
 * documented by the issuer. Receiving them does not raise the
 * "freeze authority" finding.
 */
export const WELL_KNOWN_MINTS: Readonly<Record<string, { symbol: string }>> = {
  [WSOL_MINT]: { symbol: 'wSOL' },
  [USDC_MINT]: { symbol: 'USDC' },
  [USDT_MINT]: { symbol: 'USDT' },
};

/**
 * Common Solana token mints used strictly for human-readable symbol and
 * decimal labeling in approval and balance previews (does NOT grant freeze
 * authority exemptions).
 */
export const KNOWN_TOKEN_MINTS: Readonly<Record<string, { symbol: string; decimals: number }>> = {
  [WSOL_MINT]: { symbol: 'wSOL', decimals: 9 },
  [USDC_MINT]: { symbol: 'USDC', decimals: 6 },
  [USDT_MINT]: { symbol: 'USDT', decimals: 6 },
  [JUP_MINT]: { symbol: 'JUP', decimals: 6 },
  [BONK_MINT]: { symbol: 'BONK', decimals: 5 },
  [RAY_MINT]: { symbol: 'RAY', decimals: 6 },
  [MSOL_MINT]: { symbol: 'mSOL', decimals: 9 },
  [JITOSOL_MINT]: { symbol: 'JitoSOL', decimals: 9 },
  [PYUSD_MINT]: { symbol: 'PYUSD', decimals: 6 },
};

export function knownProgram(programId: string): KnownProgram | undefined {
  return Object.hasOwn(KNOWN_PROGRAMS, programId) ? KNOWN_PROGRAMS[programId] : undefined;
}

export function isKnownProgram(programId: string): boolean {
  return knownProgram(programId) !== undefined;
}

export function isDexProgram(programId: string): boolean {
  return knownProgram(programId)?.category === 'dex';
}

export function isJitoTipAccount(address: string): boolean {
  return JITO_TIP_ACCOUNTS.has(address);
}
