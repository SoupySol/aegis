/**
 * rules.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Evaluates decoded instructions and optional simulation diffs
 *           against Aegis consumer-protection rules, producing plain-language
 *           findings, fee estimates, and consolidated authority changes while
 *           honouring benign trading exemptions.
 *
 * ACCESS:   Pure functions over decoded transaction data and simulation diffs.
 *
 * NEVER:    - No network. No storage. No logging.
 *           - Never relies on known program names alone to ignore dangerous
 *             authority or balance changes.
 * ---------------------------------------------------------------------------
 */

import {
  type ApprovalDetail,
  type AuthorityChange,
  type BalanceChange,
  type Finding,
  type ProgramInfo,
  SEVERITY_ORDER,
  type Severity,
  type SimulationSummary,
  maxSeverity,
} from '../../shared/analysis-types';
import {
  KNOWN_TOKEN_MINTS,
  PUMP_FUN_PROGRAM_ID,
  SYSTEM_PROGRAM_ID,
  WELL_KNOWN_MINTS,
  WSOL_MINT,
  isDexProgram,
  isJitoTipAccount,
  isKnownProgram,
  knownProgram,
} from '../../shared/known-programs';
import type { MintInfo, TokenAccountInfo } from './accounts';
import { formatSol, formatUnits, looksLikePubkey, shortAddr } from './bytes';
import type { DecodedIx } from './decoders';

/** ~24 hours at ~400ms per Solana slot. */
export const RECENT_DEPLOY_SLOTS = 216_000;

/** 0.05 SOL priority-fee warning threshold (in lamports). */
export const HIGH_PRIORITY_FEE_LAMPORTS = 50_000_000n;

/** Approvals >= i64::MAX (2^63 - 1) or u64::MAX are flagged as UNLIMITED. */
const UNLIMITED_APPROVAL_THRESHOLD = (1n << 63n) - 1n;

/** Minimum net external SOL inflow (0.01 SOL) required to count as swap proceeds for multi-token outflows. */
const MIN_SWAP_SOL_INFLOW_LAMPORTS = 10_000_000n;
const DEFAULT_TOKEN_ACCOUNT_RENT_LAMPORTS = 2_039_280n;
const TROJAN_MIN_DIRECT_SOL_OUT_LAMPORTS = 100_000_000n; // 0.1 SOL

const BASE_SIGNATURE_FEE_LAMPORTS = 5_000n;
const DEFAULT_IX_CU_LIMIT = 200_000;
const MAX_DEFAULT_CU_LIMIT = 1_400_000;

export interface RuleInput {
  txIndex: number;
  version?: 'legacy' | 0 | 1;
  v1PriorityFeeLamports?: bigint;
  wallet: string;
  feePayer: string;
  signers: string[];
  numRequiredSignatures: number;
  partiallySigned: boolean;
  instructions: DecodedIx[];
  programs: ProgramInfo[];
  simulation?: SimulationSummary;
  balanceChanges: BalanceChange[];
  simAuthorityChanges: AuthorityChange[];
  preWalletLamports?: bigint;
  preTokenAccounts?: ReadonlyMap<string, TokenAccountInfo>;
  postTokenAccounts?: ReadonlyMap<string, TokenAccountInfo>;
  mintInfos?: ReadonlyMap<string, MintInfo>;
  currentSlot?: number;
}

export interface RuleOutput {
  usesDurableNonce: boolean;
  estimatedFeeLamports: string;
  authorityChanges: AuthorityChange[];
  approvalDetails: ApprovalDetail[];
  findings: Finding[];
  severity: Severity;
}

export interface FeeBreakdown {
  baseFeeLamports: bigint;
  priorityFeeLamports: bigint;
  totalFeeLamports: bigint;
}

function parseBigIntSafe(raw: string | undefined): bigint {
  if (!raw) return 0n;
  try {
    return BigInt(raw);
  } catch {
    return 0n;
  }
}

/**
 * ARCHITECTURAL DESIGN NOTE: Dual-Model Solana Fee Calculation (v0/Legacy vs. SIMD-0385 v1)
 *
 * Solana transactions compute network fees via two distinct mechanisms:
 *   1. Legacy & Version 0: Base fee is 5,000 lamports per required signature. Priority fee
 *      is calculated from ComputeBudget instructions (`SetComputeUnitPrice` in microLamports/CU,
 *      multiplied by explicit CU limit or conservative fallback default of 200k CU per outer ix).
 *   2. SIMD-0385 Version 1: Priority fee is declared statically in transactionConfig as an exact
 *      lamport quantity, and ComputeBudget instructions inside the transaction are runtime no-ops.
 *
 * This function handles both formats so user fee alerts accurately reflect real cost.
 */
export function computeTransactionFee(
  instructions: DecodedIx[],
  numRequiredSignatures: number,
  opts?: { version?: 'legacy' | 0 | 1; v1PriorityFeeLamports?: bigint },
): FeeBreakdown {
  const sigCount = BigInt(Math.max(1, numRequiredSignatures));
  const baseFeeLamports = BASE_SIGNATURE_FEE_LAMPORTS * sigCount;

  // SIMD-0385 v1 transactions embed total priority fee in lamports directly in transactionConfig;
  // ComputeBudget instructions inside v1 execute as no-ops.
  if (opts?.version === 1) {
    const priorityFeeLamports = opts.v1PriorityFeeLamports ?? 0n;
    return {
      baseFeeLamports,
      priorityFeeLamports,
      totalFeeLamports: baseFeeLamports + priorityFeeLamports,
    };
  }

  let explicitCuLimit: bigint | undefined;
  let cuPriceMicroLamports = 0n;
  let legacyAdditionalFee = 0n;
  let nonComputeBudgetOuterCount = 0;

  for (const ix of instructions) {
    if (ix.inner) continue;
    if (ix.type === 'computeBudget:setComputeUnitLimit') {
      explicitCuLimit = parseBigIntSafe(ix.params.units);
    } else if (ix.type === 'computeBudget:setComputeUnitPrice') {
      cuPriceMicroLamports = parseBigIntSafe(ix.params.microLamports);
    } else if (ix.type === 'computeBudget:requestUnits') {
      explicitCuLimit = parseBigIntSafe(ix.params.units);
      legacyAdditionalFee = parseBigIntSafe(ix.params.additionalFee);
    } else if (!ix.type.startsWith('computeBudget:')) {
      nonComputeBudgetOuterCount += 1;
    }
  }

  let priorityFeeLamports = legacyAdditionalFee;
  if (cuPriceMicroLamports > 0n) {
    const defaultUnits = BigInt(Math.min(MAX_DEFAULT_CU_LIMIT, Math.max(1, nonComputeBudgetOuterCount) * DEFAULT_IX_CU_LIMIT));
    const units = explicitCuLimit ?? defaultUnits;
    priorityFeeLamports += (units * cuPriceMicroLamports + 999_999n) / 1_000_000n;
  }

  return {
    baseFeeLamports,
    priorityFeeLamports,
    totalFeeLamports: baseFeeLamports + priorityFeeLamports,
  };
}

/** True when `candidate` shares the first 4 and last 4 chars of `wallet` while being a different address. */
export function isLookalikeAddress(candidate: string, wallet: string): boolean {
  if (!candidate || !wallet || candidate === wallet) return false;
  if (!looksLikePubkey(candidate) || !looksLikePubkey(wallet)) return false;
  return candidate.slice(0, 4) === wallet.slice(0, 4) && candidate.slice(-4) === wallet.slice(-4);
}

/**
 * ARCHITECTURAL DESIGN NOTE: Benign Swap Router Fee Exemption
 *
 * Major DEX routers (Jupiter, Raydium, OKX) legitimately collect tiny platform or referral
 * fees (typically 0.05% - 0.5%, well under 2%) sent directly to developer or referrer EOAs.
 * Treating every small non-AMM transfer as an unauthorized "SOL Drain" would cause constant
 * false alarms on normal trading.
 *
 * Aegis permits direct external SOL transfers <= 2% of total swap volume ONLY when the
 * transaction routes through a recognized DEX program and contains zero delegate approvals.
 */
export function isSmallFeeAmount(feeAmount: bigint, tradeAmount: bigint): boolean {
  if (feeAmount <= 0n || tradeAmount <= 0n) return false;
  return feeAmount * 100n <= tradeAmount * 2n;
}

function labelMint(mint: string, info: MintInfo | undefined): string {
  if (info?.symbol) return `${info.symbol} (${shortAddr(mint)})`;
  if (Object.hasOwn(WELL_KNOWN_MINTS, mint)) {
    const sym = WELL_KNOWN_MINTS[mint]?.symbol;
    if (sym) return `${sym} (${shortAddr(mint)})`;
  }
  return shortAddr(mint);
}

interface StaticApproveMeta {
  account: string;
  delegate: string;
  owner: string;
  rawAmount: bigint;
  mint?: string;
  decimals?: number;
  sourceLabel: string;
}

/**
 * ARCHITECTURAL DESIGN NOTE: Full Transaction Authority Lifecycle Consolidation
 *
 * Attackers frequently attempt to hide malicious permissions within complex transactions
 * (e.g., hiding a Token:Approve or System:Assign instruction alongside legitimate DEX swap instructions).
 * Furthermore, some benign transactions approve a temporary delegate and revoke it via CPI
 * in the same block.
 *
 * Aegis executes a two-phase reconciliation:
 *   1. Static Phase: Scans all outer and inner instructions in execution order, tracking
 *      delegate approvals, account ownership changes, stake authorizations, and nonces.
 *   2. Simulation Reconciliation: Correlates the static tracking with simulated post-execution
 *      account state (`postTokenAccounts`). If a token delegate approval was completely consumed
 *      or revoked during execution (delegate === null or amount === 0n), it is cleared from alerts.
 *      If an approval remains active on the account after execution, it is flagged with the exact
 *      allowance and asset amount at risk.
 */
function consolidateAuthorityChanges(
  input: RuleInput,
): {
  authorityChanges: AuthorityChange[];
  staticApproveMeta: Map<string, StaticApproveMeta>;
  sourceLabels: Map<string, string>;
} {
  const { wallet, instructions, simAuthorityChanges, simulation, postTokenAccounts } = input;
  const merged: AuthorityChange[] = [];
  const seen = new Set<string>();
  const sourceLabels = new Map<string, string>();

  const makeKey = (change: AuthorityChange) => `${change.kind}:${change.account}:${change.to}`;
  const push = (change: AuthorityChange, label?: string) => {
    const key = makeKey(change);
    if (label && !sourceLabels.has(key)) sourceLabels.set(key, label);
    if (seen.has(key)) return;
    seen.add(key);
    merged.push(change);
  };

  for (const c of simAuthorityChanges) push(c, 'Simulated On-Chain State');

  // Track static token delegate approvals and revocations across execution order.
  const activeApprovals = new Map<string, StaticApproveMeta>();

  for (const ix of instructions) {
    const ixLabel = ix.inner ? `${ix.name} [CPI]` : ix.name;
    switch (ix.type) {
      case 'system:assign':
      case 'system:assignWithSeed':
      case 'system:allocateWithSeed': {
        const account = ix.params.account ?? '';
        const owner = ix.params.owner ?? '';
        if (account && owner && account === wallet && owner !== SYSTEM_PROGRAM_ID) {
          push({ account, kind: 'wallet-owner', from: SYSTEM_PROGRAM_ID, to: owner }, ixLabel);
        }
        break;
      }
      case 'system:createAccount':
      case 'system:createAccountWithSeed': {
        const newAccount = ix.params.newAccount ?? '';
        const owner = ix.params.owner ?? '';
        if (newAccount && owner && newAccount === wallet && owner !== SYSTEM_PROGRAM_ID) {
          push({ account: newAccount, kind: 'wallet-owner', from: SYSTEM_PROGRAM_ID, to: owner }, ixLabel);
        }
        break;
      }
      case 'token:setAuthority': {
        const account = ix.params.account ?? '';
        const currentAuthority = ix.params.currentAuthority ?? '';
        const authType = ix.params.authorityType ?? '';
        const newAuthority = ix.params.newAuthority ?? '';
        const userControlled = !currentAuthority || !wallet || currentAuthority === wallet;
        if (authType === 'AccountOwner' && account && newAuthority && newAuthority !== 'none' && newAuthority !== wallet && userControlled) {
          push(
            {
              account,
              kind: 'token-account-owner',
              ...(currentAuthority ? { from: currentAuthority } : {}),
              to: newAuthority,
            },
            ixLabel,
          );
        } else if (authType === 'CloseAccount' && account && newAuthority && newAuthority !== 'none' && newAuthority !== wallet && userControlled) {
          push(
            {
              account,
              kind: 'close-authority',
              ...(currentAuthority ? { from: currentAuthority } : {}),
              to: newAuthority,
            },
            ixLabel,
          );
        }
        break;
      }
      case 'token:approve':
      case 'token:approveChecked': {
        const source = ix.params.source ?? '';
        const delegate = ix.params.delegate ?? '';
        const owner = ix.params.owner ?? '';
        const amount = parseBigIntSafe(ix.params.amount);
        if (!source) break;
        if (amount === 0n) {
          activeApprovals.delete(source);
        } else if (delegate && delegate !== wallet && (!owner || !wallet || owner === wallet)) {
          const parsedDec = ix.params.decimals !== undefined ? Number(ix.params.decimals) : undefined;
          activeApprovals.set(source, {
            account: source,
            delegate,
            owner,
            rawAmount: amount,
            ...(ix.params.mint ? { mint: ix.params.mint } : {}),
            ...(parsedDec !== undefined && Number.isInteger(parsedDec) && parsedDec >= 0 && parsedDec <= 18
              ? { decimals: parsedDec }
              : {}),
            sourceLabel: ixLabel,
          });
        }
        break;
      }
      case 'token:revoke': {
        const source = ix.params.source ?? '';
        if (source) activeApprovals.delete(source);
        break;
      }
      case 'token:closeAccount': {
        const account = ix.params.account ?? '';
        if (account) activeApprovals.delete(account);
        break;
      }
      case 'stake:authorize':
      case 'stake:authorizeWithSeed':
      case 'stake:authorizeChecked':
      case 'stake:authorizeCheckedWithSeed': {
        const stakeAccount = ix.params.stakeAccount ?? '';
        const newAuthority = ix.params.newAuthority ?? '';
        const from = ix.params.currentAuthority ?? ix.params.authorityBase;
        if (stakeAccount && newAuthority && newAuthority !== wallet && (!from || !wallet || from === wallet)) {
          push(
            {
              account: stakeAccount,
              kind: 'stake-authority',
              ...(from ? { from } : {}),
              to: newAuthority,
            },
            ixLabel,
          );
        }
        break;
      }
      case 'loader:setAuthority':
      case 'loader:setAuthorityChecked': {
        const account = ix.params.account ?? '';
        const currentAuthority = ix.params.currentAuthority ?? '';
        const newAuthority = ix.params.newAuthority ?? '';
        if (
          account &&
          newAuthority &&
          newAuthority !== wallet &&
          (!currentAuthority || !wallet || currentAuthority === wallet)
        ) {
          push(
            {
              account,
              kind: 'upgrade-authority',
              ...(currentAuthority ? { from: currentAuthority } : {}),
              to: newAuthority,
            },
            ixLabel,
          );
        }
        break;
      }
      case 'system:authorizeNonceAccount': {
        const nonceAccount = ix.params.nonceAccount ?? '';
        const nonceAuthority = ix.params.nonceAuthority ?? '';
        const newAuthority = ix.params.newAuthority ?? '';
        if (
          nonceAccount &&
          newAuthority &&
          newAuthority !== wallet &&
          (!nonceAuthority || !wallet || nonceAuthority === wallet)
        ) {
          push(
            {
              account: nonceAccount,
              kind: 'nonce-authority',
              ...(nonceAuthority ? { from: nonceAuthority } : {}),
              to: newAuthority,
            },
            ixLabel,
          );
        }
        break;
      }
    }
  }

  for (const [source, approval] of activeApprovals) {
    // If simulation ran cleanly and shows no active delegate remaining on that account, an inner CPI cleared it.
    const postTok = postTokenAccounts?.get(source);
    if (
      simulation?.ok &&
      postTokenAccounts?.has(source) &&
      (postTok?.delegate === null || postTok?.delegatedAmount === 0n)
    ) {
      continue;
    }
    push(
      {
        account: approval.account,
        kind: 'delegate',
        to: approval.delegate,
      },
      approval.sourceLabel,
    );
  }

  return { authorityChanges: merged, staticApproveMeta: activeApprovals, sourceLabels };
}

function buildApprovalDetailForChange(
  change: AuthorityChange,
  input: RuleInput,
  staticApproveMeta: ReadonlyMap<string, StaticApproveMeta>,
  sourceLabels: ReadonlyMap<string, string>,
): ApprovalDetail {
  const { preWalletLamports, preTokenAccounts, postTokenAccounts, mintInfos } = input;
  const key = `${change.kind}:${change.account}:${change.to}`;
  const staticMeta = staticApproveMeta.get(change.account);
  const preTok = preTokenAccounts?.get(change.account);
  const postTok = postTokenAccounts?.get(change.account);

  const mint = staticMeta?.mint ?? postTok?.mint ?? preTok?.mint;
  const mintInfo = mint ? mintInfos?.get(mint) : undefined;
  const knownMint = mint && Object.hasOwn(KNOWN_TOKEN_MINTS, mint) ? KNOWN_TOKEN_MINTS[mint] : undefined;
  const symbol =
    mintInfo?.symbol ??
    knownMint?.symbol ??
    (mint && Object.hasOwn(WELL_KNOWN_MINTS, mint) ? WELL_KNOWN_MINTS[mint]?.symbol : undefined);
  const decimals = mintInfo?.decimals ?? staticMeta?.decimals ?? knownMint?.decimals;
  const assetName = symbol ?? (mint ? `Token ${shortAddr(mint)}` : 'tokens');

  const prog = knownProgram(change.to);
  const spenderKnown = Boolean(prog);
  const spenderName = prog?.name;
  const sourceLabel = staticMeta?.sourceLabel ?? sourceLabels.get(key);

  let currentBalanceAtRisk: string | undefined;
  if (change.kind === 'wallet-owner' && preWalletLamports !== undefined) {
    currentBalanceAtRisk = `${formatSol(preWalletLamports)} SOL`;
  } else if (preTok) {
    currentBalanceAtRisk =
      decimals !== undefined
        ? `${formatUnits(preTok.amount, decimals)} ${symbol ?? (mint ? shortAddr(mint) : 'tokens')}`
        : `${preTok.amount.toString()} base units`;
  }

  let permissionLabel = 'Authority Change';
  let allowanceLabel = 'Ongoing account permission';
  let rawAmount: string | undefined;
  let isUnlimited: boolean | undefined;

  switch (change.kind) {
    case 'delegate': {
      permissionLabel = 'Token Spending Approval';
      const effRaw =
        postTok && postTok.delegatedAmount > 0n
          ? postTok.delegatedAmount
          : staticMeta?.rawAmount;
      if (effRaw !== undefined) {
        rawAmount = effRaw.toString();
        isUnlimited = effRaw >= UNLIMITED_APPROVAL_THRESHOLD;
        if (isUnlimited) {
          allowanceLabel = symbol ? `UNLIMITED ${symbol}` : 'UNLIMITED tokens';
        } else if (decimals !== undefined) {
          allowanceLabel = `${formatUnits(effRaw, decimals)} ${symbol ?? (mint ? shortAddr(mint) : 'tokens')}`;
        } else {
          allowanceLabel = `${effRaw.toString()} base units${symbol ? ` (${symbol})` : ''}`;
        }
      } else {
        allowanceLabel = `Spending access to ${assetName}`;
      }
      break;
    }
    case 'token-account-owner':
      permissionLabel = 'Token Account Ownership Transfer';
      allowanceLabel = `Full ownership of ${assetName} account`;
      isUnlimited = true;
      break;
    case 'wallet-owner':
      permissionLabel = 'Wallet Ownership Transfer';
      allowanceLabel = 'Full control of your SOL wallet';
      isUnlimited = true;
      break;
    case 'close-authority':
      permissionLabel = 'Close Authority';
      allowanceLabel = 'Can close account and claim SOL rent';
      break;
    case 'stake-authority':
      permissionLabel = 'Stake Authority Transfer';
      allowanceLabel = 'Full control over staked SOL';
      isUnlimited = true;
      break;
    case 'upgrade-authority':
      permissionLabel = 'Program Upgrade Authority';
      allowanceLabel =
        change.to === 'none (immutable)'
          ? 'Locks program permanently'
          : 'Can replace program code';
      if (change.to !== 'none (immutable)') isUnlimited = true;
      break;
    case 'nonce-authority':
      permissionLabel = 'Nonce Authority Transfer';
      allowanceLabel = 'Can advance nonce and withdraw SOL';
      break;
  }

  return {
    kind: change.kind,
    permissionLabel,
    account: change.account,
    ...(mint ? { mint } : {}),
    ...(symbol ? { symbol } : {}),
    ...(decimals !== undefined ? { decimals } : {}),
    ...(rawAmount !== undefined ? { rawAmount } : {}),
    allowanceLabel,
    ...(isUnlimited ? { isUnlimited: true } : {}),
    ...(currentBalanceAtRisk ? { currentBalanceAtRisk } : {}),
    spender: change.to,
    ...(spenderName ? { spenderName } : {}),
    spenderKnown,
    ...(sourceLabel ? { sourceLabel } : {}),
  };
}

export function evaluateTransactionRules(input: RuleInput): RuleOutput {
  const {
    txIndex,
    wallet,
    partiallySigned,
    instructions,
    programs,
    simulation,
    balanceChanges,
    preWalletLamports,
    preTokenAccounts,
    postTokenAccounts,
    mintInfos,
    currentSlot,
  } = input;

  const fee = computeTransactionFee(instructions, input.numRequiredSignatures, {
    ...(input.version !== undefined ? { version: input.version } : {}),
    ...(input.v1PriorityFeeLamports !== undefined ? { v1PriorityFeeLamports: input.v1PriorityFeeLamports } : {}),
  });
  const usesDurableNonce = instructions.some(
    (ix) =>
      ix.type === 'system:advanceNonceAccount' &&
      (!ix.inner || !wallet || !ix.params.nonceAuthority || ix.params.nonceAuthority === wallet),
  );
  const { authorityChanges, staticApproveMeta, sourceLabels } = consolidateAuthorityChanges(input);
  const approvalDetails: ApprovalDetail[] = [];
  const detailByChangeKey = new Map<string, ApprovalDetail>();
  for (const c of authorityChanges) {
    if (c.to === 'none' || c.to === wallet) continue;
    const d = buildApprovalDetailForChange(c, input, staticApproveMeta, sourceLabels);
    approvalDetails.push(d);
    detailByChangeKey.set(`${c.kind}:${c.account}:${c.to}`, d);
  }
  const findings: Finding[] = [];

  const emit = (id: string, severity: Severity, title: string, detail: string) => {
    findings.push({ id, severity, title, detail, txIndex });
  };

  const hasDexProgram = programs.some((p) => isDexProgram(p.programId));
  const allProgramsKnown = programs.length > 0 && programs.every((p) => p.known);
  const isPartiallySignedPumpFunCreate =
    partiallySigned && programs.some((p) => p.programId === PUMP_FUN_PROGRAM_ID);

  // Track user-owned token accounts created within this transaction (ATAs or initialized accounts).
  const userCreatedTokenAccounts = new Set<string>();
  const userCreatedAtaMints = new Set<string>();
  for (const ix of instructions) {
    if ((ix.type === 'ata:create' || ix.type === 'ata:createIdempotent') && ix.params.owner === wallet) {
      if (ix.params.account) userCreatedTokenAccounts.add(ix.params.account);
      if (ix.params.mint) userCreatedAtaMints.add(ix.params.mint);
    } else if (
      (ix.type === 'token:initializeAccount' ||
        ix.type === 'token:initializeAccount2' ||
        ix.type === 'token:initializeAccount3') &&
      ix.params.owner === wallet &&
      ix.params.account
    ) {
      userCreatedTokenAccounts.add(ix.params.account);
    }
  }

  // Sum Jito tips paid by the wallet so tip transfers are exempted from outflow rules.
  let jitoTipLamports = 0n;
  for (const ix of instructions) {
    if (
      (ix.type === 'system:transfer' || ix.type === 'system:transferWithSeed') &&
      ix.params.from === wallet &&
      ix.params.to &&
      isJitoTipAccount(ix.params.to)
    ) {
      jitoTipLamports += parseBigIntSafe(ix.params.lamports);
    }
  }

  // Compute trade SOL scale for the aggregate <=2% small-fee-transfer exemption.
  const solBalanceChange = balanceChanges.find((b) => b.owner === wallet && b.asset === 'SOL');
  const solDelta = parseBigIntSafe(solBalanceChange?.rawChange);
  const absSolDelta = solDelta < 0n ? -solDelta : solDelta;
  const wsolBalanceChange = balanceChanges.find((b) => b.owner === wallet && b.asset === WSOL_MINT);
  const wsolDelta = parseBigIntSafe(wsolBalanceChange?.rawChange);
  const absWsolDelta = wsolDelta < 0n ? -wsolDelta : wsolDelta;
  let maxInstructionSol = 0n;
  for (const ix of instructions) {
    if (ix.params.from === wallet && ix.params.to === wallet) continue;
    const l = parseBigIntSafe(ix.params.lamports);
    if (l > maxInstructionSol) maxInstructionSol = l;
  }
  const solOrWsolScale = absSolDelta > absWsolDelta ? absSolDelta : absWsolDelta;
  const tradeSolScale = solOrWsolScale > maxInstructionSol ? solOrWsolScale : maxInstructionSol;
  const maxSmallFeeLamports = (tradeSolScale * 2n) / 100n;

  const isUserOwnedAccount = (addr: string): boolean =>
    Boolean(wallet) &&
    (addr === wallet ||
      userCreatedTokenAccounts.has(addr) ||
      preTokenAccounts?.get(addr)?.owner === wallet ||
      postTokenAccounts?.get(addr)?.owner === wallet);

  // Sum top-level direct SOL transfers from wallet to external (non-user, non-Jito) addresses,
  // capping the aggregate exempted small-fee sum at <= 2% of tradeSolScale.
  let rawDirectExternalSolOut = 0n;
  let rawDirectUnknownEoaSolOut = 0n;
  let candidateSmallFeeLamports = 0n;
  for (const ix of instructions) {
    if (
      !ix.inner &&
      (ix.type === 'system:transfer' || ix.type === 'system:transferWithSeed') &&
      ix.params.from === wallet &&
      ix.params.to &&
      !isUserOwnedAccount(ix.params.to) &&
      !isJitoTipAccount(ix.params.to)
    ) {
      const amt = parseBigIntSafe(ix.params.lamports);
      rawDirectExternalSolOut += amt;
      if (!isKnownProgram(ix.params.to)) {
        rawDirectUnknownEoaSolOut += amt;
      }
      if (hasDexProgram && isSmallFeeAmount(amt, tradeSolScale)) {
        candidateSmallFeeLamports += amt;
      }
    }
  }
  const smallFeeLamports =
    candidateSmallFeeLamports > maxSmallFeeLamports ? maxSmallFeeLamports : candidateSmallFeeLamports;
  const unexemptedDirectSolOut =
    rawDirectExternalSolOut > smallFeeLamports ? rawDirectExternalSolOut - smallFeeLamports : 0n;
  const unexemptedUnknownEoaSolOut =
    rawDirectUnknownEoaSolOut > smallFeeLamports ? rawDirectUnknownEoaSolOut - smallFeeLamports : 0n;

  // -------------------------------------------------------------------------
  // 1. Critical authority rules (all instances reported, never truncated to 1)
  // -------------------------------------------------------------------------
  for (const walletReassign of authorityChanges) {
    if (walletReassign.kind === 'wallet-owner' && walletReassign.account === wallet && walletReassign.to !== SYSTEM_PROGRAM_ID) {
      const d = detailByChangeKey.get(`${walletReassign.kind}:${walletReassign.account}:${walletReassign.to}`);
      const balClause = d?.currentBalanceAtRisk ? ` (${d.currentBalanceAtRisk} currently in wallet)` : '';
      emit(
        'wallet-owner-reassignment',
        'critical',
        'Hands control of your wallet to another program',
        `Reassigns ownership of your wallet${balClause} to program ${shortAddr(walletReassign.to)}. Once reassigned, that program can spend your SOL without asking for your signature again.`,
      );
    }
  }

  for (const tokenOwnerChange of authorityChanges) {
    if (
      tokenOwnerChange.kind === 'token-account-owner' &&
      tokenOwnerChange.to !== wallet &&
      tokenOwnerChange.to !== 'none' &&
      (!tokenOwnerChange.from || !wallet || tokenOwnerChange.from === wallet)
    ) {
      const d = detailByChangeKey.get(`${tokenOwnerChange.kind}:${tokenOwnerChange.account}:${tokenOwnerChange.to}`);
      const assetTag = d?.symbol ? `${d.symbol} account ${shortAddr(tokenOwnerChange.account)}` : `token account ${shortAddr(tokenOwnerChange.account)}`;
      const balClause = d?.currentBalanceAtRisk ? ` (${d.currentBalanceAtRisk} currently held)` : '';
      emit(
        'token-account-owner-change',
        'critical',
        'Transfers ownership of a token account',
        `Changes the owner of ${assetTag}${balClause} to ${shortAddr(tokenOwnerChange.to)}. You would permanently lose access to all tokens held in that account.`,
      );
    }
  }

  for (const stakeAuthChange of authorityChanges) {
    if (
      stakeAuthChange.kind === 'stake-authority' &&
      stakeAuthChange.to !== wallet &&
      (!stakeAuthChange.from || !wallet || stakeAuthChange.from === wallet)
    ) {
      emit(
        'stake-authority-change',
        'critical',
        'Changes authority over a stake account',
        `Transfers control of stake account ${shortAddr(stakeAuthChange.account)} to ${shortAddr(stakeAuthChange.to)}, allowing that address to manage or withdraw staked SOL.`,
      );
    }
  }

  for (const upgradeAuthChange of authorityChanges) {
    if (
      upgradeAuthChange.kind === 'upgrade-authority' &&
      upgradeAuthChange.to !== wallet &&
      (!upgradeAuthChange.from || !wallet || upgradeAuthChange.from === wallet)
    ) {
      const destLabel =
        upgradeAuthChange.to === 'none (immutable)' ? 'none (permanently immutable)' : shortAddr(upgradeAuthChange.to);
      emit(
        'program-upgrade-authority-change',
        'critical',
        'Changes program upgrade authority',
        `Updates the upgrade authority for ${shortAddr(upgradeAuthChange.account)} to ${destLabel}.`,
      );
    }
  }

  for (const nonceAuthChange of authorityChanges) {
    if (
      nonceAuthChange.kind === 'nonce-authority' &&
      nonceAuthChange.to !== wallet &&
      (!nonceAuthChange.from || !wallet || nonceAuthChange.from === wallet)
    ) {
      emit(
        'nonce-authority-change',
        'high',
        'Changes authority over a nonce account',
        `Transfers control of nonce account ${shortAddr(nonceAuthChange.account)} to ${shortAddr(nonceAuthChange.to)}, allowing that address to advance or withdraw its SOL balance.`,
      );
    }
  }

  // -------------------------------------------------------------------------
  // 2. Multi-token drain (critical) & >90% SOL / Trojan EOA drain (high)
  // -------------------------------------------------------------------------
  const tokenInflows = balanceChanges.filter(
    (b) => b.owner === wallet && b.asset !== 'SOL' && parseBigIntSafe(b.rawChange) > 0n,
  );
  const tokenOutflows = balanceChanges.filter(
    (b) => b.owner === wallet && b.asset !== 'SOL' && parseBigIntSafe(b.rawChange) < 0n,
  );

  if (simulation?.ok) {
    // Subtract rent/lamports reclaimed from closing the user's own accounts back to wallet
    // so an attacker cannot mask a multi-token drain by closing 1 drained ATA to wallet.
    let reclaimedLamports = 0n;
    const closedUserAccts = new Set<string>();
    for (const ix of instructions) {
      if (ix.type === 'token:closeAccount' && ix.params.destination === wallet) {
        const acct = ix.params.account ?? '';
        if (!acct || closedUserAccts.has(acct) || userCreatedTokenAccounts.has(acct)) continue;
        const preTok = preTokenAccounts?.get(acct);
        if (preTok && (preTok.owner === wallet || ix.params.owner === wallet)) {
          closedUserAccts.add(acct);
          reclaimedLamports += preTok.lamports;
        } else if (!preTok && ix.params.owner === wallet) {
          closedUserAccts.add(acct);
          reclaimedLamports += DEFAULT_TOKEN_ACCOUNT_RENT_LAMPORTS;
        }
      } else if (
        ix.type === 'system:withdrawNonceAccount' &&
        ix.params.to === wallet &&
        ix.params.nonceAuthority === wallet
      ) {
        reclaimedLamports += parseBigIntSafe(ix.params.lamports);
      }
    }
    const netSolInflow = solDelta - reclaimedLamports;
    const hasInflow = tokenInflows.length > 0 || netSolInflow >= MIN_SWAP_SOL_INFLOW_LAMPORTS;
    if (tokenOutflows.length >= 2 && !hasInflow) {
      emit(
        'multi-token-drain',
        'critical',
        'Sends out multiple tokens without receiving anything back',
        `Transfers ${tokenOutflows.length} different token types out of your wallet with no incoming assets in return.`,
      );
    }

    if (
      solDelta < 0n &&
      tokenInflows.length === 0 &&
      !isPartiallySignedPumpFunCreate &&
      preWalletLamports !== undefined &&
      preWalletLamports > 0n
    ) {
      const rawOut = -solDelta;
      const exempted = jitoTipLamports + smallFeeLamports;
      const effectiveOut = rawOut > exempted ? rawOut - exempted : 0n;
      if (effectiveOut > fee.totalFeeLamports && effectiveOut * 100n > preWalletLamports * 90n) {
        const pct = Number((effectiveOut * 100n) / preWalletLamports);
        emit(
          'sol-drain-over-90pct',
          'high',
          'Sends out over 90% of your SOL balance',
          `Moves ${formatSol(effectiveOut)} SOL (${pct}% of your wallet balance) with no tokens received in return.`,
        );
      }
    } else {
      // Even when tokenInflows.length > 0 or isPartiallySignedPumpFunCreate is true,
      // catch Trojan micro-swaps or co-signed txs paired with large direct EOA SOL transfers.
      const rawSolOut = solDelta < 0n ? -solDelta : 0n;
      const drainsOver90PctDirect =
        preWalletLamports !== undefined &&
        preWalletLamports > 0n &&
        unexemptedDirectSolOut > fee.totalFeeLamports &&
        unexemptedDirectSolOut * 100n > preWalletLamports * 90n;
      const trojanEoaTransfer =
        (tokenInflows.length > 0 || isPartiallySignedPumpFunCreate) &&
        rawSolOut > 0n &&
        unexemptedUnknownEoaSolOut > TROJAN_MIN_DIRECT_SOL_OUT_LAMPORTS &&
        unexemptedUnknownEoaSolOut * 100n > rawSolOut * 50n;

      if (drainsOver90PctDirect) {
        const pct = Number((unexemptedDirectSolOut * 100n) / preWalletLamports!);
        emit(
          'sol-drain-over-90pct',
          'high',
          'Sends out over 90% of your SOL balance',
          `Directly transfers ${formatSol(unexemptedDirectSolOut)} SOL (${pct}% of your wallet balance) to an external address alongside other instructions.`,
        );
      } else if (trojanEoaTransfer) {
        emit(
          'sol-drain-over-90pct',
          'high',
          'Sends out a large SOL transfer alongside token activity',
          `Directly transfers ${formatSol(unexemptedUnknownEoaSolOut)} SOL (over half of total SOL leaving your wallet) to an unrecognized address outside the trade.`,
        );
      }
    }
  } else {
    // Static fallback when simulation is unavailable or failed: detect multi-token drains.
    const outgoingTokenKeys = new Set<string>();
    let hasStaticInflow = hasDexProgram;
    let staticSolInflow = 0n;
    for (const ix of instructions) {
      if ((ix.type === 'system:transfer' || ix.type === 'system:transferWithSeed') && ix.params.to === wallet && ix.params.from !== wallet) {
        staticSolInflow += parseBigIntSafe(ix.params.lamports);
      } else if (
        (ix.type === 'token:mintTo' || ix.type === 'token:mintToChecked') &&
        ix.params.account &&
        (ix.params.account === wallet || userCreatedTokenAccounts.has(ix.params.account))
      ) {
        hasStaticInflow = true;
      } else if (
        ix.type === 'token:transfer' ||
        ix.type === 'token:transferChecked' ||
        ix.type === 'token:transferCheckedWithFee'
      ) {
        const source = ix.params.source ?? '';
        const dest = ix.params.destination ?? '';
        const authority = ix.params.authority ?? '';
        const amt = parseBigIntSafe(ix.params.amount);
        if (dest && (dest === wallet || userCreatedTokenAccounts.has(dest)) && authority !== wallet) {
          hasStaticInflow = true;
        }
        if (
          amt > 0n &&
          (!wallet || authority === wallet) &&
          source &&
          dest &&
          dest !== source &&
          dest !== wallet &&
          !userCreatedTokenAccounts.has(dest)
        ) {
          outgoingTokenKeys.add(ix.params.mint ?? source);
        }
      }
    }
    if (staticSolInflow >= MIN_SWAP_SOL_INFLOW_LAMPORTS) {
      hasStaticInflow = true;
    }
    if (outgoingTokenKeys.size >= 2 && !hasStaticInflow) {
      emit(
        'multi-token-drain',
        'critical',
        'Sends out multiple tokens without receiving anything back',
        `Transfers ${outgoingTokenKeys.size} different token accounts out of your wallet with no incoming assets in return.`,
      );
    }
  }

  // -------------------------------------------------------------------------
  // 3. High-severity permission, rent-destination, lookalike, and mint rules
  // -------------------------------------------------------------------------
  for (const lingeringDelegate of authorityChanges) {
    if (lingeringDelegate.kind === 'delegate' && lingeringDelegate.to !== 'none' && lingeringDelegate.to !== wallet) {
      const d = detailByChangeKey.get(`${lingeringDelegate.kind}:${lingeringDelegate.account}:${lingeringDelegate.to}`);
      const spenderDesc = d?.spenderName
        ? `${d.spenderName} (${shortAddr(lingeringDelegate.to)})`
        : `unrecognized address ${shortAddr(lingeringDelegate.to)}`;
      const allowanceDesc = d?.allowanceLabel ?? 'tokens';
      const riskDesc = d?.currentBalanceAtRisk ? ` (${d.currentBalanceAtRisk} currently in account)` : '';
      emit(
        'lingering-delegate-approval',
        'high',
        'Leaves a spending approval active after signing',
        `Approves ${spenderDesc} to spend ${allowanceDesc} from account ${shortAddr(lingeringDelegate.account)}${riskDesc} at any time without asking for another signature.`,
      );
    }
  }

  for (const closeAuthChange of authorityChanges) {
    if (closeAuthChange.kind === 'close-authority' && closeAuthChange.to !== 'none' && closeAuthChange.to !== wallet) {
      emit(
        'close-authority-change',
        'high',
        'Grants permission to close a token account',
        `Allows ${shortAddr(closeAuthChange.to)} to close token account ${shortAddr(closeAuthChange.account)} and claim its rent deposit later.`,
      );
    }
  }

  const seenForeignClose = new Set<string>();
  for (const ix of instructions) {
    if (ix.type !== 'token:closeAccount') continue;
    const account = ix.params.account ?? '';
    const destination = ix.params.destination ?? '';
    const owner = ix.params.owner ?? '';
    const preTok = account ? preTokenAccounts?.get(account) : undefined;
    const preOwner = preTok?.owner;
    const belongsToWallet = wallet ? owner === wallet || preOwner === wallet : Boolean(owner);
    // Exemption: wSOL (or any token account) closed back to the user's wallet is benign.
    if (belongsToWallet && destination && destination !== wallet) {
      const closeKey = `${account}:${destination}`;
      if (seenForeignClose.has(closeKey)) continue;
      seenForeignClose.add(closeKey);
      const prog = knownProgram(destination);
      approvalDetails.push({
        kind: 'foreign-close-rent',
        permissionLabel: 'Rent Redirect',
        account,
        ...(preTok?.mint ? { mint: preTok.mint } : {}),
        allowanceLabel:
          preTok && preTok.lamports > 0n
            ? `${formatSol(preTok.lamports)} SOL rent sent to another address`
            : 'SOL rent sent to another address',
        spender: destination,
        ...(prog ? { spenderName: prog.name } : {}),
        spenderKnown: Boolean(prog),
        sourceLabel: ix.inner ? `${ix.name} [CPI]` : ix.name,
      });
      emit(
        'close-account-foreign-destination',
        'high',
        'Sends reclaimed account rent to another address',
        `Closes token account ${shortAddr(account)} and sends its SOL balance to ${shortAddr(destination)} instead of your wallet.`,
      );
    }
  }

  if (wallet) {
    const candidates: string[] = [];
    for (const ix of instructions) {
      switch (ix.type) {
        case 'system:transfer':
        case 'system:transferWithSeed':
        case 'system:withdrawNonceAccount':
          if (ix.params.to && !isJitoTipAccount(ix.params.to)) candidates.push(ix.params.to);
          break;
        case 'token:transfer':
        case 'token:transferChecked':
        case 'token:transferCheckedWithFee': {
          const dest = ix.params.destination;
          if (dest) {
            candidates.push(dest);
            const destOwner = postTokenAccounts?.get(dest)?.owner ?? preTokenAccounts?.get(dest)?.owner;
            if (destOwner) candidates.push(destOwner);
          }
          break;
        }
        case 'ata:create':
        case 'ata:createIdempotent':
          if (ix.params.owner) candidates.push(ix.params.owner);
          break;
        case 'token:closeAccount':
          if (ix.params.destination) candidates.push(ix.params.destination);
          break;
        case 'stake:withdraw':
        case 'stake:moveLamports':
        case 'stake:moveStake': {
          const target = ix.params.to ?? ix.params.destination;
          if (target) candidates.push(target);
          break;
        }
      }
    }
    const lookalike = candidates.find(
      (addr) => !isKnownProgram(addr) && !isJitoTipAccount(addr) && isLookalikeAddress(addr, wallet),
    );
    if (lookalike) {
      emit(
        'lookalike-destination',
        'high',
        'Destination closely resembles your wallet address',
        `Recipient ${shortAddr(lookalike)} shares the same first and last 4 characters as your wallet (${shortAddr(wallet)}), which is a sign of address-poisoning.`,
      );
    }
  }

  // Received mint checks (Token-2022 permanent delegate, freeze authority, transfer hook / fee).
  const receivedMints = new Set<string>(tokenInflows.map((b) => b.asset));
  for (const mint of userCreatedAtaMints) {
    const out = tokenOutflows.some((b) => b.asset === mint);
    if (!out && mintInfos?.has(mint)) receivedMints.add(mint);
  }

  let flaggedPermDelegate = false;
  let flaggedFreeze = false;
  let flaggedTransferExt = false;

  for (const mint of receivedMints) {
    const info = mintInfos?.get(mint);
    if (!info) continue;

    if (!flaggedPermDelegate && info.permanentDelegate) {
      flaggedPermDelegate = true;
      emit(
        'received-mint-permanent-delegate',
        'high',
        'Incoming token has a permanent delegate',
        `Token ${labelMint(mint, info)} defines permanent delegate ${shortAddr(info.permanentDelegate)}, which can transfer or burn tokens from your wallet at any time.`,
      );
    }

    if (!flaggedFreeze && info.freezeAuthority && !Object.hasOwn(WELL_KNOWN_MINTS, mint)) {
      flaggedFreeze = true;
      emit(
        'received-mint-freeze-authority',
        'medium',
        'Incoming token can be frozen by its issuer',
        `Token ${labelMint(mint, info)} has an active freeze authority (${shortAddr(info.freezeAuthority)}), allowing that authority to freeze your token account.`,
      );
    }

    const hasHook = Boolean(info.transferHookProgram);
    const hasFee = info.transferFeeBps !== undefined && info.transferFeeBps > 0;
    if (!flaggedTransferExt && (hasHook || hasFee)) {
      flaggedTransferExt = true;
      if (hasHook && hasFee && info.transferHookProgram && info.transferFeeBps !== undefined) {
        const feePct = (info.transferFeeBps / 100).toFixed(info.transferFeeBps % 100 === 0 ? 0 : 2);
        emit(
          'received-mint-transfer-extension',
          'medium',
          'Incoming token uses a transfer fee and transfer hook',
          `Token ${labelMint(mint, info)} charges a ${feePct}% transfer fee and runs hook program ${shortAddr(info.transferHookProgram)} on every transfer.`,
        );
      } else if (hasHook && info.transferHookProgram) {
        emit(
          'received-mint-transfer-extension',
          'medium',
          'Incoming token runs custom transfer hook code',
          `Token ${labelMint(mint, info)} invokes program ${shortAddr(info.transferHookProgram)} on every transfer, which could restrict future transfers or sales.`,
        );
      } else if (hasFee && info.transferFeeBps !== undefined) {
        const feePct = (info.transferFeeBps / 100).toFixed(info.transferFeeBps % 100 === 0 ? 0 : 2);
        emit(
          'received-mint-transfer-extension',
          'medium',
          'Incoming token charges a built-in transfer fee',
          `Token ${labelMint(mint, info)} withholds a ${feePct}% Token-2022 transfer fee whenever tokens are moved or sold.`,
        );
      }
    }
  }

  // -------------------------------------------------------------------------
  // 4. Medium / low / info / safe rules
  // -------------------------------------------------------------------------
  if (usesDurableNonce) {
    emit(
      'durable-nonce',
      'medium',
      'Uses a durable nonce that does not expire',
      'Unlike standard Solana transactions that expire after about a minute, a durable-nonce signature stays valid until the nonce advances and can be submitted later.',
    );
  }

  const unknownPrograms = programs.filter((p) => !p.known);
  const recentUnknown: ProgramInfo[] = [];
  const otherUnknown: ProgramInfo[] = [];
  for (const prog of unknownPrograms) {
    if (
      prog.deploySlot !== undefined &&
      prog.deploySlot > 0 &&
      currentSlot !== undefined &&
      currentSlot >= 0 &&
      currentSlot - prog.deploySlot <= RECENT_DEPLOY_SLOTS
    ) {
      recentUnknown.push(prog);
    } else {
      otherUnknown.push(prog);
    }
  }

  if (recentUnknown.length > 0) {
    const list = recentUnknown.map((p) => shortAddr(p.programId)).join(', ');
    emit(
      'unknown-program-recent',
      'medium',
      'Calls a recently deployed unverified program',
      `Invokes ${recentUnknown.length === 1 ? `program ${list}` : `programs ${list}`}, which was deployed within the last ~24 hours and is not on Aegis's known program list.`,
    );
  }

  if (fee.priorityFeeLamports > HIGH_PRIORITY_FEE_LAMPORTS) {
    emit(
      'high-priority-fee',
      'medium',
      'Unusually high priority fee',
      `Includes a priority fee of ${formatSol(fee.priorityFeeLamports)} SOL (above 0.05 SOL) on top of the base network fee.`,
    );
  }

  if (otherUnknown.length > 0) {
    const list = otherUnknown.map((p) => shortAddr(p.programId)).join(', ');
    emit(
      'unknown-program',
      'low',
      'Calls an unrecognized program',
      `Invokes ${otherUnknown.length === 1 ? `program ${list}` : `programs ${list}`}, which is not on Aegis's list of recognized Solana programs.`,
    );
  }

  if (simulation && !simulation.ok) {
    emit(
      'simulation-failed',
      'info',
      'Transaction failed during preview simulation',
      `The RPC node reported that this transaction would fail if submitted now${simulation.error ? ` (${simulation.error})` : ''}. Balance changes could not be confirmed from simulation.`,
    );
  }

  if (findings.length === 0 && hasDexProgram && allProgramsKnown) {
    const simSwapConfirmed =
      !simulation ||
      isPartiallySignedPumpFunCreate ||
      tokenInflows.length > 0 ||
      solDelta > 0n;
    if (simSwapConfirmed) {
      emit(
        'normal-swap',
        'safe',
        'Standard trade through recognized programs',
        'Routes through recognized Solana trading programs with no unusual authority or account changes.',
      );
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity));
  const severity = maxSeverity(findings.map((f) => f.severity));

  return {
    usesDurableNonce,
    estimatedFeeLamports: fee.totalFeeLamports.toString(),
    authorityChanges,
    approvalDetails,
    findings,
    severity,
  };
}
