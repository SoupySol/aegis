/**
 * analysis-types.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Shared contract between the transaction analysis engine
 *           (src/background/analysis/) and the rest of the extension
 *           (service worker router, review window UI).
 * ACCESS:   Types only.
 * ---------------------------------------------------------------------------
 */

/** Ordered from least to most severe. */
export type Severity = 'safe' | 'info' | 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_ORDER: readonly Severity[] = ['safe', 'info', 'low', 'medium', 'high', 'critical'];

/** UI verdict buckets. */
export type Verdict = 'SAFE' | 'CAUTION' | 'DANGER' | 'UNVERIFIED';

export function verdictFor(severity: Severity): Verdict {
  if (severity === 'high' || severity === 'critical') return 'DANGER';
  if (severity === 'low' || severity === 'medium') return 'CAUTION';
  return 'SAFE';
}

export function maxSeverity(list: Severity[]): Severity {
  let best: Severity = 'safe';
  for (const s of list) if (SEVERITY_ORDER.indexOf(s) > SEVERITY_ORDER.indexOf(best)) best = s;
  return best;
}

export interface Finding {
  /** Stable rule id, e.g. "wallet-owner-reassignment". */
  id: string;
  severity: Severity;
  /** Short plain-language headline, e.g. "Hands your wallet to another program". */
  title: string;
  /** One or two sentences explaining what it means for the user. */
  detail: string;
  /** Index of the transaction in the batch this finding belongs to (if any). */
  txIndex?: number;
}

export interface DecodedInstruction {
  programId: string;
  programName?: string;
  /** e.g. "System: Transfer", "Token: SetAuthority(AccountOwner)", "Unknown". */
  name: string;
  /** Human-readable key/value details (addresses, amounts). Never secrets. */
  params: Record<string, string>;
  /** True if this came from an inner (CPI) instruction reported by simulation. */
  inner?: boolean;
}

export interface BalanceChange {
  /** "SOL" or the token mint address. */
  asset: string;
  symbol?: string;
  decimals: number;
  /** Signed raw integer amount as a string (base units). */
  rawChange: string;
  /** Signed human amount, e.g. "-2.5". */
  uiChange: string;
  /** The account owner (normally the user's wallet). */
  owner: string;
}

export type AuthorityKind =
  | 'wallet-owner'
  | 'token-account-owner'
  | 'close-authority'
  | 'delegate'
  | 'stake-authority'
  | 'upgrade-authority'
  | 'nonce-authority';

export interface AuthorityChange {
  account: string;
  kind: AuthorityKind;
  from?: string;
  to: string;
}

export interface ApprovalDetail {
  kind: AuthorityKind | 'foreign-close-rent';
  /** Plain-language permission headline, e.g. "Token Spending Approval (Delegate)". */
  permissionLabel: string;
  /** Target account being approved or reassigned. */
  account: string;
  /** Token mint address when the target account is an SPL / Token-2022 account. */
  mint?: string;
  /** Resolved token symbol when available (e.g. "USDC"). */
  symbol?: string;
  /** Resolved token decimals when available. */
  decimals?: number;
  /** Raw integer allowance string for delegate approvals. */
  rawAmount?: string;
  /** Human-readable allowance or scope, e.g. "500 USDC" or "UNLIMITED USDC (max allowance)". */
  allowanceLabel: string;
  /** True when permission grants unlimited or permanent full-account control. */
  isUnlimited?: boolean;
  /** Pre-simulation wallet/token balance exposed to this approval, when known. */
  currentBalanceAtRisk?: string;
  /** Spender, delegate, or new authority address receiving permission. */
  spender: string;
  /** Recognized program name if spender is in KNOWN_PROGRAMS. */
  spenderName?: string;
  /** True when spender is a recognized on-chain program. */
  spenderKnown: boolean;
  /** Decoded instruction or simulation source label. */
  sourceLabel?: string;
}

export interface ConnectDetails {
  requestKind: 'connect' | 'signIn' | 'signMessage' | 'legacyRequest';
  actionHeadline: string;
  origin: string;
  hostname: string;
  protocol: string;
  port?: string;
  isHttps: boolean;
  isLocalhost: boolean;
  hasPunycode: boolean;
  siteStatus: 'official' | 'unknown' | 'lookalike';
  officialBrand?: string;
  officialDomain?: string;
  lookalikeReason?: string;
  walletName: string;
  walletPubkey?: string;
  /** Exact capabilities this connection or signature grants to the site. */
  permissionsGranted: string[];
  /** Explicit wallet guarantees that remain protected. */
  protectionsKept: string[];
  /** Parsed Sign-In With Solana (SIWS) parameters when present. */
  siws?: {
    claimedDomain: string;
    domainMatchesOrigin: boolean;
    uri?: string;
    uriMatchesOrigin?: boolean;
    statement?: string;
    nonce?: string;
    issuedAt?: string;
    expirationTime?: string;
    chainId?: string;
    resources?: string[];
  };
}

export interface ProgramInfo {
  programId: string;
  name?: string;
  known: boolean;
  /** Slot at which the program was last deployed, if looked up. */
  deploySlot?: number;
}

export interface SimulationSummary {
  ok: boolean;
  error?: string;
  unitsConsumed?: number;
  /** Last few log lines, for the "advanced" section of the review window. */
  logsTail?: string[];
}

export interface TxSummary {
  index: number;
  version: 'legacy' | 0 | 1;
  feePayer: string;
  signers: string[];
  /** True when the tx already carries signatures from someone other than the user. */
  partiallySigned: boolean;
  usesDurableNonce: boolean;
  programs: ProgramInfo[];
  instructions: DecodedInstruction[];
  simulation?: SimulationSummary;
  balanceChanges: BalanceChange[];
  authorityChanges: AuthorityChange[];
  /** Rich deep-dive breakdown for every spending approval or authority change. */
  approvalDetails?: ApprovalDetail[];
  /** Estimated total fee in lamports (base + priority), if computable. */
  estimatedFeeLamports?: string;
  findings: Finding[];
  severity: Severity;
}

export interface MessageSummary {
  /** UTF-8 text if the bytes are readable, otherwise undefined. */
  text?: string;
  byteLength: number;
  isSignInWithSolana: boolean;
  /** Domain field from a Sign-In With Solana message, if present. */
  siwsDomain?: string;
  looksLikeTransaction: boolean;
}

export interface AnalysisReport {
  kind: 'transaction' | 'message' | 'connect';
  origin: string;
  method: string;
  walletPubkey?: string;
  severity: Severity;
  verdict: Verdict;
  findings: Finding[];
  transactions?: TxSummary[];
  message?: MessageSummary;
  /** Deep-dive connection, origin, and permission scan for connect / signIn / signMessage. */
  connectDetails?: ConnectDetails;
  /** True when simulation/RPC data was available. */
  rpcUsed: boolean;
  /** Non-fatal problems (e.g. "RPC unreachable"); when RPC fails, verdict may be UNVERIFIED. */
  errors: string[];
  analyzedAt: number;
  durationMs: number;
}

export interface AnalyzeTransactionsRequest {
  origin: string;
  method: string;
  walletPubkey?: string;
  /** Serialized transactions (legacy or v0 wire format). */
  transactions: Uint8Array[];
}

export interface AnalyzeMessageRequest {
  origin: string;
  method: string;
  walletPubkey?: string;
  message: Uint8Array;
}

/** Minimal JSON-RPC surface the engine needs. Implemented in analysis/rpc.ts. */
export interface RpcClient {
  call<T = unknown>(method: string, params: unknown[]): Promise<T>;
}

