/**
 * review-manager.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Orchestrates the Aegis Transaction, Approval & Connection Gate.
 *           - Passes passive silent reconnects (`onlyIfTrusted`/`silent`) on
 *             non-lookalike sites without popup noise.
 *           - Deep-dives every interactive Wallet Connect, Sign-In With Solana,
 *             and off-chain message signature so the user sees exact origin,
 *             transport security, brand verification, and permissions granted.
 *           - Simulates every transaction and fast-paths clean DEX token buys
 *             and sells straight to the wallet while intercepting every token
 *             Approve / authority delegation, non-swap transfer, unverified
 *             contract call, or high-risk drain in `review.html`.
 * ACCESS:   chrome.windows, chrome.notifications, settings.ts, domains.ts,
 *           and ./analysis/index.
 * NEVER:    Never touches private keys (only public unsigned tx/message bytes
 *           and public wallet addresses). No direct network calls outside
 *           createRpcClient().
 * ---------------------------------------------------------------------------
 */

import {
  maxSeverity,
  verdictFor,
  type AnalysisReport,
  type ConnectDetails,
  type Finding,
} from '../shared/analysis-types';
import {
  PUMP_FUN_PROGRAM_ID,
  isDexProgram,
  isJitoTipAccount,
  isKnownProgram,
} from '../shared/known-programs';
import type {
  GateRequest,
  GateResponse,
  ReviewFetchResponse,
  SiteInfo,
} from '../shared/messages';
import {
  DEFAULT_MAINNET_RPC_URL,
  FALLBACK_MAINNET_RPC_URL,
  getSettings,
} from '../shared/settings';
import { analyzeMessage, analyzeTransactions, createRpcClient } from './analysis/index';
import { evaluateSite } from './domains';

const REVIEW_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

const BLOCKING_SWAP_FINDING_IDS: ReadonlySet<string> = new Set([
  'lingering-delegate-approval',
  'wallet-owner-reassignment',
  'token-account-owner-change',
  'stake-authority-change',
  'program-upgrade-authority-change',
  'nonce-authority-change',
  'close-authority-change',
  'close-account-foreign-destination',
  'multi-token-drain',
  'sol-drain-over-90pct',
  'lookalike-destination',
  'received-mint-permanent-delegate',
  'durable-nonce',
  'unknown-program-recent',
  'high-priority-fee',
  'malformed-transaction',
  'tx-decode-error',
  'missing-tx-payload',
  'simulation-failed',
  'unreadable-transaction-input',
  'lookalike-domain',
]);

interface PendingReview {
  reviewId: string;
  request: GateRequest;
  report: AnalysisReport;
  site: SiteInfo;
  expiresAt: number;
  windowId?: number;
  timer: ReturnType<typeof setTimeout>;
  resolve: (decision: GateResponse) => void;
}

interface ParsedOriginInfo {
  origin: string;
  hostname: string;
  host: string;
  protocol: string;
  port?: string;
  isHttps: boolean;
  isLocalhost: boolean;
  hasPunycode: boolean;
}

const pendingReviews = new Map<string, PendingReview>();
let windowListenerBound = false;

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function parseOriginInfo(rawOrigin: string, site: SiteInfo): ParsedOriginInfo {
  const trimmed = rawOrigin.trim();
  try {
    const parsed = new URL(trimmed);
    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
    const host = parsed.host.toLowerCase();
    const protocol = parsed.protocol.toLowerCase();
    const port = parsed.port || undefined;
    const isLocalhost =
      hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
    const isHttps = protocol === 'https:';
    const hasPunycode = hostname.split('.').some((lbl) => lbl.startsWith('xn--'));
    return {
      origin: parsed.origin,
      hostname: hostname || site.hostname || trimmed,
      host: host || hostname,
      protocol,
      ...(port ? { port } : {}),
      isHttps,
      isLocalhost,
      hasPunycode,
    };
  } catch {
    const fallbackHost = site.hostname || trimmed || 'unknown';
    return {
      origin: trimmed || fallbackHost,
      hostname: fallbackHost,
      host: fallbackHost,
      protocol: 'unknown:',
      isHttps: false,
      isLocalhost: false,
      hasPunycode: fallbackHost.split('.').some((lbl) => lbl.startsWith('xn--')),
    };
  }
}

function domainMatchesOrigin(claimed: string, orig: ParsedOriginInfo): boolean {
  const normalized = claimed
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .toLowerCase();
  if (!normalized || !orig.host) return false;
  return normalized === orig.host || normalized === orig.hostname;
}

function uriMatchesOriginHost(rawUri: string, orig: ParsedOriginInfo): boolean {
  try {
    const u = new URL(rawUri.trim());
    const uHost = u.hostname.toLowerCase().replace(/\.$/, '');
    return Boolean(uHost) && uHost === orig.hostname;
  } catch {
    return false;
  }
}

function parseSiwsTextFields(text: string): {
  uri?: string;
  nonce?: string;
  issuedAt?: string;
  expirationTime?: string;
  chainId?: string;
  statement?: string;
  resources?: string[];
} {
  const lines = text.split(/\r?\n/);
  let uri: string | undefined;
  let nonce: string | undefined;
  let issuedAt: string | undefined;
  let expirationTime: string | undefined;
  let chainId: string | undefined;
  const resources: string[] = [];
  let inResources = false;
  let metaStartIdx = lines.length;

  const metaPatterns: Array<[RegExp, (val: string) => void]> = [
    [/^URI:\s*(.+)$/i, (v) => (uri = v.trim())],
    [/^Version:\s*(.+)$/i, () => {}],
    [/^Chain ID:\s*(.+)$/i, (v) => (chainId = v.trim())],
    [/^Nonce:\s*(.+)$/i, (v) => (nonce = v.trim())],
    [/^Issued At:\s*(.+)$/i, (v) => (issuedAt = v.trim())],
    [/^Expiration Time:\s*(.+)$/i, (v) => (expirationTime = v.trim())],
    [/^Not Before:\s*(.+)$/i, () => {}],
    [/^Request ID:\s*(.+)$/i, () => {}],
  ];

  for (let i = 2; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (/^Resources:\s*$/i.test(line.trim())) {
      if (metaStartIdx === lines.length) metaStartIdx = i;
      inResources = true;
      continue;
    }
    if (inResources) {
      const m = /^\s*-\s*(.+)$/.exec(line);
      if (m?.[1]) resources.push(m[1].trim());
      continue;
    }
    for (const [re, assign] of metaPatterns) {
      const m = re.exec(line.trim());
      if (m?.[1] !== undefined) {
        if (metaStartIdx === lines.length) metaStartIdx = i;
        assign(m[1]);
        break;
      }
    }
  }

  const stmtLines = lines
    .slice(2, metaStartIdx)
    .map((l) => l.trim())
    .filter(Boolean);
  const statement = stmtLines.length > 0 ? stmtLines.join(' ') : undefined;

  return {
    ...(uri ? { uri } : {}),
    ...(nonce ? { nonce } : {}),
    ...(issuedAt ? { issuedAt } : {}),
    ...(expirationTime ? { expirationTime } : {}),
    ...(chainId ? { chainId } : {}),
    ...(statement ? { statement } : {}),
    ...(resources.length > 0 ? { resources } : {}),
  };
}

export function buildConnectDetails(
  req: GateRequest,
  site: SiteInfo,
  report: AnalysisReport,
): ConnectDetails {
  const orig = parseOriginInfo(req.origin, site);
  const isLegacyReq = req.method.startsWith('request:');
  const isSiwsMessage = Boolean(report.message?.isSignInWithSolana);
  const requestKind: ConnectDetails['requestKind'] = isLegacyReq
    ? 'legacyRequest'
    : req.method === 'signIn' || isSiwsMessage
      ? 'signIn'
      : req.method === 'signMessage' || report.kind === 'message'
        ? 'signMessage'
        : 'connect';

  let actionHeadline = 'Wallet Connection';
  let permissionsGranted: string[] = [];
  let protectionsKept: string[] = [];

  if (requestKind === 'connect') {
    actionHeadline = 'Wallet Connection';
    permissionsGranted = [
      'Read your public wallet address',
      'View your SOL and token balances',
      'Request future signatures from your wallet',
    ];
    protectionsKept = [
      'Move SOL, tokens, or NFTs',
      'Approve token spending limits',
      'Access your private key or seed phrase',
    ];
  } else if (requestKind === 'signIn') {
    actionHeadline = 'Sign-In With Solana';
    permissionsGranted = [
      'Verify wallet ownership for login',
      'Read your public address and balances',
    ];
    protectionsKept = [
      'Move SOL or tokens on-chain',
      'Grant token spending approvals',
    ];
  } else if (requestKind === 'signMessage') {
    actionHeadline = 'Message Signature';
    permissionsGranted = [
      'Sign this off-chain message with your wallet',
      'Confirm the action written in the message',
    ];
    protectionsKept = report.message?.looksLikeTransaction
      ? []
      : [
          'Submit an on-chain Solana transaction',
          'Grant SPL token spending approvals',
        ];
  } else {
    actionHeadline = `Legacy Call (${req.method})`;
    permissionsGranted = [
      'Send a legacy request to your wallet',
    ];
    protectionsKept = [
      'Sign without confirmation inside your wallet',
    ];
  }

  let siws: ConnectDetails['siws'];
  if (req.method === 'signIn' || req.signInDomain || req.signInFields || isSiwsMessage) {
    const parsedFromText =
      report.message?.text && isSiwsMessage ? parseSiwsTextFields(report.message.text) : {};
    const claimedDomain =
      req.signInDomain?.trim() ||
      req.signInFields?.domain?.trim() ||
      report.message?.siwsDomain?.trim() ||
      orig.host;
    const matchesDomain = domainMatchesOrigin(claimedDomain, orig);
    const rawUri = req.signInFields?.uri?.trim() || parsedFromText.uri;
    const matchesUri = rawUri ? uriMatchesOriginHost(rawUri, orig) : undefined;
    const statement = req.signInFields?.statement?.trim() || parsedFromText.statement;
    const nonce = req.signInFields?.nonce?.trim() || parsedFromText.nonce;
    const issuedAt = req.signInFields?.issuedAt?.trim() || parsedFromText.issuedAt;
    const expirationTime = req.signInFields?.expirationTime?.trim() || parsedFromText.expirationTime;
    const chainId = req.signInFields?.chainId?.trim() || parsedFromText.chainId;
    const resources = req.signInFields?.resources ?? parsedFromText.resources;

    siws = {
      claimedDomain,
      domainMatchesOrigin: matchesDomain,
      ...(rawUri ? { uri: rawUri, uriMatchesOrigin: matchesUri } : {}),
      ...(statement ? { statement } : {}),
      ...(nonce ? { nonce } : {}),
      ...(issuedAt ? { issuedAt } : {}),
      ...(expirationTime ? { expirationTime } : {}),
      ...(chainId ? { chainId } : {}),
      ...(resources && resources.length > 0 ? { resources } : {}),
    };
  }

  return {
    requestKind,
    actionHeadline,
    origin: orig.origin,
    hostname: orig.hostname,
    protocol: orig.protocol.replace(/:$/, '').toUpperCase(),
    ...(orig.port ? { port: orig.port } : {}),
    isHttps: orig.isHttps,
    isLocalhost: orig.isLocalhost,
    hasPunycode: orig.hasPunycode,
    siteStatus: site.status,
    ...(site.brand ? { officialBrand: site.brand } : {}),
    ...(site.officialDomain ? { officialDomain: site.officialDomain } : {}),
    ...(site.reason ? { lookalikeReason: site.reason } : {}),
    walletName: req.wallet || 'Wallet',
    ...(req.walletPubkey ? { walletPubkey: req.walletPubkey } : {}),
    permissionsGranted,
    protectionsKept,
    ...(siws ? { siws } : {}),
  };
}

function buildFallbackReport(req: GateRequest, site: SiteInfo): AnalysisReport {
  const started = Date.now();
  const orig = parseOriginInfo(req.origin, site);

  if (req.method.startsWith('request:')) {
    return {
      kind: 'connect',
      origin: req.origin,
      method: req.method,
      walletPubkey: req.walletPubkey,
      severity: 'low',
      verdict: 'CAUTION',
      findings: [
        {
          id: 'legacy-unstructured-request',
          severity: 'low',
          title: 'Legacy wallet call cannot be previewed',
          detail:
            req.note ??
            'This site used an older provider.request() call. Check the details inside your wallet before approving.',
        },
      ],
      rpcUsed: false,
      errors: [],
      analyzedAt: started,
      durationMs: 0,
    };
  }

  if (req.method === 'signIn') {
    const findings: Finding[] = [];
    const rawClaimed = (req.signInDomain ?? req.signInFields?.domain ?? '').trim();
    if (rawClaimed && !domainMatchesOrigin(rawClaimed, orig)) {
      findings.push({
        id: 'siws-domain-mismatch',
        severity: 'high',
        title: 'Sign-In domain does not match this website',
        detail: `${orig.host || req.origin} asked you to sign in as "${rawClaimed}". Signing could let this site impersonate your session on ${rawClaimed}.`,
      });
    }

    const rawUri = req.signInFields?.uri?.trim();
    if (rawUri && !uriMatchesOriginHost(rawUri, orig)) {
      findings.push({
        id: 'siws-uri-mismatch',
        severity: 'high',
        title: 'Sign-In URI points to a different website',
        detail: `Sign-in URI "${rawUri}" does not match "${orig.hostname}". Reject to avoid session spoofing.`,
      });
    }

    if (findings.length === 0) {
      findings.push({
        id: 'sign-in-with-solana',
        severity: 'info',
        title: 'Sign-In verification request',
        detail:
          req.note ??
          `${site.hostname || req.origin} requested a Sign-In With Solana signature.`,
      });
    }

    const sev = maxSeverity(findings.map((f) => f.severity));
    return {
      kind: 'connect',
      origin: req.origin,
      method: req.method,
      walletPubkey: req.walletPubkey,
      severity: sev,
      verdict: verdictFor(sev),
      findings,
      rpcUsed: false,
      errors: [],
      analyzedAt: started,
      durationMs: 0,
    };
  }

  return {
    kind: 'connect',
    origin: req.origin,
    method: req.method,
    walletPubkey: req.walletPubkey,
    severity: 'safe',
    verdict: 'SAFE',
    findings: [
      {
        id: 'wallet-connect-request',
        severity: 'safe',
        title: 'Share public wallet address',
        detail:
          'Shares your public wallet address and balances with this site.',
      },
    ],
    rpcUsed: false,
    errors: [],
    analyzedAt: started,
    durationMs: 0,
  };
}

function isTxMethod(method: string): boolean {
  return (
    method === 'signTransaction' ||
    method === 'signAllTransactions' ||
    method === 'signAndSendTransaction' ||
    method === 'signAndSendAllTransactions'
  );
}

async function buildAnalysisReport(
  req: GateRequest,
  site: SiteInfo,
  rpcUrl: string,
): Promise<AnalysisReport> {
  const started = Date.now();
  const cleanRpcUrl = rpcUrl.trim();
  const rpc = cleanRpcUrl ? createRpcClient(cleanRpcUrl) : null;

  if (Array.isArray(req.transactions) && req.transactions.length > 0) {
    try {
      const txBytes = req.transactions.map(fromBase64);
      const txInput = {
        origin: req.origin,
        method: req.method,
        walletPubkey: req.walletPubkey,
        transactions: txBytes,
      };
      const primaryReport = await analyzeTransactions(txInput, { rpc });
      if (
        cleanRpcUrl === DEFAULT_MAINNET_RPC_URL &&
        !primaryReport.rpcUsed &&
        primaryReport.errors.length > 0
      ) {
        return await analyzeTransactions(txInput, {
          rpc: createRpcClient(FALLBACK_MAINNET_RPC_URL),
        });
      }
      return primaryReport;
    } catch (e) {
      return {
        kind: 'transaction',
        origin: req.origin,
        method: req.method,
        walletPubkey: req.walletPubkey,
        severity: 'medium',
        verdict: 'UNVERIFIED',
        findings: [
          {
            id: 'tx-decode-error',
            severity: 'medium',
            title: 'Transaction bytes could not be decoded',
            detail:
              'Could not parse this transaction payload. Reject if you did not initiate it.',
          },
        ],
        rpcUsed: false,
        errors: [e instanceof Error ? e.message : String(e)],
        analyzedAt: started,
        durationMs: Date.now() - started,
      };
    }
  }

  if (isTxMethod(req.method)) {
    return {
      kind: 'transaction',
      origin: req.origin,
      method: req.method,
      walletPubkey: req.walletPubkey,
      severity: 'medium',
      verdict: 'UNVERIFIED',
      findings: [
        {
          id: 'missing-tx-payload',
          severity: 'medium',
          title: 'Transaction payload unavailable',
          detail:
            req.note ??
            'This site requested a transaction signature without readable bytes.',
        },
      ],
      rpcUsed: false,
      errors: ['No serialized transaction bytes provided.'],
      analyzedAt: started,
      durationMs: Date.now() - started,
    };
  }

  if (typeof req.message === 'string' && req.message.length > 0) {
    try {
      const msgBytes = fromBase64(req.message);
      return await Promise.resolve(
        analyzeMessage({
          origin: req.origin,
          method: req.method,
          walletPubkey: req.walletPubkey,
          message: msgBytes,
        }),
      );
    } catch (e) {
      return {
        kind: 'message',
        origin: req.origin,
        method: req.method,
        walletPubkey: req.walletPubkey,
        severity: 'medium',
        verdict: 'CAUTION',
        findings: [
          {
            id: 'message-decode-error',
            severity: 'medium',
            title: 'Message payload could not be decoded',
            detail: 'Could not read the message bytes for this signature request.',
          },
        ],
        rpcUsed: false,
        errors: [e instanceof Error ? e.message : String(e)],
        analyzedAt: started,
        durationMs: Date.now() - started,
      };
    }
  }

  if (req.method === 'signMessage') {
    return {
      kind: 'message',
      origin: req.origin,
      method: req.method,
      walletPubkey: req.walletPubkey,
      severity: 'medium',
      verdict: 'CAUTION',
      findings: [
        {
          id: 'missing-message-payload',
          severity: 'medium',
          title: 'Message payload unavailable',
          detail:
            'This site requested a message signature without readable message bytes.',
        },
      ],
      rpcUsed: false,
      errors: ['Message payload missing or empty.'],
      analyzedAt: started,
      durationMs: Date.now() - started,
    };
  }

  return buildFallbackReport(req, site);
}

function enrichAndEscalateReport(
  report: AnalysisReport,
  req: GateRequest,
  site: SiteInfo,
): AnalysisReport {
  const prepended: Finding[] = [];
  let minSeverity = report.severity;
  const orig = parseOriginInfo(req.origin, site);

  const unreadableCount = req.unreadableCount ?? 0;
  if (unreadableCount > 0) {
    prepended.push({
      id: 'unreadable-transaction-input',
      severity: 'high',
      title:
        unreadableCount === 1
          ? '1 transaction in this batch could not be read'
          : `${unreadableCount} transactions in this batch could not be read`,
      detail:
        'Part of this batch could not be serialized for inspection. Harmful instructions may be hidden.',
    });
    minSeverity = maxSeverity([minSeverity, 'high']);
  }

  if (site.status === 'lookalike') {
    prepended.push({
      id: 'lookalike-domain',
      severity: 'high',
      title: site.brand
        ? `Possible ${site.brand} lookalike domain`
        : 'Suspicious lookalike domain',
      detail:
        site.reason ??
        `"${site.hostname}" resembles ${site.officialDomain ?? 'a known Solana app'}. Check the URL carefully.`,
    });
    minSeverity = maxSeverity([minSeverity, 'high']);
  }

  const connectDetails =
    report.kind === 'connect' || report.kind === 'message'
      ? buildConnectDetails(req, site, report)
      : undefined;

  if (connectDetails) {
    if (
      connectDetails.siws?.uri &&
      connectDetails.siws.uriMatchesOrigin === false &&
      !report.findings.some((f) => f.id === 'siws-uri-mismatch')
    ) {
      prepended.push({
        id: 'siws-uri-mismatch',
        severity: 'high',
        title: 'Sign-In URI points to a different website',
        detail: `Sign-in URI "${connectDetails.siws.uri}" does not match "${orig.hostname}". Signing could spoof your session elsewhere.`,
      });
      minSeverity = maxSeverity([minSeverity, 'high']);
    }

    if (!orig.isHttps && !orig.isLocalhost) {
      prepended.push({
        id: 'insecure-http-origin',
        severity: 'medium',
        title: 'Unencrypted HTTP connection',
        detail: `${orig.origin} is not using HTTPS. Page scripts can be tampered with on the network.`,
      });
      minSeverity = maxSeverity([minSeverity, 'medium']);
    }
  }

  if (prepended.length === 0 && !connectDetails) return report;

  const escalatedVerdict =
    minSeverity === 'high' || minSeverity === 'critical'
      ? 'DANGER'
      : report.verdict === 'UNVERIFIED'
        ? 'UNVERIFIED'
        : verdictFor(minSeverity);

  return {
    ...report,
    severity: minSeverity,
    verdict: escalatedVerdict,
    findings: prepended.length > 0 ? [...prepended, ...report.findings] : report.findings,
    ...(connectDetails ? { connectDetails } : {}),
  };
}

/**
 * ARCHITECTURAL DESIGN NOTE: Clean DEX Swap Fast-Pathing & Prompt-Fatigue Elimination
 *
 * In Solana DeFi, active traders execute dozens or hundreds of token swaps daily across
 * Jupiter, Raydium, Meteora, and pump.fun. Intercepting every benign swap with a mandatory
 * review modal induces severe "prompt fatigue": users reflexively click "Allow" without
 * reading, neutralizing the security utility of the gate when an actual drainer strikes.
 *
 * Aegis fast-paths a transaction directly to the wallet ONLY when all of the following
 * invariants are strictly satisfied:
 *   1. Routes through a known, verified Solana DEX or AMM program (`isDexProgram`).
 *   2. Strictly ZERO authority reassignments (wallet owner, token owner, close authority).
 *   3. Strictly ZERO lingering delegate approvals (`tx.approvalDetails.length === 0`).
 *   4. Strictly ZERO durable nonces (`!usesDurableNonce`).
 *   5. Simulation verifies actual buy/sell asset exchange (genuine inflow of tokens or SOL).
 *   6. Top-level SOL transfers to unrecognized external addresses are capped at <= 3%
 *      router/platform fee; anything larger or suspicious halts the fast-path.
 *   7. The originating site is not flagged as a lookalike domain.
 *
 * Any transaction that deviates from these invariants is immediately escalated to the
 * high-contrast `review.html` isolated popup window for deep-dive user confirmation.
 */
export function isCleanBuyOrSellSwap(
  report: AnalysisReport,
  req: GateRequest,
  site: SiteInfo,
  rpcFailurePolicy: 'warn' | 'block',
): boolean {
  if (report.kind !== 'transaction') return false;
  if (site.status === 'lookalike') return false;
  if ((req.unreadableCount ?? 0) > 0) return false;
  if (report.verdict === 'DANGER') return false;
  if (report.severity === 'high' || report.severity === 'critical') return false;

  const txs = report.transactions;
  if (!Array.isArray(txs) || txs.length === 0) return false;

  if (report.findings.some((f) => BLOCKING_SWAP_FINDING_IDS.has(f.id))) {
    return false;
  }

  for (const tx of txs) {
    // 1. Must route through at least one recognized Solana DEX / swap program.
    const hasDex = tx.programs.some((p) => isDexProgram(p.programId));
    if (!hasDex) return false;

    // 2. Strictly zero active approvals, authority changes, or durable nonces.
    if (tx.authorityChanges.length > 0) return false;
    if ((tx.approvalDetails?.length ?? 0) > 0) return false;
    if (tx.usesDurableNonce) return false;

    // 3. Defense-in-depth: never fast-path any outer Approve / SetAuthority / Assign / Authorize
    //    or top-level Token Transfer (legitimate DEX swaps move tokens via inner CPI).
    const createdUserAccts = new Set<string>();
    for (const ix of tx.instructions) {
      if (
        (ix.name.includes('AssociatedToken: Create') || ix.name.includes(': InitializeAccount')) &&
        ix.params.account &&
        (!report.walletPubkey || !ix.params.owner || ix.params.owner === report.walletPubkey)
      ) {
        createdUserAccts.add(ix.params.account);
      }
    }

    let directUnknownSolOut = 0n;
    for (const ix of tx.instructions) {
      if (ix.inner) continue;
      const n = ix.name;
      if (
        n.includes(': Approve') ||
        n.includes(': SetAuthority') ||
        n.startsWith('System: Assign') ||
        n.startsWith('Stake: Authorize') ||
        n.startsWith('UpgradeableLoader: SetAuthority') ||
        n === 'System: AuthorizeNonceAccount' ||
        n.includes(': Transfer') && !n.startsWith('System: Transfer')
      ) {
        return false;
      }
      if (n.startsWith('System: Transfer') && ix.params.to) {
        const dest = ix.params.to;
        const isSelfOrAta =
          dest === report.walletPubkey || dest === tx.feePayer || createdUserAccts.has(dest);
        if (!isSelfOrAta && !isJitoTipAccount(dest) && !isKnownProgram(dest)) {
          try {
            directUnknownSolOut += BigInt(ix.params.lamports ?? '0');
          } catch {
            return false;
          }
        }
      }
    }

    // 4. Confirm actual buy/sell asset exchange and ensure no outsized side-transfer to an EOA.
    if (report.rpcUsed) {
      if (!tx.simulation?.ok) return false;
      const solChangeEntry = tx.balanceChanges.find((b) => b.asset === 'SOL');
      const solRaw = BigInt(solChangeEntry?.rawChange ?? '0');
      const absSol = solRaw < 0n ? -solRaw : solRaw;
      // Allow up to 3% router/platform fee transfer on swaps; review anything larger sent directly to an EOA.
      if (directUnknownSolOut > 0n && (absSol === 0n || directUnknownSolOut * 100n > absSol * 3n)) {
        return false;
      }

      const isPumpCreate =
        tx.partiallySigned && tx.programs.some((p) => p.programId === PUMP_FUN_PROGRAM_ID);
      const hasTokenInflow = tx.balanceChanges.some(
        (b) => b.asset !== 'SOL' && !b.rawChange.startsWith('-') && b.rawChange !== '0',
      );
      const tokenOutCount = tx.balanceChanges.filter(
        (b) => b.asset !== 'SOL' && b.rawChange.startsWith('-'),
      ).length;
      // Require > 0.003 SOL net inflow (above ATA rent reclaim) when selling tokens for SOL
      const hasGenuineSolInflow = solRaw > 3_000_000n;
      const isSwapFlow =
        isPumpCreate || hasTokenInflow || (tokenOutCount >= 1 && hasGenuineSolInflow);
      if (!isSwapFlow) return false;
    } else {
      if (rpcFailurePolicy === 'block') return false;
      if (directUnknownSolOut > 0n) return false;
      if (!tx.findings.some((f) => f.id === 'normal-swap')) return false;
    }
  }

  return true;
}

function bindWindowCloseListener(): void {
  if (windowListenerBound || !chrome.windows?.onRemoved) return;
  windowListenerBound = true;

  chrome.windows.onRemoved.addListener((closedWindowId) => {
    for (const [id, entry] of pendingReviews.entries()) {
      if (entry.windowId === closedWindowId) {
        pendingReviews.delete(id);
        clearTimeout(entry.timer);
        entry.resolve({ allow: false, reason: 'Review window closed by user' });
      }
    }
  });
}

export async function handleGateRequest(req: GateRequest): Promise<GateResponse> {
  bindWindowCloseListener();

  const settings = await getSettings();
  if (!settings.transactionGate) {
    return { allow: true, reason: 'Transaction gate disabled in settings' };
  }

  const site = evaluateSite(req.origin);

  // Passive background session restore (`connect({ onlyIfTrusted: true })` / `{ silent: true }`)
  // passes silently on non-lookalike sites so refreshing tabs does not spam popups.
  // Every interactive Wallet Connect (`!req.silentConnect`), Sign-In, and Message Signature
  // proceeds to full deep-dive review in review.html!
  if (req.method === 'connect' && req.silentConnect === true && site.status !== 'lookalike') {
    return { allow: true, reason: 'Silent auto-reconnect allowed on non-lookalike site' };
  }

  const baseReport = await buildAnalysisReport(req, site, settings.rpcUrl);
  const report = enrichAndEscalateReport(baseReport, req, site);

  // Enforce strict RPC failure policy when configured to 'block' on unsimulated transactions
  if (
    report.kind === 'transaction' &&
    !report.rpcUsed &&
    settings.rpcFailure === 'block'
  ) {
    chrome.notifications.create(`aegis-rpc-block-${Date.now()}`, {
      type: 'basic',
      iconUrl: 'icon128.png',
      title: 'Transaction blocked',
      message: 'Could not reach Solana RPC to simulate this transaction.',
    });
    return {
      allow: false,
      reason: 'Blocked because transaction simulation RPC was unavailable (RPC failure policy: Block).',
    };
  }

  // Buying / selling tokens on recognized DEXes passes straight to the wallet with zero friction
  // when simulation & deep-dive checks confirm zero approvals, zero authority changes, and zero drain risk.
  if (isCleanBuyOrSellSwap(report, req, site, settings.rpcFailure)) {
    return {
      allow: true,
      reason: 'Clean DEX swap passed to wallet',
    };
  }

  const reviewId = crypto.randomUUID();
  const expiresAt = Date.now() + REVIEW_TIMEOUT_MS;

  return new Promise<GateResponse>((resolve) => {
    const timer = setTimeout(() => {
      const current = pendingReviews.get(reviewId);
      if (!current) return;
      pendingReviews.delete(reviewId);
      if (typeof current.windowId === 'number') {
        chrome.windows.remove(current.windowId).catch(() => {});
      }
      resolve({ allow: false, reason: 'Review timed out after 5 minutes' });
    }, REVIEW_TIMEOUT_MS);

    const entry: PendingReview = {
      reviewId,
      request: req,
      report,
      site,
      expiresAt,
      timer,
      resolve,
    };
    pendingReviews.set(reviewId, entry);

    // ARCHITECTURAL DESIGN NOTE: OS-Level Popup Window vs. In-Page Modal Isolation
    // In-page modals (even in shadow DOMs) are vulnerable to CSS opacity overlays, viewport
    // repositioning, z-index wars, and iframe clickjacking orchestrated by malicious dApps.
    // By launching `chrome.windows.create({ type: 'popup' })`, Aegis renders the approval UI
    // inside a dedicated native window on the `chrome-extension://` origin. Webpages possess
    // zero DOM, CSS, or script access to this window, ensuring untampered review fidelity.
    const reviewUrl = chrome.runtime.getURL(`review.html?id=${encodeURIComponent(reviewId)}`);
    // AEGIS-PERMISSION: opens an isolated extension popup window that web pages cannot overlay or click.
    chrome.windows
      .create({
        url: reviewUrl,
        type: 'popup',
        width: 472,
        height: 700,
        focused: true,
      })
      .then((win) => {
        const stillPending = pendingReviews.get(reviewId);
        if (stillPending && win?.id !== undefined) {
          stillPending.windowId = win.id;
        }
      })
      .catch(() => {
        const stillPending = pendingReviews.get(reviewId);
        if (!stillPending) return;
        pendingReviews.delete(reviewId);
        clearTimeout(stillPending.timer);
        resolve({ allow: false, reason: 'Could not open Aegis review window' });
      });
  });
}

export function getPendingReview(reviewId: string): ReviewFetchResponse {
  const entry = pendingReviews.get(reviewId);
  if (!entry) {
    return {
      request: { type: 'gate', origin: '', method: 'unknown', wallet: 'Wallet' },
      report: null,
      pending: false,
      error: 'This review session has already completed or expired.',
    };
  }
  return {
    request: entry.request,
    report: entry.report,
    pending: true,
    site: entry.site,
    expiresAt: entry.expiresAt,
  };
}

export function decidePendingReview(reviewId: string, allow: boolean): boolean {
  const entry = pendingReviews.get(reviewId);
  if (!entry) return false;
  pendingReviews.delete(reviewId);
  clearTimeout(entry.timer);
  const winId = entry.windowId;
  const finish = () => {
    entry.resolve({
      allow: allow === true,
      reason: allow === true ? 'Approved in Aegis review' : 'Rejected in Aegis review',
    });
  };
  setTimeout(() => {
    if (typeof winId === 'number') {
      chrome.windows
        .remove(winId)
        .catch(() => {})
        .finally(finish);
    } else {
      finish();
    }
  }, 30);
  return true;
}
