/**
 * message.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Inspects off-chain message payloads (`signMessage` / `signIn`)
 *           before the wallet opens: detects serialized Solana transactions
 *           disguised as messages, validates UTF-8 readability, and checks
 *           Sign-In With Solana (SIWS) domains against the requesting origin.
 *
 * ACCESS:   Pure synchronous functions over message bytes and origin URL.
 *
 * NEVER:    - No network. No storage. No logging.
 *           - Never mutates or signs message bytes.
 * ---------------------------------------------------------------------------
 */

import {
  type AnalysisReport,
  type AnalyzeMessageRequest,
  type Finding,
  type MessageSummary,
  maxSeverity,
  verdictFor,
} from '../../shared/analysis-types';
import { decodeMessage, decodeTransaction } from './wire';

/** Max signatures that can physically fit inside a 1232-byte Solana packet. */
const MAX_PLAUSIBLE_TX_SIGNERS = 20;

/** Matches C0/DEL control bytes excluding tab (\t), newline (\n), and carriage return (\r). */
const BINARY_CONTROL_CHARS = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;

/** Matches the standard Sign-In With Solana (SIWS) first line. */
const SIWS_HEADER_RE = /^\s*([^\s]+)\s+wants you to sign in with your Solana account:\s*(?:\r?\n|$)/i;

function checkLooksLikeTransaction(bytes: Uint8Array): boolean {
  if (bytes.length < 36) return false;
  try {
    const tx = decodeTransaction(bytes);
    if (tx.message.header.numRequiredSignatures <= MAX_PLAUSIBLE_TX_SIGNERS) {
      return true;
    }
  } catch {
    // Not a full wire transaction; check bare message bytes next.
  }

  try {
    const msg = decodeMessage(bytes, true);
    if (msg.header.numRequiredSignatures <= MAX_PLAUSIBLE_TX_SIGNERS) {
      return true;
    }
  } catch {
    // Not a valid bare transaction message either.
  }
  return false;
}

function tryDecodeReadableUtf8(bytes: Uint8Array): string | undefined {
  let decoded: string;
  try {
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
  if (BINARY_CONTROL_CHARS.test(decoded)) return undefined;
  return decoded;
}

function extractSiwsDomain(text: string): string | undefined {
  const match = SIWS_HEADER_RE.exec(text);
  const domain = match?.[1]?.trim();
  return domain && domain.length > 0 ? domain : undefined;
}

function parseOriginHost(origin: string): string | null {
  try {
    return new URL(origin).host;
  } catch {
    return null;
  }
}

/**
 * Analyzes an off-chain message signing request and returns an AnalysisReport.
 */
export function analyzeMessage(req: AnalyzeMessageRequest): AnalysisReport {
  const analyzedAt = Date.now();
  const start = performance.now();
  if (!(req.message instanceof Uint8Array)) {
    const finding: Finding = {
      id: 'binary-message',
      severity: 'medium',
      title: 'Unreadable binary message',
      detail:
        'This request did not provide readable UTF-8 message bytes, so its exact meaning cannot be verified.',
    };
    const severity = maxSeverity([finding.severity]);
    return {
      kind: 'message',
      origin: req.origin,
      method: req.method,
      ...(req.walletPubkey !== undefined ? { walletPubkey: req.walletPubkey } : {}),
      severity,
      verdict: verdictFor(severity),
      findings: [finding],
      message: {
        byteLength: 0,
        isSignInWithSolana: false,
        looksLikeTransaction: false,
      },
      rpcUsed: false,
      errors: ['Invalid message payload: expected Uint8Array.'],
      analyzedAt,
      durationMs: Math.max(0, Math.round(performance.now() - start)),
    };
  }

  const bytes = req.message;
  const findings: Finding[] = [];

  const looksLikeTransaction = checkLooksLikeTransaction(bytes);
  const text = looksLikeTransaction ? undefined : tryDecodeReadableUtf8(bytes);
  const siwsDomain = text !== undefined ? extractSiwsDomain(text) : undefined;
  const isSignInWithSolana = siwsDomain !== undefined;

  if (looksLikeTransaction) {
    findings.push({
      id: 'message-is-transaction',
      severity: 'critical',
      title: 'Message contains a disguised Solana transaction',
      detail:
        'These bytes decode as a Solana transaction, not text. Signing could authorize an on-chain transaction without a preview.',
    });
  } else if (text === undefined) {
    findings.push({
      id: 'binary-message',
      severity: 'medium',
      title: 'Unreadable binary message',
      detail:
        'This request asks you to sign raw binary bytes that cannot be read as text.',
    });
  } else if (isSignInWithSolana && siwsDomain) {
    const originHost = parseOriginHost(req.origin);
    const normalizedSiwsHost = siwsDomain.replace(/^https?:\/\//i, '');
    if (!originHost || normalizedSiwsHost.toLowerCase() !== originHost.toLowerCase()) {
      findings.push({
        id: 'siws-domain-mismatch',
        severity: 'high',
        title: 'Sign-In domain does not match this website',
        detail: `Sign-In message is for "${siwsDomain}", not "${originHost ?? req.origin}". Signing could let this site impersonate your session on ${siwsDomain}.`,
      });
    }
  }

  const summary: MessageSummary = {
    ...(text !== undefined ? { text } : {}),
    byteLength: bytes.byteLength,
    isSignInWithSolana,
    ...(siwsDomain !== undefined ? { siwsDomain } : {}),
    looksLikeTransaction,
  };

  const severity = maxSeverity(findings.map((f) => f.severity));
  const verdict = verdictFor(severity);
  const durationMs = Math.max(0, Math.round(performance.now() - start));

  return {
    kind: 'message',
    origin: req.origin,
    method: req.method,
    ...(req.walletPubkey !== undefined ? { walletPubkey: req.walletPubkey } : {}),
    severity,
    verdict,
    findings,
    message: summary,
    rpcUsed: false,
    errors: [],
    analyzedAt,
    durationMs,
  };
}
