/**
 * index.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Public entry point for the Aegis Transaction Preview Engine.
 *           Orchestrates wire decoding, optional RPC simulation, and rule
 *           evaluation across single or batched transactions, with clean
 *           fallback to static UNVERIFIED mode when RPC is unavailable.
 *
 * ACCESS:   Pure orchestration plus optional RpcClient calls via simulate.ts.
 *
 * NEVER:    - Never makes direct network calls outside the injected RpcClient.
 *           - Never signs, modifies or broadcasts transactions.
 *           - No storage. No logging. No @solana/web3.js dependency.
 * ---------------------------------------------------------------------------
 */

import {
  type AnalysisReport,
  type AnalyzeTransactionsRequest,
  type DecodedInstruction,
  type Finding,
  type ProgramInfo,
  type RpcClient,
  type TxSummary,
  type Verdict,
  maxSeverity,
  verdictFor,
} from '../../shared/analysis-types';
import { knownProgram } from '../../shared/known-programs';
import { type DecodedIx, decodeInstruction } from './decoders';
import { analyzeMessage } from './message';
import { createRpcClient } from './rpc';
import { evaluateTransactionRules } from './rules';
import { simulateAndDiff } from './simulate';
import { type DecodedTransaction, decodeTransaction, isPlaceholder, resolveAccountKeys } from './wire';

export { analyzeMessage, createRpcClient };

function inferWalletPubkey(decoded: DecodedTransaction, explicitWallet: string | undefined): string {
  if (explicitWallet) return explicitWallet;
  const signers = decoded.message.staticAccountKeys.slice(0, decoded.message.header.numRequiredSignatures);
  for (let i = 0; i < signers.length; i++) {
    const signer = signers[i];
    if (signer && decoded.signatures[i] === null) return signer;
  }
  return signers[0] ?? '';
}

function isPartiallySignedByOther(decoded: DecodedTransaction, wallet: string): boolean {
  const numSigs = decoded.message.header.numRequiredSignatures;
  for (let i = 0; i < numSigs; i++) {
    const signer = decoded.message.staticAccountKeys[i];
    if (decoded.signatures[i] !== null && signer !== wallet) {
      return true;
    }
  }
  return false;
}

function decodeStaticInstructions(decoded: DecodedTransaction): DecodedIx[] {
  const resolved = resolveAccountKeys(decoded.message);
  const out: DecodedIx[] = [];
  for (const ix of decoded.message.instructions) {
    const programId = resolved.keys[ix.programIdIndex] ?? '?';
    const ixAccounts = ix.accountIndexes.map((idx) => resolved.keys[idx] ?? '?');
    out.push(decodeInstruction(programId, ixAccounts, ix.data, false));
  }
  return out;
}

function collectPrograms(
  instructions: DecodedIx[],
  deploySlots?: ReadonlyMap<string, number>,
): ProgramInfo[] {
  const seen = new Set<string>();
  const programs: ProgramInfo[] = [];
  for (const ix of instructions) {
    const pid = ix.programId;
    if (!pid || pid === '?' || isPlaceholder(pid) || seen.has(pid)) continue;
    seen.add(pid);
    const known = knownProgram(pid);
    const deploySlot = deploySlots?.get(pid);
    programs.push({
      programId: pid,
      ...(known ? { name: known.name } : {}),
      known: Boolean(known),
      ...(deploySlot !== undefined ? { deploySlot } : {}),
    });
  }
  return programs;
}

function toPublicInstruction(ix: DecodedIx): DecodedInstruction {
  return {
    programId: ix.programId,
    ...(ix.programName !== undefined ? { programName: ix.programName } : {}),
    name: ix.name,
    params: ix.params,
    ...(ix.inner ? { inner: true } : {}),
  };
}

/**
 * Decodes and analyzes one or more serialized Solana transactions.
 * When `opts.rpc` is null or throws an error, falls back cleanly to static
 * instruction analysis and marks non-DANGER reports as `UNVERIFIED`.
 */
export async function analyzeTransactions(
  req: AnalyzeTransactionsRequest,
  opts: { rpc: RpcClient | null },
): Promise<AnalysisReport> {
  const analyzedAt = Date.now();
  const start = performance.now();
  const errors: string[] = [];
  const summaries: TxSummary[] = [];
  const allFindings: Finding[] = [];

  let rpcAvailable = opts.rpc !== null;
  let rpcSucceededAll = opts.rpc !== null && req.transactions.length > 0;
  let decodeFailed = false;

  if (opts.rpc === null) {
    errors.push('RPC unavailable: static instruction analysis only.');
  }

  for (let index = 0; index < req.transactions.length; index++) {
    const txBytes = req.transactions[index];
    if (!txBytes) continue;

    let decoded: DecodedTransaction;
    try {
      decoded = decodeTransaction(txBytes);
    } catch (e) {
      decodeFailed = true;
      rpcSucceededAll = false;
      const errMsg = e instanceof Error ? e.message : String(e);
      errors.push(`Transaction #${index} decode failed: ${errMsg}`);
      const finding: Finding = {
        id: 'malformed-transaction',
        severity: 'medium',
        title: 'Transaction data could not be decoded',
        detail: 'The serialized transaction bytes did not match a valid Solana wire format, so its contents could not be verified.',
        txIndex: index,
      };
      allFindings.push(finding);
      summaries.push({
        index,
        version: 'legacy',
        feePayer: '',
        signers: [],
        partiallySigned: false,
        usesDurableNonce: false,
        programs: [],
        instructions: [],
        balanceChanges: [],
        authorityChanges: [],
        findings: [finding],
        severity: 'medium',
      });
      continue;
    }

    const signers = decoded.message.staticAccountKeys.slice(0, decoded.message.header.numRequiredSignatures);
    const feePayer = signers[0] ?? '';
    const wallet = inferWalletPubkey(decoded, req.walletPubkey);
    const partiallySigned = isPartiallySignedByOther(decoded, wallet);

    let simOut: Awaited<ReturnType<typeof simulateAndDiff>> | undefined;
    if (rpcAvailable && opts.rpc) {
      try {
        simOut = await simulateAndDiff(txBytes, decoded, wallet, opts.rpc);
      } catch (e) {
        rpcAvailable = false;
        rpcSucceededAll = false;
        const errMsg = e instanceof Error ? e.message : String(e);
        errors.push(errMsg);
      }
    } else {
      rpcSucceededAll = false;
    }

    const instructions = simOut ? simOut.instructions : decodeStaticInstructions(decoded);
    const programs = collectPrograms(instructions, simOut?.programDeploySlots);

    const ruleOut = evaluateTransactionRules({
      txIndex: index,
      version: decoded.message.version,
      ...(decoded.message.transactionConfig?.priorityFeeLamports !== undefined
        ? { v1PriorityFeeLamports: decoded.message.transactionConfig.priorityFeeLamports }
        : {}),
      wallet,
      feePayer,
      signers,
      numRequiredSignatures: decoded.message.header.numRequiredSignatures,
      partiallySigned,
      instructions,
      programs,
      ...(simOut ? { simulation: simOut.simulation } : {}),
      balanceChanges: simOut ? simOut.balanceChanges : [],
      simAuthorityChanges: simOut ? simOut.authorityChanges : [],
      ...(simOut?.preWalletLamports !== undefined ? { preWalletLamports: simOut.preWalletLamports } : {}),
      ...(simOut ? { preTokenAccounts: simOut.preTokenAccounts, postTokenAccounts: simOut.postTokenAccounts, mintInfos: simOut.mintInfos } : {}),
      ...(simOut?.currentSlot !== undefined ? { currentSlot: simOut.currentSlot } : {}),
    });

    allFindings.push(...ruleOut.findings);

    summaries.push({
      index,
      version: decoded.message.version,
      feePayer,
      signers,
      partiallySigned,
      usesDurableNonce: ruleOut.usesDurableNonce,
      programs,
      instructions: instructions.map(toPublicInstruction),
      ...(simOut ? { simulation: simOut.simulation } : {}),
      balanceChanges: simOut ? simOut.balanceChanges : [],
      authorityChanges: ruleOut.authorityChanges,
      ...(ruleOut.approvalDetails.length > 0 ? { approvalDetails: ruleOut.approvalDetails } : {}),
      estimatedFeeLamports: ruleOut.estimatedFeeLamports,
      findings: ruleOut.findings,
      severity: ruleOut.severity,
    });
  }

  const rpcUsed = rpcSucceededAll && !decodeFailed;
  const severity = maxSeverity(summaries.map((s) => s.severity));
  let verdict: Verdict = verdictFor(severity);
  if (!rpcUsed && severity !== 'high' && severity !== 'critical') {
    verdict = 'UNVERIFIED';
  }

  const durationMs = Math.max(0, Math.round(performance.now() - start));

  return {
    kind: 'transaction',
    origin: req.origin,
    method: req.method,
    ...(req.walletPubkey !== undefined ? { walletPubkey: req.walletPubkey } : {}),
    severity,
    verdict,
    findings: allFindings,
    transactions: summaries,
    rpcUsed,
    errors,
    analyzedAt,
    durationMs,
  };
}
