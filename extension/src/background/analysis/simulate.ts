/**
 * simulate.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Resolves v0 address lookup tables, fetches pre-transaction account
 *           states, runs `simulateTransaction` via the injected RpcClient,
 *           decodes inner (CPI) instructions, and computes plain-language
 *           balance and authority diffs plus Token-2022 mint metadata and
 *           unknown-program deployment ages.
 *
 * ACCESS:   Calls the caller-supplied RpcClient interface (implemented in
 *           rpc.ts). Pure state diffing over returned RPC payloads.
 *
 * NEVER:    - Never makes direct fetch/network calls outside RpcClient.
 *           - Never signs, mutates or broadcasts transactions.
 *           - No storage. No logging. No @solana/web3.js dependency.
 * ---------------------------------------------------------------------------
 */

import type {
  AuthorityChange,
  BalanceChange,
  RpcClient,
  SimulationSummary,
} from '../../shared/analysis-types';
import {
  BPF_UPGRADEABLE_LOADER_ID,
  SYSTEM_PROGRAM_ID,
  USDC_MINT,
  USDT_MINT,
  WELL_KNOWN_MINTS,
  WSOL_MINT,
  isKnownProgram,
} from '../../shared/known-programs';
import {
  type AccountState,
  type MintInfo,
  type RpcAccount,
  type TokenAccountInfo,
  parseMint,
  parseProgramAccount,
  parseProgramData,
  parseRpcAccount,
  parseTokenAccount,
} from './accounts';
import { decodeBase58, encodeBase64, formatUnits } from './bytes';
import { type DecodedIx, decodeInstruction } from './decoders';
import { RpcError } from './rpc';
import {
  type DecodedTransaction,
  type ResolvedKeys,
  isPlaceholder,
  parseLookupTableAddresses,
  resolveAccountKeys,
} from './wire';

const RPC_ACCOUNT_CHUNK_SIZE = 100;
const RPC_FALLBACK_CHUNK_SIZE = 10;
const MAX_SIMULATE_ACCOUNTS = 100;
const MAX_LOG_TAIL_LINES = 10;

interface RpcContextValue<T> {
  context?: { slot?: number };
  value: T;
}

interface RpcInnerInstruction {
  programIdIndex: number;
  accounts?: number[];
  accountIndexes?: number[];
  data?: string;
}

interface RpcInnerInstructionGroup {
  index: number;
  instructions: RpcInnerInstruction[];
}

interface RpcSimulationValue {
  err: unknown;
  logs?: string[] | null;
  accounts?: (RpcAccount | null)[] | null;
  unitsConsumed?: number;
  innerInstructions?: RpcInnerInstructionGroup[] | null;
}

export interface SimulationOutput {
  resolvedKeys: ResolvedKeys;
  /** Outer and inner (CPI) decoded instructions in execution order. */
  instructions: DecodedIx[];
  simulation: SimulationSummary;
  balanceChanges: BalanceChange[];
  authorityChanges: AuthorityChange[];
  /** Pre-simulation SOL balance of the user's wallet, when inspected. */
  preWalletLamports?: bigint;
  /** Pre-simulation token accounts keyed by account address. */
  preTokenAccounts: Map<string, TokenAccountInfo>;
  /** Post-simulation token accounts keyed by account address. */
  postTokenAccounts: Map<string, TokenAccountInfo>;
  /** Parsed mint details and Token-2022 extensions keyed by mint address. */
  mintInfos: Map<string, MintInfo>;
  /** Deployment slots keyed by unknown program ID, when available. */
  programDeploySlots: Map<string, number>;
  /** Observed chain slot from RPC context or getSlot, when available. */
  currentSlot?: number;
}

function dedupeAddresses(list: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const addr of list) {
    if (!addr || isPlaceholder(addr) || seen.has(addr)) continue;
    seen.add(addr);
    out.push(addr);
  }
  return out;
}

/**
 * Fetches arbitrary-length account lists in chunks of 100 keys using
 * `getMultipleAccounts` (`encoding: 'base64'`), automatically retrying in
 * chunks of 10 keys when a public RPC enforces a 10-account limit.
 */
export async function fetchMultipleAccounts(
  rpc: RpcClient,
  addresses: string[],
): Promise<{ accounts: Map<string, AccountState | null>; slot?: number }> {
  const accounts = new Map<string, AccountState | null>();
  let slot: number | undefined;
  const unique = dedupeAddresses(addresses);
  if (unique.length === 0) return { accounts };

  let chunkSize = RPC_ACCOUNT_CHUNK_SIZE;
  let start = 0;
  while (start < unique.length) {
    const chunk = unique.slice(start, start + chunkSize);
    let raw: RpcContextValue<(RpcAccount | null)[]> | (RpcAccount | null)[];
    try {
      raw = await rpc.call<RpcContextValue<(RpcAccount | null)[]> | (RpcAccount | null)[]>(
        'getMultipleAccounts',
        [chunk, { encoding: 'base64' }],
      );
    } catch (e) {
      if (e instanceof RpcError && chunk.length > RPC_FALLBACK_CHUNK_SIZE) {
        chunkSize = RPC_FALLBACK_CHUNK_SIZE;
        continue;
      }
      throw e;
    }
    const values = Array.isArray(raw) ? raw : raw.value;
    if (!Array.isArray(raw) && typeof raw.context?.slot === 'number') {
      slot = raw.context.slot;
    }
    for (let i = 0; i < chunk.length; i++) {
      const addr = chunk[i];
      if (!addr) continue;
      accounts.set(addr, parseRpcAccount(values?.[i] ?? null));
    }
    start += chunk.length;
  }
  return { accounts, ...(slot !== undefined ? { slot } : {}) };
}

function formatSimulationError(err: unknown): string {
  if (typeof err === 'string') return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

function decodeOuterAndInnerInstructions(
  decoded: DecodedTransaction,
  keys: string[],
  innerGroups: RpcInnerInstructionGroup[] | null | undefined,
): DecodedIx[] {
  const grouped = new Map<number, RpcInnerInstruction[]>();
  const trailing: RpcInnerInstruction[] = [];
  const outerCount = decoded.message.instructions.length;

  for (const group of innerGroups ?? []) {
    if (group.index >= 0 && group.index < outerCount) {
      const existing = grouped.get(group.index);
      if (existing) existing.push(...group.instructions);
      else grouped.set(group.index, [...group.instructions]);
    } else {
      trailing.push(...group.instructions);
    }
  }

  const decodeInner = (cix: RpcInnerInstruction): DecodedIx => {
    const programId = keys[cix.programIdIndex] ?? '?';
    const idxList = cix.accounts ?? cix.accountIndexes ?? [];
    const ixAccounts = idxList.map((idx) => keys[idx] ?? '?');
    let data: Uint8Array = new Uint8Array(0);
    if (typeof cix.data === 'string' && cix.data.length > 0) {
      try {
        data = decodeBase58(cix.data);
      } catch {
        data = new Uint8Array(0);
      }
    }
    return decodeInstruction(programId, ixAccounts, data, true);
  };

  const out: DecodedIx[] = [];
  for (let i = 0; i < outerCount; i++) {
    const ix = decoded.message.instructions[i];
    if (!ix) continue;
    const programId = keys[ix.programIdIndex] ?? '?';
    const ixAccounts = ix.accountIndexes.map((idx) => keys[idx] ?? '?');
    out.push(decodeInstruction(programId, ixAccounts, ix.data, false));
    const inners = grouped.get(i);
    if (inners) {
      for (const cix of inners) out.push(decodeInner(cix));
    }
  }
  for (const cix of trailing) out.push(decodeInner(cix));
  return out;
}

function inferDecimals(mint: string, instructions: DecodedIx[]): number {
  for (const ix of instructions) {
    if (ix.params.mint === mint && ix.params.decimals !== undefined) {
      const parsed = Number(ix.params.decimals);
      if (Number.isInteger(parsed) && parsed >= 0 && parsed <= 18) return parsed;
    }
  }
  if (mint === WSOL_MINT) return 9;
  if (mint === USDC_MINT || mint === USDT_MINT) return 6;
  return 0;
}

async function resolveUnknownProgramDeploySlots(
  rpc: RpcClient,
  unknownProgramIds: string[],
  knownAccounts: Map<string, AccountState | null>,
  observedSlot: number | undefined,
): Promise<{ deploySlots: Map<string, number>; currentSlot?: number }> {
  const deploySlots = new Map<string, number>();
  let currentSlot = observedSlot;
  if (unknownProgramIds.length === 0) {
    return { deploySlots, ...(currentSlot !== undefined ? { currentSlot } : {}) };
  }

  try {
    const missingProgs = unknownProgramIds.filter((id) => !knownAccounts.has(id));
    if (missingProgs.length > 0) {
      const fetched = await fetchMultipleAccounts(rpc, missingProgs);
      if (currentSlot === undefined && fetched.slot !== undefined) currentSlot = fetched.slot;
      for (const [k, v] of fetched.accounts) knownAccounts.set(k, v);
    }

    const progToData = new Map<string, string>();
    const programDataAddrs: string[] = [];
    for (const progId of unknownProgramIds) {
      const acct = knownAccounts.get(progId) ?? null;
      const directPd = parseProgramData(acct);
      if (directPd) {
        deploySlots.set(progId, Number(directPd.slot));
        continue;
      }
      const pdAddr = parseProgramAccount(acct);
      if (pdAddr) {
        progToData.set(progId, pdAddr);
        if (!knownAccounts.has(pdAddr)) programDataAddrs.push(pdAddr);
      }
    }

    if (programDataAddrs.length > 0) {
      const fetchedPd = await fetchMultipleAccounts(rpc, programDataAddrs);
      if (currentSlot === undefined && fetchedPd.slot !== undefined) currentSlot = fetchedPd.slot;
      for (const [k, v] of fetchedPd.accounts) knownAccounts.set(k, v);
    }

    for (const [progId, pdAddr] of progToData) {
      const pd = parseProgramData(knownAccounts.get(pdAddr) ?? null);
      if (pd) deploySlots.set(progId, Number(pd.slot));
    }

    if (deploySlots.size > 0 && currentSlot === undefined) {
      const slot = await rpc.call<number>('getSlot', [{ commitment: 'processed' }]);
      if (typeof slot === 'number' && Number.isFinite(slot)) currentSlot = slot;
    }
  } catch {
    // Program deployment age lookup is best-effort enrichment; keep whatever resolved.
  }

  return { deploySlots, ...(currentSlot !== undefined ? { currentSlot } : {}) };
}

/**
 * Resolves lookup tables, simulates `txBytes` without signature verification,
 * and computes pre/post balance and authority changes for `wallet`.
 */
export async function simulateAndDiff(
  txBytes: Uint8Array,
  decoded: DecodedTransaction,
  wallet: string,
  rpc: RpcClient,
): Promise<SimulationOutput> {
  // 1. Resolve v0 address lookup tables if present.
  let resolvedKeys: ResolvedKeys;
  let observedSlot: number | undefined;
  if (decoded.message.addressTableLookups.length > 0) {
    const tableAddresses = dedupeAddresses(decoded.message.addressTableLookups.map((l) => l.accountKey));
    const { accounts: tableAccts, slot: lutSlot } = await fetchMultipleAccounts(rpc, tableAddresses);
    if (lutSlot !== undefined) observedSlot = lutSlot;
    const tables = new Map<string, string[]>();
    for (const [tableKey, acct] of tableAccts) {
      if (!acct) continue;
      try {
        tables.set(tableKey, parseLookupTableAddresses(acct.data));
      } catch {
        // Leave unresolved entries as placeholders if table data is malformed.
      }
    }
    resolvedKeys = resolveAccountKeys(decoded.message, tables);
  } else {
    resolvedKeys = resolveAccountKeys(decoded.message);
  }

  // 2. Collect [wallet + writable accounts] and fetch pre-simulation state.
  const writableKeys: string[] = [];
  if (wallet) writableKeys.push(wallet);
  for (let i = 0; i < resolvedKeys.keys.length; i++) {
    const key = resolvedKeys.keys[i];
    if (key && resolvedKeys.writable[i]) writableKeys.push(key);
  }
  const inspectAddresses = dedupeAddresses(writableKeys);
  const { accounts: preMap, slot: preSlot } = await fetchMultipleAccounts(rpc, inspectAddresses);
  if (preSlot !== undefined) observedSlot = preSlot;

  // 3. Simulate the transaction with inner instructions and post-state accounts.
  //    Only include `wallet` in simAddresses if it appears in the transaction's
  //    account keys (avoids Agave -32602 "Too many accounts provided"), and
  //    prioritize wallet, user-owned token accounts, and upgradeable-loader
  //    accounts ahead of generic writable accounts before capping at 100.
  const staticUserTokenAccounts = new Set<string>();
  if (wallet) {
    for (const cix of decoded.message.instructions) {
      const pid = resolvedKeys.keys[cix.programIdIndex] ?? '?';
      const ixAccs = cix.accountIndexes.map((idx) => resolvedKeys.keys[idx] ?? '?');
      const dix = decodeInstruction(pid, ixAccs, cix.data, false);
      if (
        (dix.type === 'ata:create' ||
          dix.type === 'ata:createIdempotent' ||
          dix.type === 'token:initializeAccount' ||
          dix.type === 'token:initializeAccount2' ||
          dix.type === 'token:initializeAccount3') &&
        dix.params.owner === wallet &&
        dix.params.account
      ) {
        staticUserTokenAccounts.add(dix.params.account);
      }
    }
  }

  const simRaw: string[] = [];
  if (wallet && resolvedKeys.keys.includes(wallet)) simRaw.push(wallet);
  for (let i = 0; i < resolvedKeys.keys.length; i++) {
    const key = resolvedKeys.keys[i];
    if (key && resolvedKeys.writable[i]) simRaw.push(key);
  }
  const simDeduped = dedupeAddresses(simRaw);
  const simPriority = (addr: string): number => {
    if (wallet && addr === wallet) return 0;
    const preAcct = preMap.get(addr) ?? null;
    if (wallet && (parseTokenAccount(preAcct)?.owner === wallet || staticUserTokenAccounts.has(addr))) {
      return 1;
    }
    if (preAcct?.owner === BPF_UPGRADEABLE_LOADER_ID) return 2;
    return 3;
  };
  simDeduped.sort((a, b) => simPriority(a) - simPriority(b));

  const simAddresses =
    simDeduped.length > MAX_SIMULATE_ACCOUNTS
      ? simDeduped.slice(0, MAX_SIMULATE_ACCOUNTS)
      : simDeduped;

  const rawSim = await rpc.call<RpcContextValue<RpcSimulationValue> | RpcSimulationValue>('simulateTransaction', [
    encodeBase64(txBytes),
    {
      encoding: 'base64',
      sigVerify: false,
      replaceRecentBlockhash: true,
      commitment: 'processed',
      innerInstructions: true,
      accounts: {
        encoding: 'base64',
        addresses: simAddresses,
      },
    },
  ]);

  const simVal: RpcSimulationValue = 'value' in rawSim && rawSim.value && typeof rawSim.value === 'object' && 'err' in rawSim.value
    ? rawSim.value
    : (rawSim as RpcSimulationValue);
  if ('context' in rawSim && typeof rawSim.context?.slot === 'number') {
    observedSlot = rawSim.context.slot;
  }

  const ok = simVal.err === null || simVal.err === undefined;
  const simulation: SimulationSummary = {
    ok,
    ...(!ok ? { error: formatSimulationError(simVal.err) } : {}),
    ...(typeof simVal.unitsConsumed === 'number' ? { unitsConsumed: simVal.unitsConsumed } : {}),
    ...(Array.isArray(simVal.logs) && simVal.logs.length > 0
      ? { logsTail: simVal.logs.slice(-MAX_LOG_TAIL_LINES) }
      : {}),
  };

  // 4. Decode outer + inner instructions in execution order.
  const instructions = decodeOuterAndInnerInstructions(decoded, resolvedKeys.keys, simVal.innerInstructions);

  const preTokenAccounts = new Map<string, TokenAccountInfo>();
  const postTokenAccounts = new Map<string, TokenAccountInfo>();
  for (const [addr, acct] of preMap) {
    const tok = parseTokenAccount(acct);
    if (tok) preTokenAccounts.set(addr, tok);
  }

  const preWalletAcct = wallet ? (preMap.get(wallet) ?? null) : null;
  const preWalletLamports = wallet && preMap.has(wallet) ? (preWalletAcct?.lamports ?? 0n) : undefined;

  const balanceChanges: BalanceChange[] = [];
  const authorityChanges: AuthorityChange[] = [];
  const mintInfos = new Map<string, MintInfo>();
  const combinedAccounts = new Map<string, AccountState | null>(preMap);

  // 5. Compute pre/post balance and authority diffs when simulation succeeded.
  if (ok && Array.isArray(simVal.accounts)) {
    const postMap = new Map<string, AccountState | null>();
    for (let i = 0; i < simAddresses.length; i++) {
      const addr = simAddresses[i];
      if (!addr) continue;
      const parsed = parseRpcAccount(simVal.accounts[i] ?? null);
      postMap.set(addr, parsed);
      combinedAccounts.set(addr, parsed);
      const tok = parseTokenAccount(parsed);
      if (tok) postTokenAccounts.set(addr, tok);
    }

    if (wallet && postMap.has(wallet)) {
      const postWalletAcct = postMap.get(wallet) ?? null;
      const preLamports = preWalletAcct?.lamports ?? 0n;
      const postLamports = postWalletAcct?.lamports ?? 0n;
      const solDelta = postLamports - preLamports;
      if (solDelta !== 0n) {
        balanceChanges.push({
          asset: 'SOL',
          symbol: 'SOL',
          decimals: 9,
          rawChange: solDelta.toString(),
          uiChange: formatUnits(solDelta, 9),
          owner: wallet,
        });
      }

      const preOwner = preWalletAcct?.owner ?? SYSTEM_PROGRAM_ID;
      if (postWalletAcct && postWalletAcct.owner !== preOwner && postWalletAcct.owner !== SYSTEM_PROGRAM_ID) {
        authorityChanges.push({
          account: wallet,
          kind: 'wallet-owner',
          from: preOwner,
          to: postWalletAcct.owner,
        });
      }
    }

    const mintDeltas = new Map<string, bigint>();
    const mintsToInspect = new Set<string>();

    for (const addr of simAddresses) {
      const preAcct = preMap.get(addr) ?? null;
      const postAcct = postMap.get(addr) ?? null;
      const preTok = preTokenAccounts.get(addr) ?? null;
      const postTok = postTokenAccounts.get(addr) ?? null;

      if (wallet && preTok && preTok.owner === wallet) {
        mintDeltas.set(preTok.mint, (mintDeltas.get(preTok.mint) ?? 0n) - preTok.amount);
        mintsToInspect.add(preTok.mint);
      }
      if (wallet && postTok && postTok.owner === wallet) {
        mintDeltas.set(postTok.mint, (mintDeltas.get(postTok.mint) ?? 0n) + postTok.amount);
        mintsToInspect.add(postTok.mint);
      }

      // Token account owner change
      if (preTok && postTok && preTok.owner !== postTok.owner) {
        mintsToInspect.add(preTok.mint);
        mintsToInspect.add(postTok.mint);
        authorityChanges.push({
          account: addr,
          kind: 'token-account-owner',
          from: preTok.owner,
          to: postTok.owner,
        });
      }

      // Close authority and delegate diffs on the user's token accounts
      const touchesWallet = Boolean(wallet) && (preTok?.owner === wallet || postTok?.owner === wallet);
      if (touchesWallet && postTok) {
        mintsToInspect.add(postTok.mint);
        const preClose = preTok?.closeAuthority ?? null;
        const postClose = postTok.closeAuthority ?? null;
        if (preClose !== postClose) {
          authorityChanges.push({
            account: addr,
            kind: 'close-authority',
            ...(preClose ? { from: preClose } : {}),
            to: postClose ?? 'none',
          });
        }

        const preDel = preTok?.delegate ?? null;
        const postDel = postTok.delegate ?? null;
        const isZeroAllowanceNoop = preDel === null && postDel !== null && postTok.delegatedAmount === 0n;
        const delAmountIncreased = postDel !== null && postTok.delegatedAmount > (preTok?.delegatedAmount ?? 0n);
        if (!isZeroAllowanceNoop && (preDel !== postDel || delAmountIncreased)) {
          authorityChanges.push({
            account: addr,
            kind: 'delegate',
            ...(preDel ? { from: preDel } : {}),
            to: postTok.delegatedAmount === 0n ? 'none' : (postDel ?? 'none'),
          });
        }
      }

      // Upgradeable program authority diff
      const prePd = parseProgramData(preAcct);
      const postPd = parseProgramData(postAcct);
      if (prePd && postPd && prePd.upgradeAuthority !== postPd.upgradeAuthority) {
        authorityChanges.push({
          account: addr,
          kind: 'upgrade-authority',
          ...(prePd.upgradeAuthority ? { from: prePd.upgradeAuthority } : {}),
          to: postPd.upgradeAuthority ?? 'none (immutable)',
        });
      }
    }

    // Also include mints from newly created ATAs and explicit token approval/transfer instructions so decimals/symbols/extensions resolve.
    for (const ix of instructions) {
      if ((ix.type === 'ata:create' || ix.type === 'ata:createIdempotent') && ix.params.owner === wallet && ix.params.mint) {
        mintsToInspect.add(ix.params.mint);
      } else if (
        (ix.type === 'token:approveChecked' ||
          ix.type === 'token:transferChecked' ||
          ix.type === 'token:transferCheckedWithFee') &&
        ix.params.mint
      ) {
        mintsToInspect.add(ix.params.mint);
      } else if (ix.type === 'token:approve' || ix.type === 'token:setAuthority' || ix.type === 'token:closeAccount') {
        const targetAcct = ix.params.source ?? ix.params.account;
        const knownTok = targetAcct ? (postTokenAccounts.get(targetAcct) ?? preTokenAccounts.get(targetAcct)) : undefined;
        if (knownTok?.mint) mintsToInspect.add(knownTok.mint);
      }
    }

    const missingMints = [...mintsToInspect].filter((m) => !isPlaceholder(m) && !combinedAccounts.has(m));
    if (missingMints.length > 0) {
      try {
        const fetchedMints = await fetchMultipleAccounts(rpc, missingMints);
        if (observedSlot === undefined && fetchedMints.slot !== undefined) observedSlot = fetchedMints.slot;
        for (const [k, v] of fetchedMints.accounts) combinedAccounts.set(k, v);
      } catch {
        // Fall back to instruction/well-known mint decimals if mint lookup fails.
      }
    }

    for (const mint of mintsToInspect) {
      const info = parseMint(combinedAccounts.get(mint) ?? null);
      if (info) mintInfos.set(mint, info);
    }

    for (const [mint, delta] of mintDeltas) {
      if (delta === 0n) continue;
      const info = mintInfos.get(mint);
      const decimals = info?.decimals ?? inferDecimals(mint, instructions);
      const symbol = info?.symbol ?? (Object.hasOwn(WELL_KNOWN_MINTS, mint) ? WELL_KNOWN_MINTS[mint]?.symbol : undefined);
      balanceChanges.push({
        asset: mint,
        ...(symbol ? { symbol } : {}),
        decimals,
        rawChange: delta.toString(),
        uiChange: formatUnits(delta, decimals),
        owner: wallet,
      });
    }
  }

  // 6. Inspect deployment slot for unknown programs invoked in outer or inner instructions.
  const unknownProgramIds = dedupeAddresses(
    instructions.map((ix) => ix.programId).filter((pid) => pid !== '?' && !isKnownProgram(pid)),
  );
  const { deploySlots: programDeploySlots, currentSlot } = await resolveUnknownProgramDeploySlots(
    rpc,
    unknownProgramIds,
    combinedAccounts,
    observedSlot,
  );

  return {
    resolvedKeys,
    instructions,
    simulation,
    balanceChanges,
    authorityChanges,
    ...(preWalletLamports !== undefined ? { preWalletLamports } : {}),
    preTokenAccounts,
    postTokenAccounts,
    mintInfos,
    programDeploySlots,
    ...(currentSlot !== undefined ? { currentSlot } : {}),
  };
}
