/**
 * wire.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Minimal decoder for the Solana transaction wire format (legacy,
 *           v0, and SIMD-0385 v1): signatures, message header, transaction
 *           config, static account keys, recent blockhash / nonce value,
 *           compiled instructions and address lookup table references. Also
 *           resolves lookup tables once their addresses are known.
 *
 * ACCESS:   Pure functions over the serialized transaction bytes the dapp
 *           asked the wallet to sign.
 *
 * NEVER:    - No network. No storage. No logging.
 *           - Never signs, modifies or re-serializes the transaction.
 *           - Does not depend on @solana/web3.js (kept out of the bundle).
 * ---------------------------------------------------------------------------
 */

import { ByteReader, DecodeError, encodeBase58, isAllZero } from './bytes';

export interface CompiledInstruction {
  programIdIndex: number;
  accountIndexes: number[];
  data: Uint8Array;
}

export interface LookupTableRef {
  accountKey: string;
  writableIndexes: number[];
  readonlyIndexes: number[];
}

export interface MessageHeader {
  numRequiredSignatures: number;
  numReadonlySignedAccounts: number;
  numReadonlyUnsignedAccounts: number;
}

export interface V1TransactionConfig {
  priorityFeeLamports?: bigint;
  computeUnitLimit?: number;
  loadedAccountsDataSizeLimit?: number;
  heapSize?: number;
}

export interface DecodedMessage {
  version: 'legacy' | 0 | 1;
  header: MessageHeader;
  staticAccountKeys: string[];
  recentBlockhash: string;
  instructions: CompiledInstruction[];
  addressTableLookups: LookupTableRef[];
  transactionConfig?: V1TransactionConfig;
}

export interface DecodedTransaction {
  /** base58 signatures; `null` for an empty (all-zero) signature slot. */
  signatures: (string | null)[];
  message: DecodedMessage;
  /** The raw message bytes (what signers sign). */
  messageBytes: Uint8Array;
}

/** All account keys in final order, with writability/signer flags. */
export interface ResolvedKeys {
  keys: string[];
  writable: boolean[];
  signer: boolean[];
  /** True when lookup-table addresses were resolved (or there were none). */
  complete: boolean;
}

const MAX_KEYS = 256;
const MAX_V1_BYTES = 4096;
const MAX_V1_KEYS = 64;
const MAX_V1_INSTRUCTIONS = 64;
const MAX_V1_SIGNERS = 12;

function readLegacyOrV0Message(r: ByteReader): DecodedMessage {
  const first = r.u8();
  let version: 'legacy' | 0 = 'legacy';
  let numRequiredSignatures: number;
  if (first & 0x80) {
    const v = first & 0x7f;
    if (v !== 0) throw new DecodeError(`unsupported transaction version ${v}`);
    version = 0;
    numRequiredSignatures = r.u8();
  } else {
    numRequiredSignatures = first;
  }
  const header: MessageHeader = {
    numRequiredSignatures,
    numReadonlySignedAccounts: r.u8(),
    numReadonlyUnsignedAccounts: r.u8(),
  };

  const numKeys = r.compactU16();
  if (numKeys === 0 || numKeys > MAX_KEYS) throw new DecodeError(`bad account key count ${numKeys}`);
  if (header.numRequiredSignatures === 0 || header.numRequiredSignatures > numKeys) {
    throw new DecodeError('bad signer count');
  }
  if (header.numReadonlySignedAccounts >= header.numRequiredSignatures) {
    throw new DecodeError('fee payer must be writable');
  }
  if (header.numReadonlyUnsignedAccounts > numKeys - header.numRequiredSignatures) {
    throw new DecodeError('bad readonly unsigned count');
  }
  const staticAccountKeys: string[] = [];
  for (let i = 0; i < numKeys; i++) staticAccountKeys.push(r.pubkey());
  const recentBlockhash = r.pubkey();

  const numIx = r.compactU16();
  const instructions: CompiledInstruction[] = [];
  for (let i = 0; i < numIx; i++) {
    const programIdIndex = r.u8();
    const nAcc = r.compactU16();
    const accountIndexes: number[] = [];
    for (let j = 0; j < nAcc; j++) accountIndexes.push(r.u8());
    const dataLen = r.compactU16();
    const data = r.take(dataLen).slice();
    instructions.push({ programIdIndex, accountIndexes, data });
  }

  const addressTableLookups: LookupTableRef[] = [];
  if (version === 0) {
    const nLookups = r.compactU16();
    for (let i = 0; i < nLookups; i++) {
      const accountKey = r.pubkey();
      const nW = r.compactU16();
      const writableIndexes: number[] = [];
      for (let j = 0; j < nW; j++) writableIndexes.push(r.u8());
      const nR = r.compactU16();
      const readonlyIndexes: number[] = [];
      for (let j = 0; j < nR; j++) readonlyIndexes.push(r.u8());
      addressTableLookups.push({ accountKey, writableIndexes, readonlyIndexes });
    }
  }

  const totalKeys =
    numKeys + addressTableLookups.reduce((n, l) => n + l.writableIndexes.length + l.readonlyIndexes.length, 0);
  if (totalKeys > MAX_KEYS) throw new DecodeError('too many account keys');
  for (const ix of instructions) {
    if (ix.programIdIndex >= numKeys) throw new DecodeError('program id must be a static key');
    for (const a of ix.accountIndexes) if (a >= totalKeys) throw new DecodeError('account index out of range');
  }

  return { version, header, staticAccountKeys, recentBlockhash, instructions, addressTableLookups };
}

/**
 * SIMD-0385 Transaction v1 message layout:
 *   0x81 | header(3B) | configMask(u32LE) | recentBlockhash(32B) |
 *   numIx(u8) | numAddresses(u8) | addresses(32B * numAddresses) |
 *   configValues(4B * popcount(configMask)) |
 *   ixHeaders((u8, u8, u16LE) * numIx) | ixPayloads((accounts + data) * numIx)
 */
function readV1Message(r: ByteReader): DecodedMessage {
  const versionByte = r.u8();
  if (versionByte !== 0x81) {
    throw new DecodeError(`expected v1 prefix 0x81, got 0x${versionByte.toString(16)}`);
  }
  const header: MessageHeader = {
    numRequiredSignatures: r.u8(),
    numReadonlySignedAccounts: r.u8(),
    numReadonlyUnsignedAccounts: r.u8(),
  };

  const configMask = r.u32();
  if ((configMask & ~0x1f) !== 0) {
    throw new DecodeError(`unsupported v1 config mask 0x${configMask.toString(16)}`);
  }
  const prioBits = configMask & 0x03;
  if (prioBits !== 0 && prioBits !== 0x03) {
    throw new DecodeError('invalid v1 priority fee config mask');
  }

  const recentBlockhash = r.pubkey();
  const numIx = r.u8();
  if (numIx > MAX_V1_INSTRUCTIONS) throw new DecodeError(`bad v1 instruction count ${numIx}`);
  const numKeys = r.u8();
  if (numKeys === 0 || numKeys > MAX_V1_KEYS) throw new DecodeError(`bad account key count ${numKeys}`);
  if (
    header.numRequiredSignatures === 0 ||
    header.numRequiredSignatures > MAX_V1_SIGNERS ||
    header.numRequiredSignatures > numKeys
  ) {
    throw new DecodeError('bad signer count');
  }
  if (header.numReadonlySignedAccounts >= header.numRequiredSignatures) {
    throw new DecodeError('fee payer must be writable');
  }
  if (header.numReadonlyUnsignedAccounts > numKeys - header.numRequiredSignatures) {
    throw new DecodeError('bad readonly unsigned count');
  }

  const staticAccountKeys: string[] = [];
  const seenKeys = new Set<string>();
  for (let i = 0; i < numKeys; i++) {
    const pk = r.pubkey();
    if (seenKeys.has(pk)) throw new DecodeError('duplicate account key in v1 message');
    seenKeys.add(pk);
    staticAccountKeys.push(pk);
  }

  const transactionConfig: V1TransactionConfig = {};
  if (prioBits === 0x03) {
    transactionConfig.priorityFeeLamports = r.u64();
  }
  if (configMask & 0x04) {
    transactionConfig.computeUnitLimit = r.u32();
  }
  if (configMask & 0x08) {
    transactionConfig.loadedAccountsDataSizeLimit = r.u32();
  }
  if (configMask & 0x10) {
    const heapSize = r.u32();
    if (heapSize < 32_768 || heapSize > 262_144 || heapSize % 1024 !== 0) {
      throw new DecodeError(`invalid v1 heap size ${heapSize}`);
    }
    transactionConfig.heapSize = heapSize;
  }

  const ixHeaders: Array<{ programIdIndex: number; nAcc: number; dataLen: number }> = [];
  for (let i = 0; i < numIx; i++) {
    const programIdIndex = r.u8();
    const nAcc = r.u8();
    const dataLen = r.u16();
    if (programIdIndex >= numKeys) throw new DecodeError('program id must be a static key');
    ixHeaders.push({ programIdIndex, nAcc, dataLen });
  }

  const instructions: CompiledInstruction[] = [];
  for (let i = 0; i < numIx; i++) {
    const h = ixHeaders[i]!;
    const accountIndexes: number[] = [];
    for (let j = 0; j < h.nAcc; j++) {
      const idx = r.u8();
      if (idx >= numKeys) throw new DecodeError('account index out of range');
      accountIndexes.push(idx);
    }
    const data = r.take(h.dataLen).slice();
    instructions.push({ programIdIndex: h.programIdIndex, accountIndexes, data });
  }

  return {
    version: 1,
    header,
    staticAccountKeys,
    recentBlockhash,
    instructions,
    addressTableLookups: [],
    transactionConfig,
  };
}

/** Decode a bare message (no signature section). Throws DecodeError on malformed input. */
export function decodeMessage(bytes: Uint8Array, requireExact = true): DecodedMessage {
  const r = new ByteReader(bytes);
  if (r.remaining === 0) throw new DecodeError('unexpected end of data');
  const msg = bytes[0] === 0x81 ? readV1Message(r) : readLegacyOrV0Message(r);
  if (requireExact && r.remaining !== 0) throw new DecodeError(`${r.remaining} trailing bytes`);
  return msg;
}

/** Decode a full serialized transaction. Throws DecodeError on malformed input. */
export function decodeTransaction(bytes: Uint8Array): DecodedTransaction {
  const r = new ByteReader(bytes);
  if (r.remaining === 0) throw new DecodeError('unexpected end of data');

  // SIMD-0385 v1 envelope: 0x81 message prefix at byte 0, trailing 64-byte signatures.
  if (bytes[0] === 0x81) {
    if (bytes.length > MAX_V1_BYTES) throw new DecodeError(`v1 transaction exceeds ${MAX_V1_BYTES} bytes`);
    const message = readV1Message(r);
    const msgEnd = r.offset;
    const signatures: (string | null)[] = [];
    for (let i = 0; i < message.header.numRequiredSignatures; i++) {
      const sig = r.take(64);
      signatures.push(isAllZero(sig) ? null : encodeBase58(sig));
    }
    if (r.remaining !== 0) throw new DecodeError(`${r.remaining} trailing bytes`);
    return { signatures, message, messageBytes: bytes.subarray(0, msgEnd) };
  }

  const nSigs = r.compactU16();
  const signatures: (string | null)[] = [];
  for (let i = 0; i < nSigs; i++) {
    const sig = r.take(64);
    signatures.push(isAllZero(sig) ? null : encodeBase58(sig));
  }
  const msgStart = r.offset;
  const message = readLegacyOrV0Message(r);
  if (r.remaining !== 0) throw new DecodeError(`${r.remaining} trailing bytes`);
  if (nSigs !== message.header.numRequiredSignatures) {
    throw new DecodeError(`signature count ${nSigs} != required ${message.header.numRequiredSignatures}`);
  }
  return { signatures, message, messageBytes: bytes.subarray(msgStart) };
}

/** Parse address lookup table account data: 56-byte header + 32-byte addresses. */
export function parseLookupTableAddresses(data: Uint8Array): string[] {
  const HEADER = 56;
  if (data.length < HEADER || (data.length - HEADER) % 32 !== 0) {
    throw new DecodeError('bad lookup table account data');
  }
  const out: string[] = [];
  for (let o = HEADER; o < data.length; o += 32) out.push(encodeBase58(data.subarray(o, o + 32)));
  return out;
}

/** Placeholder used for lookup-table addresses that could not be resolved. */
export function lookupPlaceholder(table: string, index: number): string {
  return `lookup:${table.slice(0, 4)}…${table.slice(-4)}#${index}`;
}

export function isPlaceholder(key: string): boolean {
  return key.startsWith('lookup:');
}

/**
 * Builds the final account key list: static keys, then writable lookups (all
 * tables in order), then readonly lookups. `tables` maps table address to its
 * addresses; missing tables produce placeholders and `complete: false`.
 */
export function resolveAccountKeys(msg: DecodedMessage, tables?: Map<string, string[]>): ResolvedKeys {
  const { header, staticAccountKeys } = msg;
  const n = staticAccountKeys.length;
  const keys = [...staticAccountKeys];
  const writable: boolean[] = [];
  const signer: boolean[] = [];
  for (let i = 0; i < n; i++) {
    const isSigner = i < header.numRequiredSignatures;
    signer.push(isSigner);
    writable.push(
      isSigner
        ? i < header.numRequiredSignatures - header.numReadonlySignedAccounts
        : i < n - header.numReadonlyUnsignedAccounts,
    );
  }

  let complete = true;
  const pick = (table: string, idx: number): string => {
    const addrs = tables?.get(table);
    const a = addrs?.[idx];
    if (a === undefined) {
      complete = false;
      return lookupPlaceholder(table, idx);
    }
    return a;
  };
  for (const l of msg.addressTableLookups) {
    for (const idx of l.writableIndexes) {
      keys.push(pick(l.accountKey, idx));
      writable.push(true);
      signer.push(false);
    }
  }
  for (const l of msg.addressTableLookups) {
    for (const idx of l.readonlyIndexes) {
      keys.push(pick(l.accountKey, idx));
      writable.push(false);
      signer.push(false);
    }
  }
  return { keys, writable, signer, complete };
}
