/**
 * accounts.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Parsers for on-chain account data the preview engine reads from
 *           public RPC: SPL token accounts (165-byte layout), mints (82-byte
 *           layout + Token-2022 TLV extensions), and upgradeable-loader
 *           program / program-data accounts.
 *
 * ACCESS:   Pure functions over account bytes returned by RPC.
 *
 * NEVER:    - No network. No storage. No logging.
 *           - Never throws on malformed data: parsers return null instead.
 * ---------------------------------------------------------------------------
 */

import { BPF_UPGRADEABLE_LOADER_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from '../../shared/known-programs';
import { ByteReader, decodeBase64, isAllZero, readPubkey, readU16LE, readU32LE, readU64LE } from './bytes';

/** Account as returned by getMultipleAccounts / simulateTransaction (base64 encoding). */
export interface RpcAccount {
  lamports: number;
  owner: string;
  data: [string, string] | string;
  executable?: boolean;
  rentEpoch?: number;
  space?: number;
}

export interface AccountState {
  lamports: bigint;
  owner: string;
  data: Uint8Array;
  executable: boolean;
}

export function parseRpcAccount(a: RpcAccount | null | undefined): AccountState | null {
  if (!a || typeof a !== 'object') return null;
  let data: Uint8Array = new Uint8Array(0);
  try {
    const raw = Array.isArray(a.data) ? a.data[0] : a.data;
    const enc = Array.isArray(a.data) ? a.data[1] : 'base64';
    if (typeof raw === 'string' && raw.length > 0 && enc === 'base64') data = decodeBase64(raw);
  } catch {
    data = new Uint8Array(0);
  }
  const rawLamports = Number(a.lamports);
  const lamports = Number.isFinite(rawLamports) && rawLamports > 0 ? BigInt(Math.trunc(rawLamports)) : 0n;
  return {
    lamports,
    owner: String(a.owner),
    data,
    executable: Boolean(a.executable),
  };
}

export const TOKEN_ACCOUNT_SIZE = 165;
export const MINT_SIZE = 82;
const ACCOUNT_TYPE_MINT = 1;
const ACCOUNT_TYPE_ACCOUNT = 2;

export interface TokenAccountInfo {
  mint: string;
  owner: string;
  amount: bigint;
  lamports: bigint;
  delegate: string | null;
  delegatedAmount: bigint;
  state: number;
  isNative: boolean;
  closeAuthority: string | null;
  programId: string;
}

function isTokenProgram(owner: string): boolean {
  return owner === TOKEN_PROGRAM_ID || owner === TOKEN_2022_PROGRAM_ID;
}

/** Parse an SPL token account (Token or Token-2022). Returns null if `acct` is not one. */
export function parseTokenAccount(acct: AccountState | null): TokenAccountInfo | null {
  if (!acct || !isTokenProgram(acct.owner)) return null;
  const d = acct.data;
  if (d.length < TOKEN_ACCOUNT_SIZE) return null;
  if (d.length > TOKEN_ACCOUNT_SIZE && d[TOKEN_ACCOUNT_SIZE] !== ACCOUNT_TYPE_ACCOUNT) return null;
  try {
    const state = d[108] ?? 0;
    if (state === 0) return null; // uninitialized
    const delegateTag = readU32LE(d, 72);
    const nativeTag = readU32LE(d, 109);
    const closeTag = readU32LE(d, 129);
    return {
      mint: readPubkey(d, 0),
      owner: readPubkey(d, 32),
      amount: readU64LE(d, 64),
      lamports: acct.lamports,
      delegate: delegateTag === 1 ? readPubkey(d, 76) : null,
      state,
      isNative: nativeTag === 1,
      delegatedAmount: readU64LE(d, 121),
      closeAuthority: closeTag === 1 ? readPubkey(d, 133) : null,
      programId: acct.owner,
    };
  } catch {
    return null;
  }
}

export interface MintInfo {
  decimals: number;
  supply: bigint;
  mintAuthority: string | null;
  freezeAuthority: string | null;
  programId: string;
  /** Token-2022 extensions (only the ones the rules care about). */
  permanentDelegate?: string;
  transferHookProgram?: string;
  transferFeeBps?: number;
  transferFeeMax?: bigint;
  symbol?: string;
  name?: string;
}

/** Token-2022 extension type ids. */
const EXT_TRANSFER_FEE_CONFIG = 1;
const EXT_PERMANENT_DELEGATE = 12;
const EXT_TRANSFER_HOOK = 14;
const EXT_TOKEN_METADATA = 19;

/** Parse a mint account (Token or Token-2022, including TLV extensions). */
export function parseMint(acct: AccountState | null): MintInfo | null {
  if (!acct || !isTokenProgram(acct.owner)) return null;
  const d = acct.data;
  if (d.length < MINT_SIZE) return null;
  if (d.length > MINT_SIZE && d.length <= TOKEN_ACCOUNT_SIZE) return null;
  if (d.length > TOKEN_ACCOUNT_SIZE && d[TOKEN_ACCOUNT_SIZE] !== ACCOUNT_TYPE_MINT) return null;
  try {
    if (d[45] !== 1) return null; // not initialized
    const info: MintInfo = {
      mintAuthority: readU32LE(d, 0) === 1 ? readPubkey(d, 4) : null,
      supply: readU64LE(d, 36),
      decimals: d[44] ?? 0,
      freezeAuthority: readU32LE(d, 46) === 1 ? readPubkey(d, 50) : null,
      programId: acct.owner,
    };
    if (acct.owner === TOKEN_2022_PROGRAM_ID && d.length > TOKEN_ACCOUNT_SIZE + 1) {
      readMintExtensions(d, info);
    }
    return info;
  } catch {
    return null;
  }
}

function readMintExtensions(d: Uint8Array, info: MintInfo): void {
  let o = TOKEN_ACCOUNT_SIZE + 1;
  while (o + 4 <= d.length) {
    const type = readU16LE(d, o);
    const len = readU16LE(d, o + 2);
    const start = o + 4;
    const end = start + len;
    if (end > d.length) break;
    if (type === 0 && len === 0) break; // uninitialized padding
    const v = d.subarray(start, end);
    try {
      switch (type) {
        case EXT_PERMANENT_DELEGATE:
          if (v.length >= 32 && !isAllZero(v.subarray(0, 32))) info.permanentDelegate = readPubkey(v, 0);
          break;
        case EXT_TRANSFER_HOOK:
          // authority (32) + program id (32); a zero program id means "no hook".
          if (v.length >= 64 && !isAllZero(v.subarray(32, 64))) info.transferHookProgram = readPubkey(v, 32);
          break;
        case EXT_TRANSFER_FEE_CONFIG: {
          // config authority(32) withdraw authority(32) withheld(u64)
          // older {epoch u64, max u64, bps u16} newer {epoch u64, max u64, bps u16}
          if (v.length >= 108) {
            const olderMax = readU64LE(v, 80);
            const olderBps = readU16LE(v, 88);
            const newerMax = readU64LE(v, 98);
            const newerBps = readU16LE(v, 106);
            const bps = Math.max(olderBps, newerBps);
            if (bps > 0) {
              info.transferFeeBps = bps;
              info.transferFeeMax = olderMax > newerMax ? olderMax : newerMax;
            }
          }
          break;
        }
        case EXT_TOKEN_METADATA: {
          // update authority(32) mint(32) name(str) symbol(str) uri(str) ...
          const r = new ByteReader(v, 64);
          info.name = r.borshString().slice(0, 64);
          info.symbol = r.borshString().slice(0, 16);
          break;
        }
      }
    } catch {
      // ignore a malformed extension; keep what was parsed so far
    }
    o = end;
  }
}

/** Upgradeable loader: Program account → its ProgramData address. */
export function parseProgramAccount(acct: AccountState | null): string | null {
  if (!acct || acct.owner !== BPF_UPGRADEABLE_LOADER_ID || acct.data.length < 36) return null;
  try {
    return readU32LE(acct.data, 0) === 2 ? readPubkey(acct.data, 4) : null;
  } catch {
    return null;
  }
}

/** Upgradeable loader: ProgramData account → last deploy slot + upgrade authority. */
export function parseProgramData(acct: AccountState | null): { slot: bigint; upgradeAuthority: string | null } | null {
  if (!acct || acct.owner !== BPF_UPGRADEABLE_LOADER_ID || acct.data.length < 13) return null;
  try {
    if (readU32LE(acct.data, 0) !== 3) return null;
    const slot = readU64LE(acct.data, 4);
    const hasAuth = acct.data[12] === 1 && acct.data.length >= 45;
    return { slot, upgradeAuthority: hasAuth ? readPubkey(acct.data, 13) : null };
  } catch {
    return null;
  }
}
