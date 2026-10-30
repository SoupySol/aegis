/**
 * helpers.ts
 * Shared test builders for transactions, on-chain account layouts, and a
 * deterministic fake RpcClient. Uses throwaway random keys only.
 */
import { Keypair, PublicKey, TransactionInstruction } from '@solana/web3.js';
import type { RpcClient } from '../../../src/shared/analysis-types';
import type { RpcAccount } from '../../../src/background/analysis/accounts';
import { decodeBase58, encodeBase58, encodeBase64 } from '../../../src/background/analysis/bytes';
import {
  BPF_UPGRADEABLE_LOADER_ID,
  SYSTEM_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
} from '../../../src/shared/known-programs';

export const BLOCKHASH = encodeBase58(new Uint8Array(32).fill(7));

export function randomPubkey(): PublicKey {
  return Keypair.generate().publicKey;
}

type IxData = NonNullable<ConstructorParameters<typeof TransactionInstruction>[0]>['data'];

export function ixData(bytes: ArrayLike<number>): IxData {
  const B = (globalThis as unknown as { Buffer?: { from(b: ArrayLike<number>): IxData } }).Buffer;
  return B ? B.from(bytes) : (Uint8Array.from(bytes) as unknown as IxData);
}

export function writeU16LE(buf: Uint8Array, offset: number, val: number): void {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setUint16(offset, val, true);
}

export function writeU32LE(buf: Uint8Array, offset: number, val: number): void {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setUint32(offset, val, true);
}

export function writeU64LE(buf: Uint8Array, offset: number, val: bigint): void {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setBigUint64(offset, val, true);
}

export function makeSystemRpcAccount(lamports: bigint, owner = SYSTEM_PROGRAM_ID): RpcAccount {
  return {
    lamports: Number(lamports),
    owner,
    data: ['', 'base64'],
    executable: false,
  };
}

export interface TokenAccountFixtureOpts {
  mint: string;
  owner: string;
  amount: bigint;
  delegate?: string | null;
  delegatedAmount?: bigint;
  isNative?: boolean;
  closeAuthority?: string | null;
  programId?: string;
  lamports?: number;
}

export function makeTokenRpcAccount(opts: TokenAccountFixtureOpts): RpcAccount {
  const buf = new Uint8Array(165);
  buf.set(decodeBase58(opts.mint), 0);
  buf.set(decodeBase58(opts.owner), 32);
  writeU64LE(buf, 64, opts.amount);
  if (opts.delegate) {
    writeU32LE(buf, 72, 1);
    buf.set(decodeBase58(opts.delegate), 76);
  }
  buf[108] = 1; // initialized
  if (opts.isNative) {
    writeU32LE(buf, 109, 1);
    writeU64LE(buf, 113, opts.amount);
  }
  writeU64LE(buf, 121, opts.delegatedAmount ?? 0n);
  if (opts.closeAuthority) {
    writeU32LE(buf, 129, 1);
    buf.set(decodeBase58(opts.closeAuthority), 133);
  }
  return {
    lamports: opts.lamports ?? 2_039_280,
    owner: opts.programId ?? TOKEN_PROGRAM_ID,
    data: [encodeBase64(buf), 'base64'],
    executable: false,
  };
}

export interface MintFixtureOpts {
  decimals: number;
  supply?: bigint;
  mintAuthority?: string | null;
  freezeAuthority?: string | null;
  programId?: string;
  permanentDelegate?: string;
  transferHookProgram?: string;
  transferFeeBps?: number;
  transferFeeMax?: bigint;
  symbol?: string;
  name?: string;
  mintAddressForMetadata?: string;
}

function encodeBorshString(s: string): Uint8Array {
  const utf8 = new TextEncoder().encode(s);
  const out = new Uint8Array(4 + utf8.length);
  writeU32LE(out, 0, utf8.length);
  out.set(utf8, 4);
  return out;
}

function makeTlv(type: number, value: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + value.length);
  writeU16LE(out, 0, type);
  writeU16LE(out, 2, value.length);
  out.set(value, 4);
  return out;
}

export function makeMintRpcAccount(opts: MintFixtureOpts): RpcAccount {
  const hasTlv =
    Boolean(opts.permanentDelegate) ||
    Boolean(opts.transferHookProgram) ||
    (opts.transferFeeBps !== undefined && opts.transferFeeBps > 0) ||
    Boolean(opts.symbol) ||
    Boolean(opts.name);

  const programId = opts.programId ?? (hasTlv ? TOKEN_2022_PROGRAM_ID : TOKEN_PROGRAM_ID);
  const tlvs: Uint8Array[] = [];

  if (opts.permanentDelegate) {
    tlvs.push(makeTlv(12, decodeBase58(opts.permanentDelegate)));
  }
  if (opts.transferHookProgram) {
    const v = new Uint8Array(64);
    v.set(decodeBase58(opts.transferHookProgram), 32);
    tlvs.push(makeTlv(14, v));
  }
  if (opts.transferFeeBps !== undefined) {
    const v = new Uint8Array(108);
    writeU64LE(v, 80, opts.transferFeeMax ?? 1_000_000_000n);
    writeU16LE(v, 88, opts.transferFeeBps);
    writeU64LE(v, 98, opts.transferFeeMax ?? 1_000_000_000n);
    writeU16LE(v, 106, opts.transferFeeBps);
    tlvs.push(makeTlv(1, v));
  }
  if (opts.symbol || opts.name) {
    const nameBytes = encodeBorshString(opts.name ?? 'Token');
    const symBytes = encodeBorshString(opts.symbol ?? 'TKN');
    const uriBytes = encodeBorshString('');
    const v = new Uint8Array(64 + nameBytes.length + symBytes.length + uriBytes.length);
    if (opts.mintAddressForMetadata) v.set(decodeBase58(opts.mintAddressForMetadata), 32);
    let o = 64;
    v.set(nameBytes, o);
    o += nameBytes.length;
    v.set(symBytes, o);
    o += symBytes.length;
    v.set(uriBytes, o);
    tlvs.push(makeTlv(19, v));
  }

  const tlvLen = tlvs.reduce((acc, b) => acc + b.length, 0);
  const buf = new Uint8Array(hasTlv ? 166 + tlvLen : 82);
  if (opts.mintAuthority) {
    writeU32LE(buf, 0, 1);
    buf.set(decodeBase58(opts.mintAuthority), 4);
  }
  writeU64LE(buf, 36, opts.supply ?? 1_000_000_000n);
  buf[44] = opts.decimals;
  buf[45] = 1; // initialized
  if (opts.freezeAuthority) {
    writeU32LE(buf, 46, 1);
    buf.set(decodeBase58(opts.freezeAuthority), 50);
  }
  if (hasTlv) {
    buf[165] = 1; // ACCOUNT_TYPE_MINT
    let offset = 166;
    for (const chunk of tlvs) {
      buf.set(chunk, offset);
      offset += chunk.length;
    }
  }

  return {
    lamports: 1_461_600,
    owner: programId,
    data: [encodeBase64(buf), 'base64'],
    executable: false,
  };
}

export function makeLookupTableRpcAccount(addresses: string[]): RpcAccount {
  const buf = new Uint8Array(56 + addresses.length * 32);
  writeU32LE(buf, 0, 1); // LookupTable discriminator
  addresses.forEach((addr, idx) => {
    buf.set(decodeBase58(addr), 56 + idx * 32);
  });
  return {
    lamports: 2_500_000,
    owner: 'AddressLookupTab1e1111111111111111111111111',
    data: [encodeBase64(buf), 'base64'],
    executable: false,
  };
}

export function makeUpgradeableProgramAccounts(
  programDataAddress: string,
  deploySlot: bigint,
  upgradeAuthority: string | null = null,
): { program: RpcAccount; programData: RpcAccount } {
  const progBuf = new Uint8Array(36);
  writeU32LE(progBuf, 0, 2);
  progBuf.set(decodeBase58(programDataAddress), 4);

  const pdBuf = new Uint8Array(45);
  writeU32LE(pdBuf, 0, 3);
  writeU64LE(pdBuf, 4, deploySlot);
  if (upgradeAuthority) {
    pdBuf[12] = 1;
    pdBuf.set(decodeBase58(upgradeAuthority), 13);
  }

  return {
    program: {
      lamports: 1_141_440,
      owner: BPF_UPGRADEABLE_LOADER_ID,
      data: [encodeBase64(progBuf), 'base64'],
      executable: true,
    },
    programData: {
      lamports: 50_000_000,
      owner: BPF_UPGRADEABLE_LOADER_ID,
      data: [encodeBase64(pdBuf), 'base64'],
      executable: false,
    },
  };
}

/** SPL Token instruction builders (so tests don't need @solana/spl-token). */
export function ixTokenTransfer(source: PublicKey, dest: PublicKey, authority: PublicKey, amount: bigint, programId = TOKEN_PROGRAM_ID): TransactionInstruction {
  const data = new Uint8Array(9);
  data[0] = 3;
  writeU64LE(data, 1, amount);
  return new TransactionInstruction({
    programId: new PublicKey(programId),
    keys: [
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: dest, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
    data: ixData(data),
  });
}

export function ixTokenTransferChecked(
  source: PublicKey,
  mint: PublicKey,
  dest: PublicKey,
  authority: PublicKey,
  amount: bigint,
  decimals: number,
  programId = TOKEN_PROGRAM_ID,
): TransactionInstruction {
  const data = new Uint8Array(10);
  data[0] = 12;
  writeU64LE(data, 1, amount);
  data[9] = decimals;
  return new TransactionInstruction({
    programId: new PublicKey(programId),
    keys: [
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: dest, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
    data: ixData(data),
  });
}

export function ixTokenApprove(
  source: PublicKey,
  delegate: PublicKey,
  owner: PublicKey,
  amount: bigint,
  programId = TOKEN_PROGRAM_ID,
): TransactionInstruction {
  const data = new Uint8Array(9);
  data[0] = 4;
  writeU64LE(data, 1, amount);
  return new TransactionInstruction({
    programId: new PublicKey(programId),
    keys: [
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: delegate, isSigner: false, isWritable: false },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
    data: ixData(data),
  });
}

export function ixTokenRevoke(source: PublicKey, owner: PublicKey, programId = TOKEN_PROGRAM_ID): TransactionInstruction {
  return new TransactionInstruction({
    programId: new PublicKey(programId),
    keys: [
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
    data: ixData([5]),
  });
}

export function ixTokenSetAuthority(
  account: PublicKey,
  currentAuthority: PublicKey,
  authorityType: number,
  newAuthority: PublicKey | null,
  programId = TOKEN_PROGRAM_ID,
): TransactionInstruction {
  const data = new Uint8Array(newAuthority ? 35 : 3);
  data[0] = 6;
  data[1] = authorityType;
  if (newAuthority) {
    data[2] = 1;
    data.set(newAuthority.toBytes(), 3);
  } else {
    data[2] = 0;
  }
  return new TransactionInstruction({
    programId: new PublicKey(programId),
    keys: [
      { pubkey: account, isSigner: false, isWritable: true },
      { pubkey: currentAuthority, isSigner: true, isWritable: false },
    ],
    data: ixData(data),
  });
}

export function ixTokenCloseAccount(
  account: PublicKey,
  destination: PublicKey,
  owner: PublicKey,
  programId = TOKEN_PROGRAM_ID,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: new PublicKey(programId),
    keys: [
      { pubkey: account, isSigner: false, isWritable: true },
      { pubkey: destination, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
    data: ixData([9]),
  });
}

export interface MockRpcConfig {
  slot?: number;
  preAccounts?: Record<string, RpcAccount | null>;
  postAccounts?: Record<string, RpcAccount | null>;
  simErr?: unknown;
  logs?: string[];
  unitsConsumed?: number;
  innerInstructions?: Array<{
    index: number;
    instructions: Array<{ programIdIndex: number; accounts: number[]; data: string }>;
  }>;
  calls?: Array<{ method: string; params: unknown[] }>;
}

export function createMockRpc(cfg: MockRpcConfig = {}): RpcClient {
  const slot = cfg.slot ?? 300_000_000;
  const pre = cfg.preAccounts ?? {};
  const post = cfg.postAccounts ?? {};

  return {
    async call<T = unknown>(method: string, params: unknown[]): Promise<T> {
      cfg.calls?.push({ method, params });
      if (method === 'getMultipleAccounts') {
        const keys = (params[0] as string[]) ?? [];
        const value = keys.map((k) => (k in pre ? pre[k] ?? null : null));
        return { context: { slot }, value } as T;
      }
      if (method === 'simulateTransaction') {
        const simCfg = (params[1] as { accounts?: { addresses?: string[] } }) ?? {};
        const addrs = simCfg.accounts?.addresses ?? [];
        const err = cfg.simErr ?? null;
        const accounts = err
          ? null
          : addrs.map((k) => (k in post ? post[k] ?? null : k in pre ? pre[k] ?? null : null));
        return {
          context: { slot },
          value: {
            err,
            logs: cfg.logs ?? ['Program invoke [1]', 'Program success'],
            accounts,
            unitsConsumed: cfg.unitsConsumed ?? 25_000,
            innerInstructions: cfg.innerInstructions ?? [],
          },
        } as T;
      }
      if (method === 'getSlot') {
        return slot as T;
      }
      throw new Error(`Unexpected RPC method in test: ${method}`);
    },
  };
}
