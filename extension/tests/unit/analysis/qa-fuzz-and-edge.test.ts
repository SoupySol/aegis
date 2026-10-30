/**
 * qa-fuzz-and-edge.test.ts
 * QA Fuzzing, Boundary, Cross-Account Precision & Audit Characterization Suite
 * for `src/background/analysis/` and `src/shared/detectors/`.
 */
import { describe, expect, it } from 'vitest';
import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  StakeProgram,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from '@solana/web3.js';
import { analyzeMessage, analyzeTransactions } from '../../../src/background/analysis';
import {
  parseMint,
  parseProgramAccount,
  parseProgramData,
  parseRpcAccount,
  parseTokenAccount,
  type RpcAccount,
} from '../../../src/background/analysis/accounts';
import { ByteReader, decodeBase58, encodeBase58, encodeBase64 } from '../../../src/background/analysis/bytes';
import { decodeInstruction } from '../../../src/background/analysis/decoders';
import { createRpcClient, RpcError } from '../../../src/background/analysis/rpc';
import { computeTransactionFee } from '../../../src/background/analysis/rules';
import { decodeMessage, decodeTransaction } from '../../../src/background/analysis/wire';
import { fingerprint, resetSessionKeyForTests } from '../../../src/shared/detectors/fingerprint';
import { detectSecrets } from '../../../src/shared/detectors/secret-detector';
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  BPF_UPGRADEABLE_LOADER_ID,
  COMPUTE_BUDGET_PROGRAM_ID,
  JUPITER_V6_PROGRAM_ID,
  MEMO_PROGRAM_ID,
  MEMO_V1_PROGRAM_ID,
  PUMP_FUN_PROGRAM_ID,
  STAKE_PROGRAM_ID,
  SYSTEM_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  USDC_MINT,
  WSOL_MINT,
} from '../../../src/shared/known-programs';
import {
  BLOCKHASH,
  createMockRpc,
  ixData,
  ixTokenApprove,
  ixTokenCloseAccount,
  ixTokenRevoke,
  ixTokenSetAuthority,
  ixTokenTransfer,
  ixTokenTransferChecked,
  makeLookupTableRpcAccount,
  makeMintRpcAccount,
  makeSystemRpcAccount,
  makeTokenRpcAccount,
  randomPubkey,
  writeU16LE,
  writeU32LE,
  writeU64LE,
} from './helpers';

const ORIGIN = 'https://qa-audit.example.com';

/** Deterministic 32-bit PRNG (mulberry32) so 500+ fuzz inputs are 100% reproducible. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function encodeCompactU16(val: number): Uint8Array {
  if (val < 0x80) return new Uint8Array([val]);
  if (val < 0x4000) return new Uint8Array([(val & 0x7f) | 0x80, val >>> 7]);
  return new Uint8Array([(val & 0x7f) | 0x80, ((val >>> 7) & 0x7f) | 0x80, val >>> 14]);
}

function serializeLegacy(feePayer: PublicKey, ...ixs: TransactionInstruction[]): Uint8Array {
  const tx = new Transaction({ feePayer, recentBlockhash: BLOCKHASH });
  tx.add(...ixs);
  return new Uint8Array(tx.serialize({ requireAllSignatures: false, verifySignatures: false }));
}

function makeLookalikePubkey(targetBase58: string): PublicKey {
  const raw = decodeBase58(targetBase58);
  const prefix = targetBase58.slice(0, 4);
  const suffix = targetBase58.slice(-4);
  // Flip middle bytes only — in base58 a 32-byte value's high & low digits map closely to outer bytes,
  // or we can search/construct a valid 32-byte key sharing first 4 and last 4 base58 chars.
  // Even faster: construct a base58 string of the exact same length with matching outer 4 chars and
  // adjust 2 middle chars until decodeBase58 yields 32 bytes!
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const chars = targetBase58.split('');
  const mid = Math.floor(chars.length / 2);
  for (let i = 0; i < alphabet.length; i++) {
    for (let j = 0; j < alphabet.length; j++) {
      chars[mid] = alphabet[i]!;
      chars[mid + 1] = alphabet[j]!;
      const candidate = chars.join('');
      if (candidate === targetBase58) continue;
      if (!candidate.startsWith(prefix) || !candidate.endsWith(suffix)) continue;
      try {
        const decoded = decodeBase58(candidate);
        if (decoded.length === 32 && encodeBase58(decoded) === candidate) {
          return new PublicKey(decoded);
        }
      } catch {
        // try next middle char pair
      }
    }
  }
  throw new Error(`Failed to synthesize lookalike pubkey for ${raw.length}-byte key`);
}

// =============================================================================
// 1. WIRE & DECODER FUZZING (700+ mutated / random / boundary inputs)
// =============================================================================

describe('Wire & Decoder Fuzzing (700+ boundary, malformed, truncated, and PRNG inputs)', () => {
  it('handles empty Uint8Array(0), all 256 1-byte buffers, and truncated signatures without throwing', async () => {
    const wallet = randomPubkey();
    const boundaryInputs: Uint8Array[] = [new Uint8Array(0)];

    // Every possible 1-byte buffer (256 inputs)
    for (let b = 0; b <= 0xff; b++) {
      boundaryInputs.push(new Uint8Array([b]));
    }

    // Truncated signature arrays (declaring 1, 2, 127 signatures with insufficient bytes)
    boundaryInputs.push(
      new Uint8Array([1]), // 1 sig, 0 sig bytes
      new Uint8Array([1, ...new Uint8Array(31).fill(0xaa)]), // 1 sig, 31 bytes
      new Uint8Array([1, ...new Uint8Array(63).fill(0xaa)]), // 1 sig, 63 bytes
      new Uint8Array([1, ...new Uint8Array(64).fill(0)]), // 1 sig, 0 message bytes
      new Uint8Array([2, ...new Uint8Array(64).fill(0xbb)]), // 2 sigs, only 1 sig present
      new Uint8Array([2, ...new Uint8Array(127).fill(0xbb)]), // 2 sigs, 127 bytes
      new Uint8Array([0x7f, ...new Uint8Array(64).fill(0xcc)]), // 127 sigs, 64 bytes
    );

    const mockRpc = createMockRpc();
    for (const buf of boundaryInputs) {
      expect(() => {
        try {
          decodeTransaction(buf);
        } catch (err) {
          // decodeTransaction may only throw DecodeError, never RangeError/TypeError
          expect((err as Error).name).toBe('DecodeError');
        }
      }).not.toThrow();

      const staticRes = await analyzeTransactions(
        { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [buf] },
        { rpc: null },
      );
      expect(staticRes.verdict).toBe('UNVERIFIED');
      expect(staticRes.findings.some((f) => f.id === 'malformed-transaction')).toBe(true);

      const onlineRes = await analyzeTransactions(
        { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [buf] },
        { rpc: mockRpc },
      );
      expect(onlineRes.verdict).toBe('UNVERIFIED');

      const msgRes = analyzeMessage({
        origin: ORIGIN,
        method: 'signMessage',
        walletPubkey: wallet.toBase58(),
        message: buf,
      });
      expect(['SAFE', 'CAUTION', 'DANGER', 'UNVERIFIED']).toContain(msgRes.verdict);
    }
  });

  it('rejects non-canonical compact-u16, 4-byte varints, overflow > 0xffff, v1..v127 versions, and out-of-range indexes cleanly', async () => {
    const wallet = randomPubkey();

    // Direct compact-u16 malformed vectors
    const badCompactVectors: Uint8Array[] = [
      new Uint8Array([]),
      new Uint8Array([0x80]), // truncated 2-byte
      new Uint8Array([0x80, 0x00]), // non-canonical 0 in 2 bytes
      new Uint8Array([0xff, 0x00]), // non-canonical 127 in 2 bytes
      new Uint8Array([0x80, 0x80]), // truncated 3-byte
      new Uint8Array([0x80, 0x80, 0x00]), // non-canonical 0 in 3 bytes
      new Uint8Array([0xff, 0xff, 0x00]), // non-canonical 0x3fff in 3 bytes
      new Uint8Array([0x80, 0x80, 0x04]), // overflow: 0x10000 > 0xffff
      new Uint8Array([0xff, 0xff, 0x04]), // overflow > 0xffff
      new Uint8Array([0x80, 0x80, 0x80, 0x01]), // 4-byte varint (3rd byte has continuation bit >= 0x04)
      new Uint8Array([0xff, 0xff, 0xff, 0xff]), // all 0xff varint
    ];

    for (const vec of badCompactVectors) {
      expect(() => new ByteReader(vec).compactU16()).toThrow();
    }

    // Valid round-trip boundary check for compact-u16 (0, 0x7f, 0x80, 0x3fff, 0x4000, 0xffff)
    for (const val of [0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0xffff]) {
      const enc = encodeCompactU16(val);
      const reader = new ByteReader(enc);
      expect(reader.compactU16()).toBe(val);
      expect(reader.offset).toBe(enc.length);
    }

    // Build wire transactions containing unsupported version prefixes (v1 = 0x81 .. v127 = 0xff),
    // out-of-range programIdIndex, out-of-range accountIndexes, bad headers, and trailing bytes.
    const sigSection = new Uint8Array(65);
    sigSection[0] = 1; // 1 zero signature

    const validBase = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: randomPubkey(), lamports: 1000 }),
    );

    const malformedWireTxs: Uint8Array[] = [];

    // v1 (0x81), v2 (0x82), v64 (0xc0), v127 (0xff)
    for (const verByte of [0x81, 0x82, 0xc0, 0xfe, 0xff]) {
      const mutated = validBase.slice();
      mutated[65] = verByte;
      malformedWireTxs.push(mutated);
    }

    // Trailing garbage byte appended to valid transaction
    const withTrailing = new Uint8Array(validBase.length + 1);
    withTrailing.set(validBase, 0);
    withTrailing[validBase.length] = 0x99;
    malformedWireTxs.push(withTrailing);

    // Header: numRequiredSignatures (5) > staticAccountKeys.length (1)
    const badHeader1 = new Uint8Array([
      ...sigSection,
      5, 0, 0, // header: 5 sigs required
      1, ...wallet.toBytes(), // only 1 key
      ...new Uint8Array(32).fill(7), // blockhash
      0, // 0 instructions
    ]);
    malformedWireTxs.push(badHeader1);

    // Header: numReadonlySignedAccounts (2) > numRequiredSignatures (1)
    const badHeader2 = new Uint8Array([
      ...sigSection,
      1, 2, 0,
      2, ...wallet.toBytes(), ...randomPubkey().toBytes(),
      ...new Uint8Array(32).fill(7),
      0,
    ]);
    malformedWireTxs.push(badHeader2);

    // Out-of-range programIdIndex (legacy: 2 keys, programIdIndex = 99)
    const badProgIdxLegacy = new Uint8Array([
      ...sigSection,
      1, 0, 1,
      2, ...wallet.toBytes(), ...new PublicKey(SYSTEM_PROGRAM_ID).toBytes(),
      ...new Uint8Array(32).fill(7),
      1, // 1 instruction
      99, // out-of-range programIdIndex!
      0, // 0 accounts
      0, // 0 data
    ]);
    malformedWireTxs.push(badProgIdxLegacy);

    // Out-of-range accountIndex in legacy instruction (2 keys, accountIndex = 50)
    const badAcctIdxLegacy = new Uint8Array([
      ...sigSection,
      1, 0, 1,
      2, ...wallet.toBytes(), ...new PublicKey(SYSTEM_PROGRAM_ID).toBytes(),
      ...new Uint8Array(32).fill(7),
      1, // 1 instruction
      1, // programIdIndex = 1 (valid)
      1, 50, // 1 account index = 50 (out of range!)
      0, // 0 data
    ]);
    malformedWireTxs.push(badAcctIdxLegacy);

    // Out-of-range programIdIndex in v0 message WITH LUT lookups (static=2, LUT writable=1, readonly=1 -> total=4, programIdIndex=4)
    const lutKey = randomPubkey();
    const badProgIdxV0 = new Uint8Array([
      ...sigSection,
      0x80, // v0 prefix
      1, 0, 1,
      2, ...wallet.toBytes(), ...new PublicKey(SYSTEM_PROGRAM_ID).toBytes(),
      ...new Uint8Array(32).fill(7),
      1, // 1 instruction
      4, // programIdIndex = 4 (out of bounds for total 4 keys: 0..3!)
      1, 2, // account index = 2 (LUT writable)
      0, // 0 data
      1, // 1 address table lookup
      ...lutKey.toBytes(),
      1, 0, // 1 writable index
      1, 1, // 1 readonly index
    ]);
    malformedWireTxs.push(badProgIdxV0);

    for (const txBytes of malformedWireTxs) {
      expect(() => decodeTransaction(txBytes)).toThrow();
      const report = await analyzeTransactions(
        { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
        { rpc: null },
      );
      expect(report.verdict).toBe('UNVERIFIED');
      expect(report.findings.some((f) => f.id === 'malformed-transaction')).toBe(true);
      expect(() =>
        analyzeMessage({ origin: ORIGIN, method: 'signMessage', walletPubkey: wallet.toBase58(), message: txBytes }),
      ).not.toThrow();
    }
  });

  it('fuzzes truncated & malformed payloads across every System, Token, Token-2022, Stake, Loader, ComputeBudget, ATA, and Memo discriminator', async () => {
    const k0 = randomPubkey().toBase58();
    const k1 = randomPubkey().toBase58();
    const k2 = randomPubkey().toBase58();
    const k3 = randomPubkey().toBase58();
    const keySets: string[][] = [[], [k0], [k0, k1], [k0, k1, k2, k3]];

    let totalDecodedCalls = 0;

    // 1. System Program: discriminators 0..15 + 999 with truncated lengths 0..68
    for (const disc of [...Array.from({ length: 16 }, (_, i) => i), 999]) {
      for (const len of [0, 1, 2, 3, 4, 7, 8, 11, 12, 35, 36, 43, 68]) {
        const buf = new Uint8Array(len);
        if (len >= 4) writeU32LE(buf, 0, disc);
        // Also test gigantic seed lengths inside CreateAccountWithSeed / AllocateWithSeed / AssignWithSeed / TransferWithSeed
        if (len >= 44) writeU64LE(buf, 36, 0xffff_ffff_ffff_ffffn);
        for (const keys of keySets) {
          const ix = decodeInstruction(SYSTEM_PROGRAM_ID, keys, buf, false);
          expect(ix.programId).toBe(SYSTEM_PROGRAM_ID);
          totalDecodedCalls++;
        }
      }
    }

    // 2. SPL Token & Token-2022: discriminators 0..45 + 255 with truncated lengths and invalid COption / AuthorityType tags
    for (const prog of [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]) {
      for (const disc of [...Array.from({ length: 46 }, (_, i) => i), 255]) {
        for (const len of [0, 1, 2, 3, 5, 8, 9, 10, 34, 35]) {
          const buf = new Uint8Array(len);
          if (len >= 1) buf[0] = disc;
          if (disc === 6 && len >= 2) buf[1] = len % 20; // SetAuthority types including unknown > 16
          if (disc === 6 && len >= 3) buf[2] = len % 4; // COption tags 0, 1, 2, 3
          if (disc === 26 && len >= 2) buf[1] = len % 6; // TransferFeeExtension subdiscriminators
          for (const keys of keySets) {
            const ix = decodeInstruction(prog, keys, buf, false);
            expect(ix.programId).toBe(prog);
            totalDecodedCalls++;
          }
        }
      }
    }

    // 3. Stake Program: discriminators 0..18 + 99 with truncated lengths & COption tags
    for (const disc of [...Array.from({ length: 19 }, (_, i) => i), 99]) {
      for (const len of [0, 1, 3, 4, 8, 12, 35, 36, 39, 40]) {
        const buf = new Uint8Array(len);
        if (len >= 4) writeU32LE(buf, 0, disc);
        if (disc === 7 && len >= 8) writeU32LE(buf, 4, len % 3); // Lockup COption
        for (const keys of keySets) {
          const ix = decodeInstruction(STAKE_PROGRAM_ID, keys, buf, true);
          expect(ix.programId).toBe(STAKE_PROGRAM_ID);
          expect(ix.inner).toBe(true);
          totalDecodedCalls++;
        }
      }
    }

    // 4. BPF Upgradeable Loader: discriminators 0..10 + 99 with truncated lengths
    for (const disc of [...Array.from({ length: 11 }, (_, i) => i), 99]) {
      for (const len of [0, 1, 3, 4, 5, 36, 37]) {
        const buf = new Uint8Array(len);
        if (len >= 4) writeU32LE(buf, 0, disc);
        if (disc === 4 && len >= 5) buf[4] = len % 3; // SetAuthority COption byte
        for (const keys of keySets) {
          const ix = decodeInstruction(BPF_UPGRADEABLE_LOADER_ID, keys, buf, false);
          expect(ix.programId).toBe(BPF_UPGRADEABLE_LOADER_ID);
          totalDecodedCalls++;
        }
      }
    }

    // 5. ComputeBudget, ATA, Memo v1 & v2 (including invalid UTF-8 sequences)
    for (const disc of [0, 1, 2, 3, 4, 5, 99]) {
      for (const len of [0, 1, 2, 4, 5, 8, 9, 12]) {
        const buf = new Uint8Array(len);
        if (len >= 1) buf[0] = disc;
        expect(() => decodeInstruction(COMPUTE_BUDGET_PROGRAM_ID, [k0], buf, false)).not.toThrow();
        expect(() => decodeInstruction(ASSOCIATED_TOKEN_PROGRAM_ID, keySets[3]!, buf, false)).not.toThrow();
        totalDecodedCalls += 2;
      }
    }

    for (const memoProg of [MEMO_V1_PROGRAM_ID, MEMO_PROGRAM_ID]) {
      for (const payload of [
        new Uint8Array(0),
        new Uint8Array([0xff, 0xfe, 0xfd]), // invalid UTF-8
        new Uint8Array([0xc3, 0x28]), // invalid 2-byte UTF-8 sequence
        new Uint8Array(1024).fill(0x41), // long ASCII memo
      ]) {
        const ix = decodeInstruction(memoProg, [k0], payload, false);
        expect(ix.type).toBe('memo:memo');
        totalDecodedCalls++;
      }
    }

    expect(totalDecodedCalls).toBeGreaterThan(5000);
  });

  it('survives 550+ seeded PRNG random & mutated wire buffers through analyzeTransactions and analyzeMessage with zero unhandled exceptions', async () => {
    const rand = mulberry32(0xae615001);
    const wallet = Keypair.fromSeed(new Uint8Array(32).fill(11)).publicKey;
    const recipient = Keypair.fromSeed(new Uint8Array(32).fill(22)).publicKey;
    const mint = Keypair.fromSeed(new Uint8Array(32).fill(33)).publicKey;

    // Seed corpus: valid Legacy tx, valid v0 tx, valid Token SetAuthority tx, valid Stake tx
    const corpus: Uint8Array[] = [
      serializeLegacy(
        wallet,
        ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 5_000 }),
        SystemProgram.transfer({ fromPubkey: wallet, toPubkey: recipient, lamports: 500_000 }),
      ),
      new VersionedTransaction(
        new TransactionMessage({
          payerKey: wallet,
          recentBlockhash: BLOCKHASH,
          instructions: [
            ixTokenTransferChecked(wallet, mint, recipient, wallet, 1_000n, 6),
            ixTokenApprove(wallet, recipient, wallet, 500n),
          ],
        }).compileToV0Message(),
      ).serialize(),
      serializeLegacy(
        wallet,
        ...StakeProgram.authorize({
          stakePubkey: recipient,
          authorizedPubkey: wallet,
          newAuthorizedPubkey: recipient,
          stakeAuthorizationType: { index: 0 },
        }).instructions,
      ),
    ];

    const fuzzBuffers: Uint8Array[] = [];

    // 250 random-length purely random buffers (0..300 bytes)
    for (let i = 0; i < 250; i++) {
      const len = Math.floor(rand() * 300);
      const b = new Uint8Array(len);
      for (let j = 0; j < len; j++) b[j] = Math.floor(rand() * 256);
      fuzzBuffers.push(b);
    }

    // 300 mutated corpus buffers (truncations, bit-flips, byte overwrites, slices, splices)
    for (let i = 0; i < 300; i++) {
      const base = corpus[i % corpus.length]!;
      const mode = i % 5;
      if (mode === 0) {
        // Truncate at random point
        const cut = Math.floor(rand() * base.length);
        fuzzBuffers.push(base.slice(0, cut));
      } else if (mode === 1) {
        // Flip 1..6 random bytes
        const copy = base.slice();
        const flips = 1 + Math.floor(rand() * 6);
        for (let f = 0; f < flips; f++) {
          const idx = Math.floor(rand() * copy.length);
          copy[idx] = copy[idx]! ^ (1 + Math.floor(rand() * 255));
        }
        fuzzBuffers.push(copy);
      } else if (mode === 2) {
        // Corrupt compact-u16 / header region around offset 64..75
        const copy = base.slice();
        const pos = Math.min(copy.length - 1, 64 + Math.floor(rand() * 12));
        copy[pos] = 0x80 | Math.floor(rand() * 128);
        fuzzBuffers.push(copy);
      } else if (mode === 3) {
        // Corrupt instruction payload tail
        const copy = base.slice();
        const tailStart = Math.max(0, copy.length - 15);
        for (let k = tailStart; k < copy.length; k++) {
          copy[k] = Math.floor(rand() * 256);
        }
        fuzzBuffers.push(copy);
      } else {
        // Splice random extra bytes into middle
        const split = Math.floor(rand() * base.length);
        const extra = new Uint8Array(1 + Math.floor(rand() * 20)).map(() => Math.floor(rand() * 256));
        const out = new Uint8Array(base.length + extra.length);
        out.set(base.subarray(0, split), 0);
        out.set(extra, split);
        out.set(base.subarray(split), split + extra.length);
        fuzzBuffers.push(out);
      }
    }

    expect(fuzzBuffers.length).toBe(550);

    const mockRpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(10_000_000_000n),
      },
    });

    for (const buf of fuzzBuffers) {
      const rStatic = await analyzeTransactions(
        { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [buf] },
        { rpc: null },
      );
      expect(['SAFE', 'CAUTION', 'DANGER', 'UNVERIFIED']).toContain(rStatic.verdict);

      const rSim = await analyzeTransactions(
        { origin: ORIGIN, method: 'signAndSendTransaction', walletPubkey: wallet.toBase58(), transactions: [buf] },
        { rpc: mockRpc },
      );
      expect(['SAFE', 'CAUTION', 'DANGER', 'UNVERIFIED']).toContain(rSim.verdict);

      const rMsg = analyzeMessage({
        origin: ORIGIN,
        method: 'signMessage',
        walletPubkey: wallet.toBase58(),
        message: buf,
      });
      expect(['SAFE', 'CAUTION', 'DANGER', 'UNVERIFIED']).toContain(rMsg.verdict);
    }

    // Empty transactions array check
    const emptyBatch = await analyzeTransactions(
      { origin: ORIGIN, method: 'signAllTransactions', walletPubkey: wallet.toBase58(), transactions: [] },
      { rpc: mockRpc },
    );
    expect(emptyBatch.verdict).toBe('UNVERIFIED');
  });
});

// =============================================================================
// 2. RULE PRECISION & CROSS-ACCOUNT CONFUSION CHECKS
// =============================================================================

describe('Rule Precision & Cross-Account Confusion Checks', () => {
  it('Approve on X + Revoke on Y (different account!) flags DANGER, whereas Approve on X + Revoke on X is forgiven (SAFE)', async () => {
    const wallet = randomPubkey();
    const tokenAcctX = randomPubkey();
    const tokenAcctY = randomPubkey();
    const delegate = randomPubkey();
    const mint = new PublicKey(USDC_MINT);

    const preAccounts = {
      [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n),
      [tokenAcctX.toBase58()]: makeTokenRpcAccount({ mint: mint.toBase58(), owner: wallet.toBase58(), amount: 1_000_000n }),
      [tokenAcctY.toBase58()]: makeTokenRpcAccount({ mint: mint.toBase58(), owner: wallet.toBase58(), amount: 1_000_000n }),
      [mint.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'USDC' }),
    };

    // Case 1: Approve(X) followed by Revoke(Y) -> X STILL has an active delegate! Must be DANGER (high)
    const crossAccountTx = serializeLegacy(
      wallet,
      ixTokenApprove(tokenAcctX, delegate, wallet, 500_000n),
      ixTokenRevoke(tokenAcctY, wallet),
    );
    const crossStatic = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [crossAccountTx] },
      { rpc: null },
    );
    expect(crossStatic.severity).toBe('high');
    expect(crossStatic.verdict).toBe('DANGER');
    expect(crossStatic.findings.some((f) => f.id === 'lingering-delegate-approval')).toBe(true);

    const crossSimRpc = createMockRpc({
      preAccounts,
      postAccounts: {
        ...preAccounts,
        [tokenAcctX.toBase58()]: makeTokenRpcAccount({
          mint: mint.toBase58(),
          owner: wallet.toBase58(),
          amount: 1_000_000n,
          delegate: delegate.toBase58(),
          delegatedAmount: 500_000n,
        }),
      },
    });
    const crossSim = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [crossAccountTx] },
      { rpc: crossSimRpc },
    );
    expect(crossSim.severity).toBe('high');
    expect(crossSim.verdict).toBe('DANGER');
    expect(crossSim.findings.some((f) => f.id === 'lingering-delegate-approval')).toBe(true);

    // Case 2: Approve(X) followed by CloseAccount(Y -> wallet) -> X STILL has delegate! Must be DANGER
    const crossCloseTx = serializeLegacy(
      wallet,
      ixTokenApprove(tokenAcctX, delegate, wallet, 500_000n),
      ixTokenCloseAccount(tokenAcctY, wallet, wallet),
    );
    const crossCloseSim = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [crossCloseTx] },
      { rpc: crossSimRpc },
    );
    expect(crossCloseSim.severity).toBe('high');
    expect(crossCloseSim.verdict).toBe('DANGER');

    // Case 3: Revoke(X) BEFORE Approve(X) -> order matters! Delegate remains active at end of tx -> DANGER
    const reverseOrderTx = serializeLegacy(
      wallet,
      ixTokenRevoke(tokenAcctX, wallet),
      ixTokenApprove(tokenAcctX, delegate, wallet, 500_000n),
    );
    const reverseSim = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [reverseOrderTx] },
      { rpc: crossSimRpc },
    );
    expect(reverseSim.severity).toBe('high');
    expect(reverseSim.verdict).toBe('DANGER');

    // Case 4: Approve(X) followed by Revoke(X) in same tx -> forgiven (SAFE)
    const sameAccountTx = serializeLegacy(
      wallet,
      ixTokenApprove(tokenAcctX, delegate, wallet, 500_000n),
      ixTokenRevoke(tokenAcctX, wallet),
    );
    const sameSim = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [sameAccountTx] },
      { rpc: createMockRpc({ preAccounts }) },
    );
    expect(sameSim.verdict).toBe('SAFE');
    expect(sameSim.findings.some((f) => f.id === 'lingering-delegate-approval')).toBe(false);
  });

  it('distinguishes SetAuthority(AccountOwner -> critical), SetAuthority(CloseAccount -> high), and SetAuthority(MintTokens -> SAFE)', async () => {
    const wallet = randomPubkey();
    const userAcct = randomPubkey();
    const userMint = randomPubkey();
    const thirdParty = randomPubkey();

    const preAccounts = {
      [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n),
      [userAcct.toBase58()]: makeTokenRpcAccount({
        mint: USDC_MINT,
        owner: wallet.toBase58(),
        amount: 100_000n,
      }),
      [USDC_MINT]: makeMintRpcAccount({ decimals: 6, symbol: 'USDC' }),
      [userMint.toBase58()]: makeMintRpcAccount({ decimals: 9, mintAuthority: wallet.toBase58() }),
    };

    // 1. AccountOwner (type = 2) -> critical / DANGER (token-account-owner-reassignment)
    const ownerTx = serializeLegacy(wallet, ixTokenSetAuthority(userAcct, wallet, 2, thirdParty));
    const ownerReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [ownerTx] },
      {
        rpc: createMockRpc({
          preAccounts,
          postAccounts: {
            ...preAccounts,
            [userAcct.toBase58()]: makeTokenRpcAccount({
              mint: USDC_MINT,
              owner: thirdParty.toBase58(),
              amount: 100_000n,
            }),
          },
        }),
      },
    );
    expect(ownerReport.severity).toBe('critical');
    expect(ownerReport.verdict).toBe('DANGER');
    expect(ownerReport.findings.some((f) => f.id === 'token-account-owner-change')).toBe(true);

    // 2. CloseAccount (type = 3) -> high / DANGER (close-authority-change)
    const closeAuthTx = serializeLegacy(wallet, ixTokenSetAuthority(userAcct, wallet, 3, thirdParty));
    const closeAuthReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [closeAuthTx] },
      {
        rpc: createMockRpc({
          preAccounts,
          postAccounts: {
            ...preAccounts,
            [userAcct.toBase58()]: makeTokenRpcAccount({
              mint: USDC_MINT,
              owner: wallet.toBase58(),
              amount: 100_000n,
              closeAuthority: thirdParty.toBase58(),
            }),
          },
        }),
      },
    );
    expect(closeAuthReport.severity).toBe('high');
    expect(closeAuthReport.verdict).toBe('DANGER');
    expect(closeAuthReport.findings.some((f) => f.id === 'close-authority-change')).toBe(true);

    // 3. MintTokens (type = 0) on mint controlled by wallet -> SAFE (not a token-account theft vector)
    const mintAuthTx = serializeLegacy(wallet, ixTokenSetAuthority(userMint, wallet, 0, thirdParty));
    const mintAuthReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [mintAuthTx] },
      {
        rpc: createMockRpc({
          preAccounts,
          postAccounts: {
            ...preAccounts,
            [userMint.toBase58()]: makeMintRpcAccount({ decimals: 9, mintAuthority: thirdParty.toBase58() }),
          },
        }),
      },
    );
    expect(mintAuthReport.verdict).toBe('SAFE');
    expect(mintAuthReport.findings.some((f) => f.id === 'token-account-owner-change')).toBe(false);
    expect(mintAuthReport.findings.some((f) => f.id === 'close-authority-change')).toBe(false);
  });

  it('CloseAccount sending rent to a third party is high/DANGER vs sending rent back to walletPubkey is SAFE', async () => {
    const wallet = randomPubkey();
    const userWsolAta = randomPubkey();
    const attacker = randomPubkey();

    const preAccounts = {
      [wallet.toBase58()]: makeSystemRpcAccount(2_000_000_000n),
      [userWsolAta.toBase58()]: makeTokenRpcAccount({
        mint: WSOL_MINT,
        owner: wallet.toBase58(),
        amount: 0n,
        isNative: true,
        lamports: 2_039_280,
      }),
    };

    // Rent to third party -> high / DANGER
    const foreignCloseTx = serializeLegacy(wallet, ixTokenCloseAccount(userWsolAta, attacker, wallet));
    const foreignRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [foreignCloseTx] },
      {
        rpc: createMockRpc({
          preAccounts,
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(1_999_995_000n),
            [userWsolAta.toBase58()]: null,
            [attacker.toBase58()]: makeSystemRpcAccount(2_039_280n),
          },
        }),
      },
    );
    expect(foreignRes.severity).toBe('high');
    expect(foreignRes.verdict).toBe('DANGER');
    expect(foreignRes.findings.some((f) => f.id === 'close-account-foreign-destination')).toBe(true);

    // Rent back to walletPubkey -> SAFE
    const selfCloseTx = serializeLegacy(wallet, ixTokenCloseAccount(userWsolAta, wallet, wallet));
    const selfRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [selfCloseTx] },
      {
        rpc: createMockRpc({
          preAccounts,
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(2_002_034_280n),
            [userWsolAta.toBase58()]: null,
          },
        }),
      },
    );
    expect(selfRes.verdict).toBe('SAFE');
    expect(selfRes.findings.some((f) => f.id === 'close-account-foreign-destination')).toBe(false);
  });

  it('Multi-token outflow (>=3 mints out, 0 inflow -> critical) vs normal swap (wSOL + <=2% fee out, token in -> SAFE)', async () => {
    const wallet = randomPubkey();
    const attacker = randomPubkey();
    const mintA = randomPubkey();
    const mintB = randomPubkey();
    const mintC = randomPubkey();
    const uAtaA = randomPubkey();
    const uAtaB = randomPubkey();
    const uAtaC = randomPubkey();
    const dAtaA = randomPubkey();
    const dAtaB = randomPubkey();
    const dAtaC = randomPubkey();

    // 1. 3 mints drained with 0 inflow -> critical / DANGER
    const drain3Tx = serializeLegacy(
      wallet,
      ixTokenTransfer(uAtaA, dAtaA, wallet, 1_000_000n),
      ixTokenTransfer(uAtaB, dAtaB, wallet, 2_000_000n),
      ixTokenTransfer(uAtaC, dAtaC, wallet, 3_000_000n),
    );
    const drainPre = {
      [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
      [uAtaA.toBase58()]: makeTokenRpcAccount({ mint: mintA.toBase58(), owner: wallet.toBase58(), amount: 1_000_000n }),
      [uAtaB.toBase58()]: makeTokenRpcAccount({ mint: mintB.toBase58(), owner: wallet.toBase58(), amount: 2_000_000n }),
      [uAtaC.toBase58()]: makeTokenRpcAccount({ mint: mintC.toBase58(), owner: wallet.toBase58(), amount: 3_000_000n }),
      [dAtaA.toBase58()]: makeTokenRpcAccount({ mint: mintA.toBase58(), owner: attacker.toBase58(), amount: 0n }),
      [dAtaB.toBase58()]: makeTokenRpcAccount({ mint: mintB.toBase58(), owner: attacker.toBase58(), amount: 0n }),
      [dAtaC.toBase58()]: makeTokenRpcAccount({ mint: mintC.toBase58(), owner: attacker.toBase58(), amount: 0n }),
      [mintA.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'TKNA' }),
      [mintB.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'TKNB' }),
      [mintC.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'TKNC' }),
    };
    const drainPost = {
      ...drainPre,
      [wallet.toBase58()]: makeSystemRpcAccount(999_995_000n),
      [uAtaA.toBase58()]: makeTokenRpcAccount({ mint: mintA.toBase58(), owner: wallet.toBase58(), amount: 0n }),
      [uAtaB.toBase58()]: makeTokenRpcAccount({ mint: mintB.toBase58(), owner: wallet.toBase58(), amount: 0n }),
      [uAtaC.toBase58()]: makeTokenRpcAccount({ mint: mintC.toBase58(), owner: wallet.toBase58(), amount: 0n }),
    };
    const drainRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [drain3Tx] },
      { rpc: createMockRpc({ preAccounts: drainPre, postAccounts: drainPost }) },
    );
    expect(drainRes.severity).toBe('critical');
    expect(drainRes.verdict).toBe('DANGER');
    expect(drainRes.findings.some((f) => f.id === 'multi-token-drain')).toBe(true);

    // 2. Normal swap via Jupiter: wSOL out + 1% protocol fee out, USDC in -> SAFE (normal-swap)
    const wsolAta = randomPubkey();
    const usdcAta = randomPubkey();
    const feeCollector = randomPubkey();
    const swapTx = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: feeCollector, lamports: 10_000_000 }), // 0.01 SOL (1% of 1 SOL swap)
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: wsolAta, isSigner: false, isWritable: true },
          { pubkey: usdcAta, isSigner: false, isWritable: true },
        ],
        data: ixData([1, 2, 3]),
      }),
    );
    const swapPre = {
      [wallet.toBase58()]: makeSystemRpcAccount(2_000_000_000n),
      [wsolAta.toBase58()]: makeTokenRpcAccount({
        mint: WSOL_MINT,
        owner: wallet.toBase58(),
        amount: 1_000_000_000n,
        isNative: true,
      }),
      [usdcAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 0n }),
      [WSOL_MINT]: makeMintRpcAccount({ decimals: 9, symbol: 'SOL' }),
      [USDC_MINT]: makeMintRpcAccount({ decimals: 6, symbol: 'USDC' }),
    };
    const swapPost = {
      ...swapPre,
      [wallet.toBase58()]: makeSystemRpcAccount(1_989_995_000n),
      [wsolAta.toBase58()]: makeTokenRpcAccount({
        mint: WSOL_MINT,
        owner: wallet.toBase58(),
        amount: 0n,
        isNative: true,
      }),
      [usdcAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 150_000_000n }),
    };
    const swapRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [swapTx] },
      { rpc: createMockRpc({ preAccounts: swapPre, postAccounts: swapPost }) },
    );
    expect(swapRes.verdict).toBe('SAFE');
    expect(swapRes.severity).toBe('safe');
    expect(swapRes.findings.some((f) => f.id === 'normal-swap')).toBe(true);
  });

  it('Over 90% SOL outflow with 0 token inflow is high/DANGER vs 95% SOL outflow WITH token inflow via known DEX is SAFE', async () => {
    const wallet = randomPubkey();
    const recipient = randomPubkey();
    const usdcAta = randomPubkey();
    const preLamports = 10_000_000_000n; // 10 SOL

    // 1. 95% SOL outflow, zero token inflow -> high / DANGER (sol-drain-over-90pct)
    const drain95Tx = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: recipient, lamports: 9_500_000_000n }),
    );
    const drain95Res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [drain95Tx] },
      {
        rpc: createMockRpc({
          preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(preLamports) },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(499_995_000n),
            [recipient.toBase58()]: makeSystemRpcAccount(9_500_000_000n),
          },
        }),
      },
    );
    expect(drain95Res.severity).toBe('high');
    expect(drain95Res.verdict).toBe('DANGER');
    expect(drain95Res.findings.some((f) => f.id === 'sol-drain-over-90pct')).toBe(true);

    // 2. Exact 90.00% SOL outflow (effectiveOut * 100 === pre * 90 -> NOT > 90%) -> SAFE
    // Note: totalSolOut includes the 5000-lamport base fee, so transferring 8_999_995_000 + 5_000 fee = exact 9_000_000_000 (90.0%)
    const exact90Tx = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: recipient, lamports: 8_999_995_000n }),
    );
    const exact90Res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [exact90Tx] },
      {
        rpc: createMockRpc({
          preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(preLamports) },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
            [recipient.toBase58()]: makeSystemRpcAccount(8_999_995_000n),
          },
        }),
      },
    );
    expect(exact90Res.verdict).toBe('SAFE');
    expect(exact90Res.findings.some((f) => f.id === 'sol-drain-over-90pct')).toBe(false);

    // 3. 95% SOL outflow WITH USDC inflow in a Jupiter swap -> SAFE (normal-swap)
    const swap95Tx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: usdcAta, isSigner: false, isWritable: true },
        ],
        data: ixData([9, 9, 9]),
      }),
    );
    const swap95Res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [swap95Tx] },
      {
        rpc: createMockRpc({
          preAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(preLamports),
            [usdcAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 0n }),
            [USDC_MINT]: makeMintRpcAccount({ decimals: 6, symbol: 'USDC' }),
          },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(499_995_000n),
            [usdcAta.toBase58()]: makeTokenRpcAccount({
              mint: USDC_MINT,
              owner: wallet.toBase58(),
              amount: 1_425_000_000n,
            }),
            [USDC_MINT]: makeMintRpcAccount({ decimals: 6, symbol: 'USDC' }),
          },
        }),
      },
    );
    expect(swap95Res.verdict).toBe('SAFE');
    expect(swap95Res.severity).toBe('safe');
    expect(swap95Res.findings.some((f) => f.id === 'sol-drain-over-90pct')).toBe(false);
    expect(swap95Res.findings.some((f) => f.id === 'normal-swap')).toBe(true);
  });

  it('Lookalike destination address check catches poisoned SOL & SPL Token destinations (high/DANGER) while allowing self-transfers', async () => {
    const wallet = randomPubkey();
    const lookalike = makeLookalikePubkey(wallet.toBase58());
    expect(lookalike.toBase58().slice(0, 4)).toBe(wallet.toBase58().slice(0, 4));
    expect(lookalike.toBase58().slice(-4)).toBe(wallet.toBase58().slice(-4));
    expect(lookalike.toBase58()).not.toBe(wallet.toBase58());

    // 1. Direct SOL transfer to lookalike -> high / DANGER
    const solPoisonTx = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: lookalike, lamports: 10_000_000 }),
    );
    const solPoisonRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [solPoisonTx] },
      {
        rpc: createMockRpc({
          preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n) },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(4_989_995_000n),
            [lookalike.toBase58()]: makeSystemRpcAccount(10_000_000n),
          },
        }),
      },
    );
    expect(solPoisonRes.severity).toBe('high');
    expect(solPoisonRes.verdict).toBe('DANGER');
    expect(solPoisonRes.findings.some((f) => f.id === 'lookalike-destination')).toBe(true);

    // 2. SPL Token transfer to a non-lookalike ATA whose on-chain owner IS the lookalike wallet -> high / DANGER!
    const userAta = randomPubkey();
    const attackerAta = randomPubkey();
    const tokPoisonTx = serializeLegacy(wallet, ixTokenTransfer(userAta, attackerAta, wallet, 5_000_000n));
    const tokPoisonRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [tokPoisonTx] },
      {
        rpc: createMockRpc({
          preAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n),
            [userAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 10_000_000n }),
            [attackerAta.toBase58()]: makeTokenRpcAccount({
              mint: USDC_MINT,
              owner: lookalike.toBase58(),
              amount: 0n,
            }),
            [USDC_MINT]: makeMintRpcAccount({ decimals: 6, symbol: 'USDC' }),
          },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(4_999_995_000n),
            [userAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 5_000_000n }),
            [attackerAta.toBase58()]: makeTokenRpcAccount({
              mint: USDC_MINT,
              owner: lookalike.toBase58(),
              amount: 5_000_000n,
            }),
          },
        }),
      },
    );
    expect(tokPoisonRes.severity).toBe('high');
    expect(tokPoisonRes.verdict).toBe('DANGER');
    expect(tokPoisonRes.findings.some((f) => f.id === 'lookalike-destination')).toBe(true);

    // 3. Exact self-transfer (wallet -> wallet) -> SAFE (not flagged as lookalike)
    const selfTx = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: wallet, lamports: 9_900_000_000n }),
    );
    const selfRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [selfTx] },
      {
        rpc: createMockRpc({
          preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(10_000_000_000n) },
          postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(9_999_995_000n) },
        }),
      },
    );
    expect(selfRes.verdict).toBe('SAFE');
    expect(selfRes.findings.some((f) => f.id === 'lookalike-destination')).toBe(false);
  });

  it('ComputeBudget handles u32::MAX CU limit * u64::MAX CU price via exact BigInt math without overflow', async () => {
    const wallet = randomPubkey();
    const maxCuLimit = 0xffff_ffff; // 4,294,967,295 units
    const maxCuPrice = 0xffff_ffff_ffff_ffffn; // 18,446,744,073,709,551,615 microLamports

    // Build raw ComputeBudget instructions for max u32 & max u64
    const limitData = new Uint8Array(5);
    limitData[0] = 2;
    writeU32LE(limitData, 1, maxCuLimit);

    const priceData = new Uint8Array(9);
    priceData[0] = 3;
    writeU64LE(priceData, 1, maxCuPrice);

    const cbProg = new PublicKey(COMPUTE_BUDGET_PROGRAM_ID);
    const txBytes = serializeLegacy(
      wallet,
      new TransactionInstruction({ programId: cbProg, keys: [], data: ixData(limitData) }),
      new TransactionInstruction({ programId: cbProg, keys: [], data: ixData(priceData) }),
    );

    const expectedPriorityFee = (BigInt(maxCuLimit) * maxCuPrice + 999_999n) / 1_000_000n;
    const expectedTotalFee = 5_000n + expectedPriorityFee;

    const feeCalc = computeTransactionFee(
      [
        decodeInstruction(COMPUTE_BUDGET_PROGRAM_ID, [], limitData, false),
        decodeInstruction(COMPUTE_BUDGET_PROGRAM_ID, [], priceData, false),
      ],
      1,
    );
    expect(feeCalc.priorityFeeLamports).toBe(expectedPriorityFee);
    expect(feeCalc.totalFeeLamports).toBe(expectedTotalFee);

    // Verify Agave ceiling division: 200,000 CU * 1 microLamport = ceil(0.2) = 1 lamport priority fee
    const oneMicroPriceData = new Uint8Array(9);
    oneMicroPriceData[0] = 3;
    writeU64LE(oneMicroPriceData, 1, 1n);
    const smallFeeCalc = computeTransactionFee(
      [decodeInstruction(COMPUTE_BUDGET_PROGRAM_ID, [], oneMicroPriceData, false)],
      1,
    );
    expect(smallFeeCalc.priorityFeeLamports).toBe(1n);
    expect(smallFeeCalc.totalFeeLamports).toBe(5_001n);

    const res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      {
        rpc: createMockRpc({
          preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n) },
        }),
      },
    );
    expect(res.severity).toBe('medium');
    expect(res.verdict).toBe('CAUTION');
    expect(res.findings.some((f) => f.id === 'high-priority-fee')).toBe(true);
    expect(res.transactions?.[0]?.estimatedFeeLamports).toBe(expectedTotalFee.toString());
  });

  it('Token-2022 TLV edge cases: truncated/odd lengths, all-zero permanentDelegate & transferHook pubkeys (no false positive), and active extensions', async () => {
    const wallet = randomPubkey();
    const recipient = randomPubkey();
    const zeroPubkey = encodeBase58(new Uint8Array(32).fill(0)); // 11111111111111111111111111111111

    // 1. Direct parseMint TLV malformed / boundary checks:
    //    - odd length TLV, truncated header, truncated value, padding 0x0000 0x0000,
    //    - all-zero permanentDelegate (32 zero bytes -> MUST be undefined!),
    //    - non-zero hook authority + all-zero transferHook programId (bytes 32..64 all zero -> MUST be undefined!)
    const rawZeroExtBuf = new Uint8Array(166 + 4 + 32 + 4 + 64 + 4 + 108 + 3);
    rawZeroExtBuf[44] = 6; // decimals
    rawZeroExtBuf[45] = 1; // isInitialized
    rawZeroExtBuf[165] = 1; // ACCOUNT_TYPE_MINT
    let off = 166;
    // Ext 12 (PermanentDelegate) with 32 zero bytes
    writeU16LE(rawZeroExtBuf, off, 12);
    writeU16LE(rawZeroExtBuf, off + 2, 32);
    off += 36;
    // Ext 14 (TransferHook) with NON-ZERO authority (bytes 0..32) + ALL-ZERO program_id (bytes 32..64)
    writeU16LE(rawZeroExtBuf, off, 14);
    writeU16LE(rawZeroExtBuf, off + 2, 64);
    rawZeroExtBuf.set(wallet.toBytes(), off + 4); // authority != 0, program_id == 0
    off += 68;
    // Ext 1 (TransferFeeConfig) with 0 bps
    writeU16LE(rawZeroExtBuf, off, 1);
    writeU16LE(rawZeroExtBuf, off + 2, 108);
    off += 112;
    // Trailing 3-byte truncated TLV header at end of buffer
    rawZeroExtBuf[off] = 99;

    const parsedZeroMint = parseMint(
      parseRpcAccount({
        lamports: 2_000_000,
        owner: TOKEN_2022_PROGRAM_ID,
        data: [encodeBase64(rawZeroExtBuf), 'base64'],
        executable: false,
      }),
    );
    expect(parsedZeroMint).not.toBeNull();
    expect(parsedZeroMint?.permanentDelegate).toBeUndefined();
    expect(parsedZeroMint?.transferHookProgram).toBeUndefined();
    expect(parsedZeroMint?.transferFeeBps).toBeUndefined();

    // Truncated TLV value claiming length = 5000 -> loop terminates safely without throwing
    const truncatedTlvBuf = new Uint8Array(166 + 8);
    truncatedTlvBuf[44] = 9;
    truncatedTlvBuf[45] = 1;
    truncatedTlvBuf[165] = 1;
    writeU16LE(truncatedTlvBuf, 166, 12);
    writeU16LE(truncatedTlvBuf, 168, 5000);
    expect(() =>
      parseMint(
        parseRpcAccount({
          lamports: 2_000_000,
          owner: TOKEN_2022_PROGRAM_ID,
          data: [encodeBase64(truncatedTlvBuf), 'base64'],
          executable: false,
        }),
      ),
    ).not.toThrow();

    // Odd-sized TLV (type 999, length 5) followed by valid PermanentDelegate -> advances cleanly without 4-byte alignment bug
    const oddBeforeValidBuf = new Uint8Array(166 + 4 + 5 + 4 + 32);
    oddBeforeValidBuf[44] = 6;
    oddBeforeValidBuf[45] = 1;
    oddBeforeValidBuf[165] = 1;
    writeU16LE(oddBeforeValidBuf, 166, 999);
    writeU16LE(oddBeforeValidBuf, 168, 5);
    writeU16LE(oddBeforeValidBuf, 175, 12);
    writeU16LE(oddBeforeValidBuf, 177, 32);
    oddBeforeValidBuf.set(recipient.toBytes(), 179);
    const parsedOdd = parseMint(
      parseRpcAccount({
        lamports: 2_000_000,
        owner: TOKEN_2022_PROGRAM_ID,
        data: [encodeBase64(oddBeforeValidBuf), 'base64'],
        executable: false,
      }),
    );
    expect(parsedOdd?.permanentDelegate).toBe(recipient.toBase58());

    // 2. End-to-end analyzeTransactions RECEIVING a Token-2022 mint with zeroed permanentDelegate & zeroed transferHook -> SAFE (zero false positives!)
    const zeroExtMintKey = randomPubkey();
    const userZeroAta = randomPubkey();
    const zeroTx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: userZeroAta, isSigner: false, isWritable: true },
        ],
        data: ixData([1]),
      }),
    );
    const zeroRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [zeroTx] },
      {
        rpc: createMockRpc({
          preAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n),
            [userZeroAta.toBase58()]: makeTokenRpcAccount({
              mint: zeroExtMintKey.toBase58(),
              owner: wallet.toBase58(),
              amount: 0n,
              programId: TOKEN_2022_PROGRAM_ID,
            }),
            [zeroExtMintKey.toBase58()]: {
              lamports: 2_000_000,
              owner: TOKEN_2022_PROGRAM_ID,
              data: [encodeBase64(rawZeroExtBuf), 'base64'],
              executable: false,
            },
          },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(4_989_995_000n),
            [userZeroAta.toBase58()]: makeTokenRpcAccount({
              mint: zeroExtMintKey.toBase58(),
              owner: wallet.toBase58(),
              amount: 5_000n,
              programId: TOKEN_2022_PROGRAM_ID,
            }),
          },
        }),
      },
    );
    expect(zeroPubkey).toBe(SYSTEM_PROGRAM_ID);
    expect(zeroRes.verdict).toBe('SAFE');
    expect(zeroRes.findings.some((f) => f.id.startsWith('received-mint-'))).toBe(false);

    // 3. Receiving active permanentDelegate -> high / DANGER; active transferHook + transferFeeBps -> medium / CAUTION
    const permMint = randomPubkey();
    const hookMint = randomPubkey();
    const uPermAta = randomPubkey();
    const uHookAta = randomPubkey();

    const permTx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: uPermAta, isSigner: false, isWritable: true },
        ],
        data: ixData([1]),
      }),
    );
    const permRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [permTx] },
      {
        rpc: createMockRpc({
          preAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n),
            [uPermAta.toBase58()]: makeTokenRpcAccount({
              mint: permMint.toBase58(),
              owner: wallet.toBase58(),
              amount: 0n,
              programId: TOKEN_2022_PROGRAM_ID,
            }),
            [permMint.toBase58()]: makeMintRpcAccount({
              decimals: 6,
              permanentDelegate: recipient.toBase58(),
              symbol: 'PERM',
            }),
          },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(4_989_995_000n),
            [uPermAta.toBase58()]: makeTokenRpcAccount({
              mint: permMint.toBase58(),
              owner: wallet.toBase58(),
              amount: 1_000n,
              programId: TOKEN_2022_PROGRAM_ID,
            }),
          },
        }),
      },
    );
    expect(permRes.severity).toBe('high');
    expect(permRes.verdict).toBe('DANGER');
    expect(permRes.findings.some((f) => f.id === 'received-mint-permanent-delegate')).toBe(true);

    const hookTx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: uHookAta, isSigner: false, isWritable: true },
        ],
        data: ixData([1]),
      }),
    );
    const hookRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [hookTx] },
      {
        rpc: createMockRpc({
          preAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n),
            [uHookAta.toBase58()]: makeTokenRpcAccount({
              mint: hookMint.toBase58(),
              owner: wallet.toBase58(),
              amount: 0n,
              programId: TOKEN_2022_PROGRAM_ID,
            }),
            [hookMint.toBase58()]: makeMintRpcAccount({
              decimals: 6,
              transferHookProgram: recipient.toBase58(),
              transferFeeBps: 500,
              symbol: 'HOOK',
            }),
          },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(4_989_995_000n),
            [uHookAta.toBase58()]: makeTokenRpcAccount({
              mint: hookMint.toBase58(),
              owner: wallet.toBase58(),
              amount: 1_000n,
              programId: TOKEN_2022_PROGRAM_ID,
            }),
          },
        }),
      },
    );
    expect(hookRes.severity).toBe('medium');
    expect(hookRes.verdict).toBe('CAUTION');
    expect(hookRes.findings.some((f) => f.id === 'received-mint-transfer-extension')).toBe(true);
  });
});

// =============================================================================
// 3. QA AUDIT REGRESSION SUITE (Verifying Hardened Fixes for [BUG-1]..[BUG-8])
// =============================================================================

describe('QA Audit Regression Suite (Verifying Hardened Security Fixes)', () => {
  it('[BUG-1 FIXED] rules.ts multi-token-drain is NOT bypassed when attacker closes drained ATA back to wallet or sends dust SOL', async () => {
    const wallet = randomPubkey();
    const attacker = randomPubkey();
    const mintA = randomPubkey();
    const mintB = randomPubkey();
    const mintC = randomPubkey();
    const uAtaA = randomPubkey();
    const uAtaB = randomPubkey();
    const uAtaC = randomPubkey();
    const dAtaA = randomPubkey();
    const dAtaB = randomPubkey();
    const dAtaC = randomPubkey();

    // Attacker drains 3 distinct SPL tokens to attacker ATAs, then closes uAtaA sending the victim's own 0.00203928 SOL rent to `wallet`
    const bypassTx = serializeLegacy(
      wallet,
      ixTokenTransfer(uAtaA, dAtaA, wallet, 1_000_000n),
      ixTokenTransfer(uAtaB, dAtaB, wallet, 2_000_000n),
      ixTokenTransfer(uAtaC, dAtaC, wallet, 3_000_000n),
      ixTokenCloseAccount(uAtaA, wallet, wallet),
    );

    const preAccounts: Record<string, RpcAccount> = {
      [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
      [uAtaA.toBase58()]: makeTokenRpcAccount({ mint: mintA.toBase58(), owner: wallet.toBase58(), amount: 1_000_000n }),
      [uAtaB.toBase58()]: makeTokenRpcAccount({ mint: mintB.toBase58(), owner: wallet.toBase58(), amount: 2_000_000n }),
      [uAtaC.toBase58()]: makeTokenRpcAccount({ mint: mintC.toBase58(), owner: wallet.toBase58(), amount: 3_000_000n }),
      [dAtaA.toBase58()]: makeTokenRpcAccount({ mint: mintA.toBase58(), owner: attacker.toBase58(), amount: 0n }),
      [dAtaB.toBase58()]: makeTokenRpcAccount({ mint: mintB.toBase58(), owner: attacker.toBase58(), amount: 0n }),
      [dAtaC.toBase58()]: makeTokenRpcAccount({ mint: mintC.toBase58(), owner: attacker.toBase58(), amount: 0n }),
      [mintA.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'TKNA' }),
      [mintB.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'TKNB' }),
      [mintC.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'TKNC' }),
    };
    const postAccounts: Record<string, RpcAccount | null> = {
      ...preAccounts,
      // Wallet SOL goes UP by +2,034,280 lamports (2,039,280 reclaimed rent - 5,000 base fee)
      [wallet.toBase58()]: makeSystemRpcAccount(1_002_034_280n),
      [uAtaA.toBase58()]: null,
      [uAtaB.toBase58()]: makeTokenRpcAccount({ mint: mintB.toBase58(), owner: wallet.toBase58(), amount: 0n }),
      [uAtaC.toBase58()]: makeTokenRpcAccount({ mint: mintC.toBase58(), owner: wallet.toBase58(), amount: 0n }),
    };

    const res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [bypassTx] },
      { rpc: createMockRpc({ preAccounts, postAccounts }) },
    );

    // Reclaimed ATA rent is subtracted from solDelta -> multi-token-drain fires (critical / DANGER)!
    expect(res.findings.some((f) => f.id === 'multi-token-drain')).toBe(true);
    expect(res.severity).toBe('critical');
    expect(res.verdict).toBe('DANGER');

    // Even if attacker adds +0.005 SOL (< 0.01 SOL threshold) non-reclaimed dust inflow, multi-token-drain STILL fires!
    const dustPostAccounts: Record<string, RpcAccount | null> = {
      ...postAccounts,
      [wallet.toBase58()]: makeSystemRpcAccount(1_007_034_280n),
    };
    const dustRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [bypassTx] },
      { rpc: createMockRpc({ preAccounts, postAccounts: dustPostAccounts }) },
    );
    expect(dustRes.findings.some((f) => f.id === 'multi-token-drain')).toBe(true);
    expect(dustRes.verdict).toBe('DANGER');
  });

  it('[BUG-2 FIXED] rules.ts Trojan micro-swap + large SOL transfer to attacker EOA flags sol-drain-over-90pct (high / DANGER) and blocks normal-swap', async () => {
    const wallet = randomPubkey();
    const attacker = randomPubkey();
    const usdcAta = randomPubkey();

    const trojanTx = serializeLegacy(
      wallet,
      // 0.001 SOL swap through Jupiter giving +0.15 USDC inflow
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: usdcAta, isSigner: false, isWritable: true },
        ],
        data: ixData([1]),
      }),
      // Hidden 9.95 SOL (99.5% of wallet!) transfer to attacker EOA
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: attacker, lamports: 9_950_000_000n }),
    );

    const res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [trojanTx] },
      {
        rpc: createMockRpc({
          preAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(10_000_000_000n),
            [usdcAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 0n }),
            [USDC_MINT]: makeMintRpcAccount({ decimals: 6, symbol: 'USDC' }),
          },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(48_995_000n),
            [usdcAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 150_000n }),
            [attacker.toBase58()]: makeSystemRpcAccount(9_950_000_000n),
          },
        }),
      },
    );

    expect(res.findings.some((f) => f.id === 'sol-drain-over-90pct')).toBe(true);
    expect(res.findings.some((f) => f.id === 'normal-swap')).toBe(false);
    expect(res.severity).toBe('high');
    expect(res.verdict).toBe('DANGER');

    // Also catches partial (>0.1 SOL & >50% of total SOL outflow) hidden transfer to unknown EOA during micro-swap
    const partialTrojanTx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: usdcAta, isSigner: false, isWritable: true },
        ],
        data: ixData([1]),
      }),
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: attacker, lamports: 5_000_000_000n }), // 50% of 10 SOL wallet, >99% of SOL outflow
    );
    const partialRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [partialTrojanTx] },
      {
        rpc: createMockRpc({
          preAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(10_000_000_000n),
            [usdcAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 0n }),
            [USDC_MINT]: makeMintRpcAccount({ decimals: 6, symbol: 'USDC' }),
          },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(4_998_995_000n),
            [usdcAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 150_000n }),
            [attacker.toBase58()]: makeSystemRpcAccount(5_000_000_000n),
          },
        }),
      },
    );
    expect(partialRes.findings.some((f) => f.id === 'sol-drain-over-90pct')).toBe(true);
    expect(partialRes.findings.some((f) => f.id === 'normal-swap')).toBe(false);
    expect(partialRes.verdict).toBe('DANGER');

    // Co-signed Pump.fun create does NOT excuse a direct >90% system:transfer to an arbitrary EOA
    const mintKp = Keypair.generate();
    const pumpTx = new Transaction({ recentBlockhash: BLOCKHASH, feePayer: wallet }).add(
      new TransactionInstruction({
        programId: new PublicKey(PUMP_FUN_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: mintKp.publicKey, isSigner: true, isWritable: true },
        ],
        data: ixData([24, 30, 200, 40, 5, 28, 7, 119]),
      }),
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: attacker, lamports: 9_500_000_000n }),
    );
    pumpTx.partialSign(mintKp);
    const pumpBytes = new Uint8Array(pumpTx.serialize({ requireAllSignatures: false, verifySignatures: false }));
    const pumpRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [pumpBytes] },
      {
        rpc: createMockRpc({
          preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(10_000_000_000n) },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(499_990_000n),
            [attacker.toBase58()]: makeSystemRpcAccount(9_500_000_000n),
          },
        }),
      },
    );
    expect(pumpRes.findings.some((f) => f.id === 'sol-drain-over-90pct')).toBe(true);
    expect(pumpRes.verdict).toBe('DANGER');
  });

  it('[BUG-3 FIXED] accounts.ts parseProgramAccount & parseProgramData enforce owner === BPF_UPGRADEABLE_LOADER_ID -> zero false positives on DeFi PDAs', async () => {
    const wallet = randomPubkey();
    const arbitraryProgram = new PublicKey(JUPITER_V6_PROGRAM_ID);
    const poolStatePda = randomPubkey();
    const addrA = randomPubkey();
    const addrB = randomPubkey();

    // Non-loader account owned by Jupiter whose first 4 bytes happen to equal u32(3) (or u32(2)) and byte 12 === 1
    const preBuf = new Uint8Array(64);
    writeU32LE(preBuf, 0, 3);
    preBuf[12] = 1;
    preBuf.set(addrA.toBytes(), 13);

    const progLikeBuf = new Uint8Array(36);
    writeU32LE(progLikeBuf, 0, 2);
    progLikeBuf.set(addrA.toBytes(), 4);

    const postBuf = preBuf.slice();
    postBuf.set(addrB.toBytes(), 13);

    const prePda: RpcAccount = {
      lamports: 5_000_000,
      owner: JUPITER_V6_PROGRAM_ID, // NOT BPF_UPGRADEABLE_LOADER_ID!
      data: [encodeBase64(preBuf), 'base64'],
      executable: false,
    };
    const postPda: RpcAccount = {
      ...prePda,
      data: [encodeBase64(postBuf), 'base64'],
    };
    const progLikePda: RpcAccount = {
      lamports: 5_000_000,
      owner: JUPITER_V6_PROGRAM_ID,
      data: [encodeBase64(progLikeBuf), 'base64'],
      executable: false,
    };

    // Confirm both parseProgramData and parseProgramAccount reject non-loader owners
    expect(parseProgramData(parseRpcAccount(prePda))).toBeNull();
    expect(parseProgramAccount(parseRpcAccount(progLikePda))).toBeNull();
    // Positive check: when owned by BPF_UPGRADEABLE_LOADER_ID, both parse properly
    expect(
      parseProgramData(parseRpcAccount({ ...prePda, owner: BPF_UPGRADEABLE_LOADER_ID }))?.upgradeAuthority,
    ).toBe(addrA.toBase58());
    expect(parseProgramAccount(parseRpcAccount({ ...progLikePda, owner: BPF_UPGRADEABLE_LOADER_ID }))).toBe(
      addrA.toBase58(),
    );

    const txBytes = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: arbitraryProgram,
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: poolStatePda, isSigner: false, isWritable: true },
        ],
        data: ixData([7]),
      }),
    );

    const res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      {
        rpc: createMockRpc({
          preAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n),
            [poolStatePda.toBase58()]: prePda,
          },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(4_999_995_000n),
            [poolStatePda.toBase58()]: postPda,
          },
        }),
      },
    );

    expect(res.findings.some((f) => f.id === 'program-upgrade-authority-change')).toBe(false);
    expect(res.verdict).toBe('SAFE');
  });

  it('[BUG-4 FIXED] simulate.ts prioritizes wallet-owned token accounts BEFORE slicing MAX_SIMULATE_ACCOUNTS (100) in LUT-padded v0 tx', async () => {
    const wallet = randomPubkey();
    const lutPubkey = randomPubkey();
    const dummyWritables = Array.from({ length: 100 }, () => randomPubkey());
    const userAta = randomPubkey(); // Sits at writable index > 100!

    const lutAddresses = [...dummyWritables.map((k) => k.toBase58()), userAta.toBase58()];
    // Build raw v0 transaction referencing 101 writable accounts via LUT
    const sigSection = new Uint8Array(65);
    sigSection[0] = 1;
    const jupKey = new PublicKey(JUPITER_V6_PROGRAM_ID);
    const writableIndices = Array.from({ length: 101 }, (_, i) => i);
    const ixAcctIndices = [0, ...Array.from({ length: 101 }, (_, i) => i + 2)];

    const v0Bytes = new Uint8Array([
      ...sigSection,
      0x80, // v0
      1, 0, 1, // 1 signer (wallet), 0 readonly signed, 1 readonly unsigned (Jupiter)
      2, ...wallet.toBytes(), ...jupKey.toBytes(),
      ...decodeBase58(BLOCKHASH),
      1, // 1 instruction
      1, // programIdIndex = 1 (Jupiter)
      ...encodeCompactU16(ixAcctIndices.length),
      ...ixAcctIndices,
      1, 0xaa, // 1-byte data
      1, // 1 LUT lookup
      ...lutPubkey.toBytes(),
      ...encodeCompactU16(writableIndices.length),
      ...writableIndices,
      0, // 0 readonly LUT indices
    ]);

    const calls: Array<{ method: string; params: unknown[] }> = [];
    const preAccounts: Record<string, RpcAccount> = {
      [lutPubkey.toBase58()]: makeLookupTableRpcAccount(lutAddresses),
      [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n),
      [userAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 500_000_000n }),
      [USDC_MINT]: makeMintRpcAccount({ decimals: 6, symbol: 'USDC' }),
    };
    const postAccounts: Record<string, RpcAccount> = {
      ...preAccounts,
      // CPI drains userAta to 0!
      [userAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 0n }),
    };

    const res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [v0Bytes] },
      { rpc: createMockRpc({ preAccounts, postAccounts, calls }) },
    );

    const simCall = calls.find((c) => c.method === 'simulateTransaction');
    const requestedAddrs = (simCall?.params[1] as { accounts?: { addresses?: string[] } })?.accounts?.addresses ?? [];
    expect(requestedAddrs.length).toBe(100);
    expect(requestedAddrs).toContain(userAta.toBase58());
    const usdcDelta = res.transactions?.[0]?.balanceChanges.find((b) => b.asset === USDC_MINT);
    expect(usdcDelta).toBeDefined();
    expect(usdcDelta?.rawChange).toBe('-500000000');
  });

  it('[BUG-5 FIXED] fingerprint.ts concurrent cold-start race condition & secret-detector leading-zero base58 keypair detection', async () => {
    // 1. Reset session key so concurrent calls genuinely hit cold start
    resetSessionKeyForTests();
    const [fp1, fp2] = await Promise.all([fingerprint('race-input'), fingerprint('race-input')]);
    const fp3 = await fingerprint('race-input');
    expect(fp3).toMatch(/^[0-9a-f]{64}$/);
    expect(fp1).toMatch(/^[0-9a-f]{64}$/);
    expect(fp2).toMatch(/^[0-9a-f]{64}$/);
    expect(fp1).toBe(fp2);
    expect(fp2).toBe(fp3);

    // 2. Secret detector: normal 64-byte Solana keypair in base58 (87-88 chars) IS caught
    const normalKp = Keypair.fromSeed(new Uint8Array(32).fill(9));
    const normalB58 = encodeBase58(normalKp.secretKey);
    expect(normalB58.length).toBeGreaterThanOrEqual(84);
    expect(
      detectSecrets(`key=${normalB58}`).findings.some((f) => f.kind === 'solana-secret-key' && f.format === 'base58'),
    ).toBe(true);

    // 3. Valid 64-byte Solana keypair whose 32-byte seed starts with 12 zero bytes (77 base58 chars < 84) IS ALSO caught
    const leadingZeroSeed = new Uint8Array(32);
    leadingZeroSeed.fill(7, 12);
    const leadingZeroKp = Keypair.fromSeed(leadingZeroSeed);
    const shortB58 = encodeBase58(leadingZeroKp.secretKey);
    expect(shortB58.length).toBeLessThan(84);
    expect(
      detectSecrets(`key=${shortB58}`).findings.some((f) => f.kind === 'solana-secret-key' && f.format === 'base58'),
    ).toBe(true);
  });

  it('[BUG-6 FIXED] simulate.ts excludes external walletPubkey from simAddresses when not in resolvedKeys.keys', async () => {
    const txFeePayer = randomPubkey();
    const writableProg = randomPubkey();
    const externalWallet = randomPubkey();

    // 2-account transaction where BOTH accounts are marked writable
    const allWritableTx = serializeLegacy(
      txFeePayer,
      new TransactionInstruction({
        programId: writableProg,
        keys: [
          { pubkey: txFeePayer, isSigner: true, isWritable: true },
          { pubkey: writableProg, isSigner: false, isWritable: true },
        ],
        data: ixData([]),
      }),
    );

    const calls: Array<{ method: string; params: unknown[] }> = [];
    await analyzeTransactions(
      {
        origin: ORIGIN,
        method: 'signTransaction',
        walletPubkey: externalWallet.toBase58(),
        transactions: [allWritableTx],
      },
      { rpc: createMockRpc({ calls }) },
    );

    const simCall = calls.find((c) => c.method === 'simulateTransaction');
    const simAddrs = (simCall?.params[1] as { accounts?: { addresses?: string[] } })?.accounts?.addresses ?? [];
    expect(simAddrs.length).toBe(2);
    expect(simAddrs).not.toContain(externalWallet.toBase58());
  });

  it('[BUG-7 FIXED] rules.ts gates inner CPI stake/loader/nonce authority changes on currentAuthority === wallet', async () => {
    const wallet = randomPubkey();
    const poolStakeAcct = randomPubkey();
    const poolAuthorityPda = randomPubkey();
    const newPoolAuthorityPda = randomPubkey();
    const jupKey = new PublicKey(JUPITER_V6_PROGRAM_ID);
    const stakeProgKey = new PublicKey(STAKE_PROGRAM_ID);

    // Outer tx invokes Jupiter (known DEX) with pool accounts in key list so inner CPI can reference them
    const txBytes = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: jupKey,
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: poolStakeAcct, isSigner: false, isWritable: true },
          { pubkey: poolAuthorityPda, isSigner: false, isWritable: false },
          { pubkey: stakeProgKey, isSigner: false, isWritable: false },
        ],
        data: ixData([1]),
      }),
    );

    const decoded = decodeTransaction(txBytes);
    const keys = decoded.message.staticAccountKeys;
    const stakeProgIdx = keys.indexOf(STAKE_PROGRAM_ID);
    const stakeAcctIdx = keys.indexOf(poolStakeAcct.toBase58());
    const poolAuthIdx = keys.indexOf(poolAuthorityPda.toBase58());

    // Inner CPI Stake:Authorize (disc=1, newAuthority=newPoolAuthorityPda, authType=0) signed by poolAuthorityPda !== wallet
    const authPayload = new Uint8Array(40);
    writeU32LE(authPayload, 0, 1);
    authPayload.set(newPoolAuthorityPda.toBytes(), 4);
    writeU32LE(authPayload, 36, 0);

    const res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      {
        rpc: createMockRpc({
          preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n) },
          innerInstructions: [
            {
              index: 0,
              instructions: [
                {
                  programIdIndex: stakeProgIdx,
                  accounts: [stakeAcctIdx, stakeAcctIdx, poolAuthIdx],
                  data: encodeBase58(authPayload),
                },
              ],
            },
          ],
        }),
      },
    );

    expect(res.findings.some((f) => f.id === 'stake-authority-change')).toBe(false);
    expect(res.verdict).toBe('SAFE');

    // Conversely, when wallet itself authorizes a NonceAccount handover to a third party -> nonce-authority-change (high / DANGER)
    const nonceAcct = randomPubkey();
    const attacker = randomPubkey();
    const nonceAuthData = new Uint8Array(36);
    writeU32LE(nonceAuthData, 0, 7); // AuthorizeNonceAccount
    nonceAuthData.set(attacker.toBytes(), 4);
    const nonceTx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: SystemProgram.programId,
        keys: [
          { pubkey: nonceAcct, isSigner: false, isWritable: true },
          { pubkey: wallet, isSigner: true, isWritable: false },
        ],
        data: ixData(nonceAuthData),
      }),
    );
    const nonceRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [nonceTx] },
      { rpc: createMockRpc({ preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n) } }) },
    );
    expect(nonceRes.findings.some((f) => f.id === 'nonce-authority-change')).toBe(true);
    expect(nonceRes.severity).toBe('high');
    expect(nonceRes.verdict).toBe('DANGER');
  });

  it('[BUG-8 FIXED] rules.ts caps aggregate exempted smallFeeLamports at <= 2% of tradeSolScale -> catches split 95% SOL drain', async () => {
    const wallet = randomPubkey();
    const attacker = randomPubkey();
    const preLamports = 10_000_000_000n; // 10 SOL
    const chunkLamports = 180_000_000n; // 0.18 SOL each (1.89% individually, 95.4% in aggregate)

    const ixs: TransactionInstruction[] = [
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [{ pubkey: wallet, isSigner: true, isWritable: true }],
        data: ixData([0]),
      }),
    ];
    for (let i = 0; i < 53; i++) {
      ixs.push(SystemProgram.transfer({ fromPubkey: wallet, toPubkey: attacker, lamports: chunkLamports }));
    }
    const splitDrainTx = serializeLegacy(wallet, ...ixs);

    const res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [splitDrainTx] },
      {
        rpc: createMockRpc({
          preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(preLamports) },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(preLamports - 53n * chunkLamports - 5_000n),
            [attacker.toBase58()]: makeSystemRpcAccount(53n * chunkLamports),
          },
        }),
      },
    );

    expect(res.findings.some((f) => f.id === 'sol-drain-over-90pct')).toBe(true);
    expect(res.severity).toBe('high');
    expect(res.verdict).toBe('DANGER');
  });
});

// =============================================================================
// 4. SIMD-0385 TRANSACTION V1, PUBLICNODE 10-KEY FALLBACK & PARSER GUARDS
// =============================================================================

function buildV1Bytes(opts: {
  header: [number, number, number];
  configMask?: number;
  priorityFeeLamports?: bigint;
  computeUnitLimit?: number;
  loadedAccountsDataSizeLimit?: number;
  heapSize?: number;
  addresses: Uint8Array[];
  instructions: Array<{ programIdIndex: number; accountIndexes: number[]; data: Uint8Array }>;
  includeSignatures?: boolean;
}): Uint8Array {
  const mask = opts.configMask ?? 0;
  const chunks: number[] = [
    0x81,
    opts.header[0],
    opts.header[1],
    opts.header[2],
  ];
  const maskBuf = new Uint8Array(4);
  writeU32LE(maskBuf, 0, mask);
  chunks.push(...maskBuf);
  chunks.push(...decodeBase58(BLOCKHASH));
  chunks.push(opts.instructions.length, opts.addresses.length);
  for (const addr of opts.addresses) chunks.push(...addr);

  if ((mask & 0x03) === 0x03) {
    const b = new Uint8Array(8);
    writeU64LE(b, 0, opts.priorityFeeLamports ?? 0n);
    chunks.push(...b);
  }
  if ((mask & 0x04) !== 0) {
    const b = new Uint8Array(4);
    writeU32LE(b, 0, opts.computeUnitLimit ?? 200_000);
    chunks.push(...b);
  }
  if ((mask & 0x08) !== 0) {
    const b = new Uint8Array(4);
    writeU32LE(b, 0, opts.loadedAccountsDataSizeLimit ?? 65_536);
    chunks.push(...b);
  }
  if ((mask & 0x10) !== 0) {
    const b = new Uint8Array(4);
    writeU32LE(b, 0, opts.heapSize ?? 32_768);
    chunks.push(...b);
  }

  // Contiguous 4-byte instruction headers first
  for (const ix of opts.instructions) {
    const hdr = new Uint8Array(4);
    hdr[0] = ix.programIdIndex;
    hdr[1] = ix.accountIndexes.length;
    writeU16LE(hdr, 2, ix.data.length);
    chunks.push(...hdr);
  }
  // Instruction payloads second
  for (const ix of opts.instructions) {
    chunks.push(...ix.accountIndexes, ...ix.data);
  }
  if (opts.includeSignatures !== false) {
    const sigBytes = new Uint8Array(opts.header[0] * 64);
    if (opts.header[0] > 0) sigBytes[0] = 0x42; // non-zero first signature
    chunks.push(...sigBytes);
  }
  return new Uint8Array(chunks);
}

describe('SIMD-0385 v1 Wire Support, PublicNode 10-Key Fallback & Input Guards', () => {
  it('decodes SIMD-0385 v1 transactions & bare v1 messages, evaluates v1 priority fees, and rejects invalid v1 masks', async () => {
    const wallet = randomPubkey();
    const recipient = randomPubkey();
    const sysProg = new PublicKey(SYSTEM_PROGRAM_ID);
    const memoProg = new PublicKey(MEMO_PROGRAM_ID);

    const sysTransferData = new Uint8Array(12);
    writeU32LE(sysTransferData, 0, 2);
    writeU64LE(sysTransferData, 4, 250_000_000n);
    const memoData = new TextEncoder().encode('v1-simd-0385');

    const v1TxBytes = buildV1Bytes({
      header: [1, 0, 2],
      configMask: 0x1f,
      priorityFeeLamports: 60_000_000n, // 0.06 SOL (> 0.05 SOL high-priority-fee threshold)
      computeUnitLimit: 350_000,
      loadedAccountsDataSizeLimit: 131_072,
      heapSize: 65_536,
      addresses: [wallet.toBytes(), recipient.toBytes(), sysProg.toBytes(), memoProg.toBytes()],
      instructions: [
        { programIdIndex: 2, accountIndexes: [0, 1], data: sysTransferData },
        { programIdIndex: 3, accountIndexes: [0], data: memoData },
      ],
      includeSignatures: true,
    });

    const decoded = decodeTransaction(v1TxBytes);
    expect(decoded.message.version).toBe(1);
    expect(decoded.signatures.length).toBe(1);
    expect(decoded.signatures[0]).not.toBeNull();
    expect(decoded.message.transactionConfig).toEqual({
      priorityFeeLamports: 60_000_000n,
      computeUnitLimit: 350_000,
      loadedAccountsDataSizeLimit: 131_072,
      heapSize: 65_536,
    });
    expect(decoded.message.instructions.length).toBe(2);
    expect(decoded.messageBytes.length).toBe(v1TxBytes.length - 64);

    // Bare v1 message decodes cleanly via decodeMessage
    const bareV1Msg = decodeMessage(decoded.messageBytes);
    expect(bareV1Msg.version).toBe(1);
    expect(bareV1Msg.instructions.length).toBe(2);

    // End-to-end analyzeTransactions on v1 surfaces version: 1 and v1 priorityFeeLamports
    const res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [v1TxBytes] },
      {
        rpc: createMockRpc({
          preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n) },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n - 250_000_000n - 60_005_000n),
            [recipient.toBase58()]: makeSystemRpcAccount(250_000_000n),
          },
        }),
      },
    );
    expect(res.transactions?.[0]?.version).toBe(1);
    expect(res.transactions?.[0]?.estimatedFeeLamports).toBe('60005000');
    expect(res.findings.some((f) => f.id === 'high-priority-fee')).toBe(true);

    // Half-set priority fee mask (bit 0 without bit 1), unknown bit 5 (0x20), and non-1024-aligned heapSize are rejected
    expect(() =>
      decodeTransaction(
        buildV1Bytes({
          header: [1, 0, 1],
          configMask: 0x01,
          addresses: [wallet.toBytes(), sysProg.toBytes()],
          instructions: [],
        }),
      ),
    ).toThrow();
    expect(() =>
      decodeTransaction(
        buildV1Bytes({
          header: [1, 0, 1],
          configMask: 0x20,
          addresses: [wallet.toBytes(), sysProg.toBytes()],
          instructions: [],
        }),
      ),
    ).toThrow();
    expect(() =>
      decodeTransaction(
        buildV1Bytes({
          header: [1, 0, 1],
          configMask: 0x10,
          heapSize: 33_000, // not a multiple of 1024
          addresses: [wallet.toBytes(), sysProg.toBytes()],
          instructions: [],
        }),
      ),
    ).toThrow();
  });

  it('analyzeMessage catches disguised v1 transactions/messages, guards non-Uint8Array input, and normalizes SIWS https:// scheme', () => {
    const wallet = randomPubkey();
    const sysProg = new PublicKey(SYSTEM_PROGRAM_ID);
    const v1Tx = buildV1Bytes({
      header: [1, 0, 1],
      configMask: 0,
      addresses: [wallet.toBytes(), sysProg.toBytes()],
      instructions: [{ programIdIndex: 1, accountIndexes: [0], data: new Uint8Array([0, 0, 0, 0]) }],
      includeSignatures: true,
    });
    const v1BareMsg = v1Tx.subarray(0, v1Tx.length - 64);

    const txAsMsg = analyzeMessage({ origin: ORIGIN, method: 'signMessage', walletPubkey: wallet.toBase58(), message: v1Tx });
    expect(txAsMsg.severity).toBe('critical');
    expect(txAsMsg.verdict).toBe('DANGER');
    expect(txAsMsg.findings.some((f) => f.id === 'message-is-transaction')).toBe(true);

    const bareAsMsg = analyzeMessage({ origin: ORIGIN, method: 'signMessage', walletPubkey: wallet.toBase58(), message: v1BareMsg });
    expect(bareAsMsg.severity).toBe('critical');
    expect(bareAsMsg.verdict).toBe('DANGER');
    expect(bareAsMsg.findings.some((f) => f.id === 'message-is-transaction')).toBe(true);

    // Non-Uint8Array message payload returns safe CAUTION instead of throwing
    const malformedReq = analyzeMessage({
      origin: ORIGIN,
      method: 'signMessage',
      walletPubkey: wallet.toBase58(),
      message: null as unknown as Uint8Array,
    });
    expect(malformedReq.verdict).toBe('CAUTION');
    expect(malformedReq.findings.some((f) => f.id === 'binary-message')).toBe(true);

    // SIWS with optional https:// scheme matching origin host -> SAFE
    const siwsMatchingScheme = new TextEncoder().encode(
      `https://qa-audit.example.com wants you to sign in with your Solana account:\n${wallet.toBase58()}\n\nNonce: 123456`,
    );
    const siwsOk = analyzeMessage({ origin: ORIGIN, method: 'signMessage', walletPubkey: wallet.toBase58(), message: siwsMatchingScheme });
    expect(siwsOk.verdict).toBe('SAFE');
    expect(siwsOk.findings.some((f) => f.id === 'siws-domain-mismatch')).toBe(false);

    // SIWS with https:// scheme for a DIFFERENT host -> siws-domain-mismatch (high / DANGER)
    const siwsMismatchScheme = new TextEncoder().encode(
      `https://evil-phish.example.com wants you to sign in with your Solana account:\n${wallet.toBase58()}\n\nNonce: 123456`,
    );
    const siwsBad = analyzeMessage({ origin: ORIGIN, method: 'signMessage', walletPubkey: wallet.toBase58(), message: siwsMismatchScheme });
    expect(siwsBad.verdict).toBe('DANGER');
    expect(siwsBad.findings.some((f) => f.id === 'siws-domain-mismatch')).toBe(true);
  });

  it('PublicNode 10-key getMultipleAccounts fallback retries in chunks of <= 10 when > 10 keys throws RpcError', async () => {
    const wallet = randomPubkey();
    const extraKeys = Array.from({ length: 14 }, () => randomPubkey());
    const txBytes = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          ...extraKeys.map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
        ],
        data: ixData([1]),
      }),
    );

    const batchSizes: number[] = [];
    const baseRpc = createMockRpc({
      preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n) },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(4_999_995_000n) },
    });
    const tenKeyLimitedRpc = {
      async call<T = unknown>(method: string, params: unknown[]): Promise<T> {
        if (method === 'getMultipleAccounts') {
          const keys = params[0] as string[];
          batchSizes.push(keys.length);
          if (keys.length > 10) {
            throw new RpcError('RPC HTTP 403');
          }
        }
        return baseRpc.call<T>(method, params);
      },
    };

    const res = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc: tenKeyLimitedRpc },
    );

    expect(res.rpcUsed).toBe(true);
    expect(res.errors).toEqual([]);
    // Initial attempt (>10 keys) failed, followed by fallback chunks of <= 10 keys
    expect(batchSizes[0]).toBeGreaterThan(10);
    expect(batchSizes.slice(1).length).toBeGreaterThanOrEqual(2);
    expect(batchSizes.slice(1).every((n) => n <= 10)).toBe(true);
  });

  it('createRpcClient enforces isAllowedRpcUrl, parseRpcAccount guards non-finite lamports, Approve(0) stays SAFE, and Token-2022 TransferCheckedWithFee decodes', async () => {
    // 1. createRpcClient URL validation
    expect(() => createRpcClient('')).toThrow(RpcError);
    expect(() => createRpcClient('http://evil.example.com/rpc')).toThrow(RpcError);
    expect(() => createRpcClient('ws://localhost:8900')).toThrow(RpcError);
    expect(() => createRpcClient('https://api.mainnet-beta.solana.com')).not.toThrow();
    expect(() => createRpcClient('http://localhost:8899')).not.toThrow();
    expect(() => createRpcClient('http://127.0.0.1:8899')).not.toThrow();

    // 2. parseRpcAccount non-finite lamports guard
    expect(
      parseRpcAccount({
        lamports: Number.POSITIVE_INFINITY,
        owner: SYSTEM_PROGRAM_ID,
        data: ['', 'base64'],
        executable: false,
      })?.lamports,
    ).toBe(0n);
    expect(
      parseRpcAccount({
        lamports: Number.NaN,
        owner: SYSTEM_PROGRAM_ID,
        data: ['', 'base64'],
        executable: false,
      })?.lamports,
    ).toBe(0n);

    // 3. Simulated Approve(..., 0) where preTok.delegate == null and postTok.delegatedAmount === 0n -> SAFE (matches static rule)
    const wallet = randomPubkey();
    const spender = randomPubkey();
    const userAta = randomPubkey();
    const zeroApproveTx = serializeLegacy(wallet, ixTokenApprove(userAta, spender, wallet, 0n));
    const approveZeroRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [zeroApproveTx] },
      {
        rpc: createMockRpc({
          preAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(2_000_000_000n),
            [userAta.toBase58()]: makeTokenRpcAccount({ mint: USDC_MINT, owner: wallet.toBase58(), amount: 1_000_000n }),
          },
          postAccounts: {
            [wallet.toBase58()]: makeSystemRpcAccount(1_999_995_000n),
            [userAta.toBase58()]: makeTokenRpcAccount({
              mint: USDC_MINT,
              owner: wallet.toBase58(),
              amount: 1_000_000n,
              delegate: spender.toBase58(),
              delegatedAmount: 0n,
            }),
          },
        }),
      },
    );
    expect(approveZeroRes.findings.some((f) => f.id === 'token-delegate-approval')).toBe(false);
    expect(approveZeroRes.verdict).toBe('SAFE');

    // 4. Token-2022 TransferFeeExtension TransferCheckedWithFee ([26, 1, amount u64, decimals u8, fee u64])
    const mintA = randomPubkey();
    const mintB = randomPubkey();
    const mintC = randomPubkey();
    const srcA = randomPubkey();
    const srcB = randomPubkey();
    const srcC = randomPubkey();
    const dst = randomPubkey();

    const makeTransferCheckedWithFeeIx = (src: PublicKey, mint: PublicKey, subDisc: 0 | 1) => {
      const d = new Uint8Array(19);
      d[0] = 26;
      d[1] = subDisc;
      writeU64LE(d, 2, 100_000n);
      d[10] = 6;
      writeU64LE(d, 11, 500n);
      return new TransactionInstruction({
        programId: new PublicKey(TOKEN_2022_PROGRAM_ID),
        keys: [
          { pubkey: src, isSigner: false, isWritable: true },
          { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: dst, isSigner: false, isWritable: true },
          { pubkey: wallet, isSigner: true, isWritable: false },
        ],
        data: ixData(d),
      });
    };

    const t22FeeDrainTx = serializeLegacy(
      wallet,
      makeTransferCheckedWithFeeIx(srcA, mintA, 1),
      makeTransferCheckedWithFeeIx(srcB, mintB, 1),
      makeTransferCheckedWithFeeIx(srcC, mintC, 0),
    );
    const staticDrainRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [t22FeeDrainTx] },
      { rpc: null },
    );
    expect(staticDrainRes.findings.some((f) => f.id === 'multi-token-drain')).toBe(true);
    expect(staticDrainRes.verdict).toBe('DANGER');
  });
});
