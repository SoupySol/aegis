/**
 * simulate-and-rules.test.ts
 * Tests every consumer-protection rule in docs/specs/analysis-engine.md,
 * benign exemptions (SOL self-transfer, Jupiter/Pump.fun swaps, <=2% fee,
 * Jito tips, wSOL close to self, partially signed Pump.fun create),
 * simulation pre/post balance & authority diffs, Token-2022 extensions,
 * multi-tx batches, and offline/failing RPC UNVERIFIED vs DANGER fallbacks.
 */
import { describe, expect, it } from 'vitest';
import {
  AddressLookupTableAccount,
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
import { analyzeTransactions } from '../../../src/background/analysis';
import { encodeBase58 } from '../../../src/background/analysis/bytes';
import { evaluateSite } from '../../../src/background/domains';
import { buildConnectDetails, isCleanBuyOrSellSwap } from '../../../src/background/review-manager';
import { RECENT_DEPLOY_SLOTS } from '../../../src/background/analysis/rules';
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  BPF_UPGRADEABLE_LOADER_ID,
  JITO_TIP_ACCOUNTS,
  JUPITER_V6_PROGRAM_ID,
  METAPLEX_TOKEN_METADATA_PROGRAM_ID,
  PUMP_FUN_PROGRAM_ID,
  STAKE_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  USDC_MINT,
  USDT_MINT,
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
  makeUpgradeableProgramAccounts,
  randomPubkey,
  writeU32LE,
} from './helpers';

const ORIGIN = 'https://app.example.com';

function serializeLegacy(feePayer: PublicKey, ...ixs: TransactionInstruction[]): Uint8Array {
  const tx = new Transaction({ feePayer, recentBlockhash: BLOCKHASH });
  tx.add(...ixs);
  return tx.serialize({ requireAllSignatures: false, verifySignatures: false });
}

describe('every rule in docs/specs/analysis-engine.md', () => {
  it('1. wallet account reassigned to another program (Assign static & post-sim owner diff) -> critical', async () => {
    const wallet = randomPubkey();
    const attackerProg = randomPubkey();
    const txBytes = serializeLegacy(
      wallet,
      SystemProgram.assign({ accountPubkey: wallet, programId: attackerProg }),
    );

    // Static check (no RPC) -> critical / DANGER
    const staticReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc: null },
    );
    expect(staticReport.severity).toBe('critical');
    expect(staticReport.verdict).toBe('DANGER');
    expect(staticReport.findings.some((f) => f.id === 'wallet-owner-reassignment')).toBe(true);

    // Post-simulation owner change without static Assign -> critical / DANGER
    const knownTx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [{ pubkey: wallet, isSigner: true, isWritable: true }],
        data: ixData([1]),
      }),
    );
    const rpc = createMockRpc({
      preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n) },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n, attackerProg.toBase58()) },
    });
    const simReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [knownTx] },
      { rpc },
    );
    expect(simReport.severity).toBe('critical');
    expect(simReport.verdict).toBe('DANGER');
    expect(simReport.transactions?.[0]?.authorityChanges).toContainEqual({
      account: wallet.toBase58(),
      kind: 'wallet-owner',
      from: '11111111111111111111111111111111',
      to: attackerProg.toBase58(),
    });
  });

  it('2. token account owner changed (SetAuthority AccountOwner static & post-sim) -> critical', async () => {
    const wallet = randomPubkey();
    const userTokenAcct = randomPubkey();
    const attacker = randomPubkey();
    const txBytes = serializeLegacy(wallet, ixTokenSetAuthority(userTokenAcct, wallet, 2, attacker));

    const staticReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc: null },
    );
    expect(staticReport.severity).toBe('critical');
    expect(staticReport.verdict).toBe('DANGER');
    expect(staticReport.findings.some((f) => f.id === 'token-account-owner-change')).toBe(true);

    // Post-sim owner change via CPI
    const mint = randomPubkey();
    const cpiTx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: userTokenAcct, isSigner: false, isWritable: true },
        ],
        data: ixData([0]),
      }),
    );
    const rpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
        [userTokenAcct.toBase58()]: makeTokenRpcAccount({
          mint: mint.toBase58(),
          owner: wallet.toBase58(),
          amount: 1_000_000n,
        }),
        [mint.toBase58()]: makeMintRpcAccount({ decimals: 6 }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(999_995_000n),
        [userTokenAcct.toBase58()]: makeTokenRpcAccount({
          mint: mint.toBase58(),
          owner: attacker.toBase58(),
          amount: 1_000_000n,
        }),
      },
    });
    const simReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [cpiTx] },
      { rpc },
    );
    expect(simReport.severity).toBe('critical');
    expect(simReport.findings.some((f) => f.id === 'token-account-owner-change')).toBe(true);
  });

  it('3. stake authority change -> critical', async () => {
    const wallet = randomPubkey();
    const stakeAcct = randomPubkey();
    const attacker = randomPubkey();
    const stakeTx = StakeProgram.authorize({
      stakePubkey: stakeAcct,
      authorizedPubkey: wallet,
      newAuthorizedPubkey: attacker,
      stakeAuthorizationType: { index: 1 }, // Withdrawer
    });
    const txBytes = serializeLegacy(wallet, ...stakeTx.instructions);
    const rpc = createMockRpc({
      preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(2_000_000_000n) },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(1_999_995_000n) },
    });

    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );
    expect(report.severity).toBe('critical');
    expect(report.verdict).toBe('DANGER');
    expect(report.findings.some((f) => f.id === 'stake-authority-change')).toBe(true);
    expect(report.transactions?.[0]?.authorityChanges).toContainEqual({
      account: stakeAcct.toBase58(),
      kind: 'stake-authority',
      from: wallet.toBase58(),
      to: attacker.toBase58(),
    });
  });

  it('4. program upgrade authority change -> critical', async () => {
    const wallet = randomPubkey();
    const programData = randomPubkey();
    const newAuthority = randomPubkey();
    const data = new Uint8Array(4);
    writeU32LE(data, 0, 4); // Loader: SetAuthority
    const ix = new TransactionInstruction({
      programId: new PublicKey(BPF_UPGRADEABLE_LOADER_ID),
      keys: [
        { pubkey: programData, isSigner: false, isWritable: true },
        { pubkey: wallet, isSigner: true, isWritable: false },
        { pubkey: newAuthority, isSigner: false, isWritable: false },
      ],
      data: ixData(data),
    });
    const txBytes = serializeLegacy(wallet, ix);
    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc: null },
    );
    expect(report.severity).toBe('critical');
    expect(report.verdict).toBe('DANGER');
    expect(report.findings.some((f) => f.id === 'program-upgrade-authority-change')).toBe(true);
  });

  it('5. several token types leave the wallet with nothing received (simulation & static) -> critical', async () => {
    const wallet = randomPubkey();
    const mintA = randomPubkey();
    const mintB = randomPubkey();
    const userAtaA = randomPubkey();
    const userAtaB = randomPubkey();
    const drainAtaA = randomPubkey();
    const drainAtaB = randomPubkey();

    const txBytes = serializeLegacy(
      wallet,
      ixTokenTransferChecked(userAtaA, mintA, drainAtaA, wallet, 50_000_000n, 6),
      ixTokenTransferChecked(userAtaB, mintB, drainAtaB, wallet, 100_000_000n, 6),
    );

    // Static fallback catches multi-token drain
    const staticReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc: null },
    );
    expect(staticReport.severity).toBe('critical');
    expect(staticReport.verdict).toBe('DANGER');
    expect(staticReport.findings.some((f) => f.id === 'multi-token-drain')).toBe(true);

    // Simulation diff catches multi-token drain
    const rpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
        [userAtaA.toBase58()]: makeTokenRpcAccount({ mint: mintA.toBase58(), owner: wallet.toBase58(), amount: 50_000_000n }),
        [userAtaB.toBase58()]: makeTokenRpcAccount({ mint: mintB.toBase58(), owner: wallet.toBase58(), amount: 100_000_000n }),
        [mintA.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'TOKA' }),
        [mintB.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'TOKB' }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(999_995_000n),
        [userAtaA.toBase58()]: makeTokenRpcAccount({ mint: mintA.toBase58(), owner: wallet.toBase58(), amount: 0n }),
        [userAtaB.toBase58()]: makeTokenRpcAccount({ mint: mintB.toBase58(), owner: wallet.toBase58(), amount: 0n }),
      },
    });
    const simReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );
    expect(simReport.severity).toBe('critical');
    expect(simReport.findings.some((f) => f.id === 'multi-token-drain')).toBe(true);
    expect(simReport.transactions?.[0]?.balanceChanges).toHaveLength(3); // SOL + 2 tokens
  });

  it('6. more than 90% of SOL leaves with no inflow -> high', async () => {
    const wallet = randomPubkey();
    const recipient = randomPubkey();
    const txBytes = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: recipient, lamports: 9_500_000_000 }),
    );
    const rpc = createMockRpc({
      preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(10_000_000_000n) },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(499_995_000n) },
    });
    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );
    expect(report.severity).toBe('high');
    expect(report.verdict).toBe('DANGER');
    expect(report.findings.some((f) => f.id === 'sol-drain-over-90pct')).toBe(true);
  });

  it('7. delegate approval not revoked within the same tx -> high (and revoked in same tx -> SAFE)', async () => {
    const wallet = randomPubkey();
    const userAta = randomPubkey();
    const delegate = randomPubkey();
    const mint = randomPubkey();

    const unrevokedBytes = serializeLegacy(wallet, ixTokenApprove(userAta, delegate, wallet, 1_000_000n));
    const rpcUnrevoked = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
        [userAta.toBase58()]: makeTokenRpcAccount({ mint: mint.toBase58(), owner: wallet.toBase58(), amount: 1_000_000n }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(999_995_000n),
        [userAta.toBase58()]: makeTokenRpcAccount({
          mint: mint.toBase58(),
          owner: wallet.toBase58(),
          amount: 1_000_000n,
          delegate: delegate.toBase58(),
          delegatedAmount: 1_000_000n,
        }),
      },
    });
    const dangerReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [unrevokedBytes] },
      { rpc: rpcUnrevoked },
    );
    expect(dangerReport.severity).toBe('high');
    expect(dangerReport.verdict).toBe('DANGER');
    expect(dangerReport.findings.some((f) => f.id === 'lingering-delegate-approval')).toBe(true);

    // Approve + Revoke within the same transaction is safe
    const revokedBytes = serializeLegacy(
      wallet,
      ixTokenApprove(userAta, delegate, wallet, 1_000_000n),
      ixTokenRevoke(userAta, wallet),
    );
    const rpcRevoked = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
        [userAta.toBase58()]: makeTokenRpcAccount({ mint: mint.toBase58(), owner: wallet.toBase58(), amount: 1_000_000n }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(999_995_000n),
        [userAta.toBase58()]: makeTokenRpcAccount({ mint: mint.toBase58(), owner: wallet.toBase58(), amount: 1_000_000n }),
      },
    });
    const safeReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [revokedBytes] },
      { rpc: rpcRevoked },
    );
    expect(safeReport.severity).toBe('safe');
    expect(safeReport.verdict).toBe('SAFE');
  });

  it('8. close authority change -> high', async () => {
    const wallet = randomPubkey();
    const userAta = randomPubkey();
    const attacker = randomPubkey();
    // AuthorityType 3 = CloseAccount
    const txBytes = serializeLegacy(wallet, ixTokenSetAuthority(userAta, wallet, 3, attacker));
    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc: null },
    );
    expect(report.severity).toBe('high');
    expect(report.verdict).toBe('DANGER');
    expect(report.findings.some((f) => f.id === 'close-authority-change')).toBe(true);
  });

  it('9. CloseAccount sending rent to someone other than the wallet -> high', async () => {
    const wallet = randomPubkey();
    const userAta = randomPubkey();
    const foreignDest = randomPubkey();
    const txBytes = serializeLegacy(wallet, ixTokenCloseAccount(userAta, foreignDest, wallet));
    const rpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
        [userAta.toBase58()]: makeTokenRpcAccount({ mint: WSOL_MINT, owner: wallet.toBase58(), amount: 0n }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(999_995_000n),
        [userAta.toBase58()]: null,
      },
    });
    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );
    expect(report.severity).toBe('high');
    expect(report.verdict).toBe('DANGER');
    expect(report.findings.some((f) => f.id === 'close-account-foreign-destination')).toBe(true);
  });

  it('10. lookalike destination (same first/last 4 chars as wallet, different address) -> high', async () => {
    // Construct two valid base58 32-byte addresses with identical first 4 & last 4 chars.
    const walletStr = '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';
    const wallet = new PublicKey(walletStr);
    // Tweak middle characters while keeping valid 32-byte base58 decoding and same prefix/suffix.
    let lookalike: PublicKey | undefined;
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    for (const ch of alphabet) {
      const candidate = `${walletStr.slice(0, 12)}${ch}${walletStr.slice(13)}`;
      if (candidate === walletStr) continue;
      try {
        const pk = new PublicKey(candidate);
        if (pk.toBase58() === candidate && candidate.slice(0, 4) === walletStr.slice(0, 4) && candidate.slice(-4) === walletStr.slice(-4)) {
          lookalike = pk;
          break;
        }
      } catch {
        // try next char
      }
    }
    expect(lookalike).toBeDefined();

    const txBytes = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: lookalike!, lamports: 100_000_000 }),
    );
    const rpc = createMockRpc({
      preAccounts: { [walletStr]: makeSystemRpcAccount(5_000_000_000n) },
      postAccounts: { [walletStr]: makeSystemRpcAccount(4_899_995_000n) },
    });
    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: walletStr, transactions: [txBytes] },
      { rpc },
    );
    expect(report.severity).toBe('high');
    expect(report.verdict).toBe('DANGER');
    expect(report.findings.some((f) => f.id === 'lookalike-destination')).toBe(true);
  });

  it('11, 16, 17. Token-2022 permanent delegate (high), freeze authority (medium), transfer hook & transfer fee (medium) on received mints', async () => {
    const wallet = randomPubkey();
    const userAta = randomPubkey();
    const shadyMint = randomPubkey();
    const permDelegate = randomPubkey();
    const hookProg = randomPubkey();
    const freezeAuth = randomPubkey();

    const swapTx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: userAta, isSigner: false, isWritable: true },
        ],
        data: ixData([1, 2, 3]),
      }),
    );

    const rpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(2_000_000_000n),
        [userAta.toBase58()]: null,
        [shadyMint.toBase58()]: makeMintRpcAccount({
          decimals: 6,
          programId: TOKEN_2022_PROGRAM_ID,
          permanentDelegate: permDelegate.toBase58(),
          transferHookProgram: hookProg.toBase58(),
          transferFeeBps: 500, // 5%
          freezeAuthority: freezeAuth.toBase58(),
          symbol: 'TRAP',
          name: 'Trap Token',
          mintAddressForMetadata: shadyMint.toBase58(),
        }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
        [userAta.toBase58()]: makeTokenRpcAccount({
          mint: shadyMint.toBase58(),
          owner: wallet.toBase58(),
          amount: 25_000_000n,
          programId: TOKEN_2022_PROGRAM_ID,
        }),
      },
    });

    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [swapTx] },
      { rpc },
    );
    expect(report.severity).toBe('high');
    expect(report.verdict).toBe('DANGER');
    const ids = report.findings.map((f) => f.id);
    expect(ids).toContain('received-mint-permanent-delegate');
    expect(ids).toContain('received-mint-freeze-authority');
    expect(ids).toContain('received-mint-transfer-extension');
    const tokChange = report.transactions?.[0]?.balanceChanges.find((b) => b.asset === shadyMint.toBase58());
    expect(tokChange?.symbol).toBe('TRAP');
    expect(tokChange?.uiChange).toBe('25');
  });

  it('12. durable nonce -> medium', async () => {
    const wallet = randomPubkey();
    const nonceAcct = randomPubkey();
    const txBytes = serializeLegacy(
      wallet,
      SystemProgram.nonceAdvance({ noncePubkey: nonceAcct, authorizedPubkey: wallet }),
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: wallet, lamports: 1_000 }),
    );
    const rpc = createMockRpc({
      preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n) },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(999_995_000n) },
    });
    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );
    expect(report.transactions?.[0]?.usesDurableNonce).toBe(true);
    expect(report.severity).toBe('medium');
    expect(report.verdict).toBe('CAUTION');
    expect(report.findings.some((f) => f.id === 'durable-nonce')).toBe(true);
  });

  it('13 & 14. unknown program (low) vs recently deployed unknown program (medium + deploySlot)', async () => {
    const wallet = randomPubkey();
    const unknownProg = randomPubkey();
    const progData = randomPubkey();
    const txBytes = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: unknownProg,
        keys: [{ pubkey: wallet, isSigner: true, isWritable: true }],
        data: ixData([0xaa, 0xbb]),
      }),
    );

    const currentSlot = 300_000_000;
    // Deployed long ago -> low ('unknown-program')
    const oldAccounts = makeUpgradeableProgramAccounts(
      progData.toBase58(),
      BigInt(currentSlot - RECENT_DEPLOY_SLOTS - 500_000),
    );
    const rpcOld = createMockRpc({
      slot: currentSlot,
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
        [unknownProg.toBase58()]: oldAccounts.program,
        [progData.toBase58()]: oldAccounts.programData,
      },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(999_995_000n) },
    });
    const oldReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc: rpcOld },
    );
    expect(oldReport.severity).toBe('low');
    expect(oldReport.verdict).toBe('CAUTION');
    expect(oldReport.findings.map((f) => f.id)).toEqual(['unknown-program']);
    expect(oldReport.transactions?.[0]?.programs[0]?.deploySlot).toBe(currentSlot - RECENT_DEPLOY_SLOTS - 500_000);

    // Deployed 500 slots ago -> medium ('unknown-program-recent')
    const recentSlot = currentSlot - 500;
    const recentAccounts = makeUpgradeableProgramAccounts(progData.toBase58(), BigInt(recentSlot));
    const rpcRecent = createMockRpc({
      slot: currentSlot,
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
        [unknownProg.toBase58()]: recentAccounts.program,
        [progData.toBase58()]: recentAccounts.programData,
      },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(999_995_000n) },
    });
    const recentReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc: rpcRecent },
    );
    expect(recentReport.severity).toBe('medium');
    expect(recentReport.verdict).toBe('CAUTION');
    expect(recentReport.findings.map((f) => f.id)).toEqual(['unknown-program-recent']);
    expect(recentReport.transactions?.[0]?.programs[0]?.deploySlot).toBe(recentSlot);
  });

  it('15. priority fee above 0.05 SOL -> medium, with exact estimatedFeeLamports math', async () => {
    const wallet = randomPubkey();
    // 400,000 CU * 200,000,000 microLamports / 1,000,000 = 80,000,000 lamports (0.08 SOL) priority fee
    // + 5,000 base fee = 80,005,000 lamports
    const txBytes = serializeLegacy(
      wallet,
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 200_000_000 }),
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: wallet, lamports: 1_000 }),
    );
    const rpc = createMockRpc({
      preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n) },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(4_919_995_000n) },
    });
    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );
    expect(report.transactions?.[0]?.estimatedFeeLamports).toBe('80005000');
    expect(report.severity).toBe('medium');
    expect(report.verdict).toBe('CAUTION');
    expect(report.findings.some((f) => f.id === 'high-priority-fee')).toBe(true);
  });

  it('18. simulation failed -> info finding with logsTail', async () => {
    const wallet = randomPubkey();
    const txBytes = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: wallet, lamports: 1_000 }),
    );
    const rpc = createMockRpc({
      preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n) },
      simErr: { InstructionError: [0, { Custom: 6001 }] },
      logs: ['Program log: slippage exceeded', 'Program failed: custom program error: 0x1771'],
      unitsConsumed: 14_200,
    });
    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );
    expect(report.rpcUsed).toBe(true);
    expect(report.severity).toBe('info');
    expect(report.verdict).toBe('SAFE');
    expect(report.findings.some((f) => f.id === 'simulation-failed')).toBe(true);
    expect(report.transactions?.[0]?.simulation?.ok).toBe(false);
    expect(report.transactions?.[0]?.simulation?.logsTail).toContain('Program log: slippage exceeded');
  });
});

describe('benign transactions and exemptions stay SAFE', () => {
  it('SOL transfer to self stays SAFE', async () => {
    const wallet = randomPubkey();
    const txBytes = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: wallet, lamports: 500_000_000 }),
    );
    const rpc = createMockRpc({
      preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n) },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(999_995_000n) },
    });
    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );
    expect(report.severity).toBe('safe');
    expect(report.verdict).toBe('SAFE');
    expect(report.findings).toEqual([]);
  });

  it('normal Jupiter swap with USDC inflow (well-known freeze authority), 1% integrator fee, and Jito tip stays SAFE', async () => {
    const wallet = randomPubkey();
    const userUsdcAta = randomPubkey();
    const feeRecipient = randomPubkey();
    const jitoTip = new PublicKey([...JITO_TIP_ACCOUNTS][0]!);

    const txBytes = serializeLegacy(
      wallet,
      ComputeBudgetProgram.setComputeUnitLimit({ units: 300_000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 100_000 }),
      new TransactionInstruction({
        programId: new PublicKey(ASSOCIATED_TOKEN_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: userUsdcAta, isSigner: false, isWritable: true },
          { pubkey: wallet, isSigner: false, isWritable: false },
          { pubkey: new PublicKey(USDC_MINT), isSigner: false, isWritable: false },
        ],
        data: ixData([1]), // CreateIdempotent
      }),
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: userUsdcAta, isSigner: false, isWritable: true },
        ],
        data: ixData([0xe4, 0x45, 0xa5]),
      }),
      // 1% fee on 1 SOL trade = 0.01 SOL (<= 2%)
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: feeRecipient, lamports: 10_000_000 }),
      // Jito tip = 0.001 SOL
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: jitoTip, lamports: 1_000_000 }),
    );

    const rpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_050_000_000n), // >95% spent on trade, yet receiving USDC
        [userUsdcAta.toBase58()]: null,
        [USDC_MINT]: makeMintRpcAccount({
          decimals: 6,
          freezeAuthority: randomPubkey().toBase58(), // USDC has Circle freeze authority, exempted via WELL_KNOWN_MINTS
        }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(38_965_000n),
        [userUsdcAta.toBase58()]: makeTokenRpcAccount({
          mint: USDC_MINT,
          owner: wallet.toBase58(),
          amount: 155_250_000n,
        }),
      },
    });

    const report = await analyzeTransactions(
      { origin: 'https://jup.ag', method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );
    expect(report.severity).toBe('safe');
    expect(report.verdict).toBe('SAFE');
    expect(report.findings.map((f) => f.id)).toEqual(['normal-swap']);
    expect(report.transactions?.[0]?.balanceChanges).toContainEqual({
      asset: USDC_MINT,
      symbol: 'USDC',
      decimals: 6,
      rawChange: '155250000',
      uiChange: '155.25',
      owner: wallet.toBase58(),
    });
  });

  it('standalone Jito tip transfer stays SAFE even when >90% of a tiny wallet', async () => {
    const wallet = randomPubkey();
    const jitoTip = new PublicKey([...JITO_TIP_ACCOUNTS][2]!);
    const txBytes = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: jitoTip, lamports: 9_500_000 }),
    );
    const rpc = createMockRpc({
      preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(10_000_000n) },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(495_000n) },
    });
    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );
    expect(report.severity).toBe('safe');
    expect(report.verdict).toBe('SAFE');
    expect(report.findings).toEqual([]);
  });

  it('wSOL account close back to the wallet stays SAFE', async () => {
    const wallet = randomPubkey();
    const wsolAta = randomPubkey();
    const txBytes = serializeLegacy(wallet, ixTokenCloseAccount(wsolAta, wallet, wallet));
    const rpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(500_000_000n),
        [wsolAta.toBase58()]: makeTokenRpcAccount({
          mint: WSOL_MINT,
          owner: wallet.toBase58(),
          amount: 1_000_000_000n,
          isNative: true,
        }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_502_034_280n),
        [wsolAta.toBase58()]: null,
      },
    });
    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );
    expect(report.severity).toBe('safe');
    expect(report.verdict).toBe('SAFE');
    expect(report.findings).toEqual([]);
  });

  it('partially signed Pump.fun create transaction stays SAFE', async () => {
    const wallet = Keypair.generate();
    const mintKeypair = Keypair.generate();
    const bondingCurve = randomPubkey();

    const tx = new Transaction({
      feePayer: wallet.publicKey,
      recentBlockhash: BLOCKHASH,
    }).add(
      new TransactionInstruction({
        programId: new PublicKey(PUMP_FUN_PROGRAM_ID),
        keys: [
          { pubkey: mintKeypair.publicKey, isSigner: true, isWritable: true },
          { pubkey: bondingCurve, isSigner: false, isWritable: true },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
          { pubkey: new PublicKey(TOKEN_PROGRAM_ID), isSigner: false, isWritable: false },
          { pubkey: new PublicKey(METAPLEX_TOKEN_METADATA_PROGRAM_ID), isSigner: false, isWritable: false },
        ],
        data: ixData([0x18, 0x1e, 0xc8, 0x28, 0x05, 0x1c, 0x07, 0x77]),
      }),
    );
    // Mint keypair co-signs before user's wallet is prompted
    tx.partialSign(mintKeypair);
    const txBytes = tx.serialize({ requireAllSignatures: false, verifySignatures: false });

    // Inner CPI sets MintTokens authority on the new mint to none
    const setMintAuthNone = ixTokenSetAuthority(mintKeypair.publicKey, bondingCurve, 0, null);
    const rpc = createMockRpc({
      preAccounts: {
        [wallet.publicKey.toBase58()]: makeSystemRpcAccount(25_000_000n),
      },
      postAccounts: {
        [wallet.publicKey.toBase58()]: makeSystemRpcAccount(1_500_000n),
      },
      innerInstructions: [
        {
          index: 0,
          instructions: [
            {
              programIdIndex: 4, // TOKEN_PROGRAM_ID in static keys
              accounts: [1, 2],
              data: encodeBase58(setMintAuthNone.data),
            },
          ],
        },
      ],
    });

    const report = await analyzeTransactions(
      {
        origin: 'https://pump.fun',
        method: 'signTransaction',
        walletPubkey: wallet.publicKey.toBase58(),
        transactions: [txBytes],
      },
      { rpc },
    );
    expect(report.transactions?.[0]?.partiallySigned).toBe(true);
    expect(report.transactions?.[0]?.instructions.some((ix) => ix.inner)).toBe(true);
    expect(report.severity).toBe('safe');
    expect(report.verdict).toBe('SAFE');
    expect(report.findings.map((f) => f.id)).toEqual(['normal-swap']);
  });
});

describe('simulation lookup tables, >100 account chunking, batches, and RPC fallback', () => {
  it('resolves v0 lookup tables during simulation and chunks >100 writable accounts', async () => {
    const payer = Keypair.generate();
    const extraWritables = Array.from({ length: 105 }, () => randomPubkey());
    const lutAddress = randomPubkey();
    const lutAccount = new AddressLookupTableAccount({
      key: lutAddress,
      state: {
        deactivationSlot: BigInt('18446744073709551615'),
        lastExtendedSlot: 1,
        lastExtendedSlotStartIndex: 0,
        authority: undefined,
        addresses: extraWritables,
      },
    });

    const v0Msg = new TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: BLOCKHASH,
      instructions: [
        new TransactionInstruction({
          programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
          keys: [
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            ...extraWritables.map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
          ],
          data: ixData([1]),
        }),
      ],
    }).compileToV0Message([lutAccount]);
    const vtx = new VersionedTransaction(v0Msg);
    const wire = vtx.serialize();

    const calls: Array<{ method: string; params: unknown[] }> = [];
    const rpc = createMockRpc({
      calls,
      preAccounts: {
        [lutAddress.toBase58()]: makeLookupTableRpcAccount(extraWritables.map((k) => k.toBase58())),
        [payer.publicKey.toBase58()]: makeSystemRpcAccount(2_000_000_000n),
      },
      postAccounts: {
        [payer.publicKey.toBase58()]: makeSystemRpcAccount(2_500_000_000n),
      },
    });

    const report = await analyzeTransactions(
      {
        origin: 'https://jup.ag',
        method: 'signTransaction',
        walletPubkey: payer.publicKey.toBase58(),
        transactions: [wire],
      },
      { rpc },
    );

    // 1 call for LUT + 2 chunked calls for 106 writable accounts
    const gmaCalls = calls.filter((c) => c.method === 'getMultipleAccounts');
    expect(gmaCalls.length).toBe(3);
    expect((gmaCalls[1]?.params[0] as string[]).length).toBe(100);
    expect((gmaCalls[2]?.params[0] as string[]).length).toBe(6);

    const simCall = calls.find((c) => c.method === 'simulateTransaction');
    expect(simCall?.params[1]).toMatchObject({
      sigVerify: false,
      replaceRecentBlockhash: true,
      commitment: 'processed',
      innerInstructions: true,
    });
    expect(report.verdict).toBe('SAFE');
  });

  it('aggregates worst severity across multi-transaction batches', async () => {
    const wallet = randomPubkey();
    const benignTx = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: wallet, lamports: 1_000 }),
    );
    const unknownProgTx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: randomPubkey(),
        keys: [{ pubkey: wallet, isSigner: true, isWritable: true }],
        data: ixData([1]),
      }),
    );

    const rpc = createMockRpc({
      preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(2_000_000_000n) },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(1_999_995_000n) },
    });

    const report = await analyzeTransactions(
      {
        origin: ORIGIN,
        method: 'signAllTransactions',
        walletPubkey: wallet.toBase58(),
        transactions: [benignTx, unknownProgTx],
      },
      { rpc },
    );
    expect(report.transactions).toHaveLength(2);
    expect(report.transactions?.[0]?.severity).toBe('safe');
    expect(report.transactions?.[1]?.severity).toBe('low');
    expect(report.severity).toBe('low');
    expect(report.verdict).toBe('CAUTION');
    expect(report.findings[0]?.txIndex).toBe(1);
  });

  it('returns UNVERIFIED on null or failing RPC when severity < high, and keeps DANGER on high/critical', async () => {
    const wallet = randomPubkey();
    const benignTx = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: wallet, lamports: 1_000 }),
    );

    // 1. Null RPC on benign tx -> UNVERIFIED
    const nullRpcReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [benignTx] },
      { rpc: null },
    );
    expect(nullRpcReport.rpcUsed).toBe(false);
    expect(nullRpcReport.verdict).toBe('UNVERIFIED');
    expect(nullRpcReport.errors.length).toBeGreaterThan(0);

    // 2. Throwing RPC on benign tx -> UNVERIFIED + error recorded
    const failingRpc = {
      async call(): Promise<never> {
        throw new Error('RPC network unreachable');
      },
    };
    const failRpcReport = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [benignTx] },
      { rpc: failingRpc },
    );
    expect(failRpcReport.rpcUsed).toBe(false);
    expect(failRpcReport.verdict).toBe('UNVERIFIED');
    expect(failRpcReport.errors.some((e) => e.includes('RPC network unreachable'))).toBe(true);

    // 3. Throwing RPC when static analysis finds a high/critical issue -> DANGER
    const foreignDest = randomPubkey();
    const highRiskTx = serializeLegacy(wallet, ixTokenCloseAccount(randomPubkey(), foreignDest, wallet));
    const dangerFallback = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [highRiskTx] },
      { rpc: failingRpc },
    );
    expect(dangerFallback.rpcUsed).toBe(false);
    expect(dangerFallback.severity).toBe('high');
    expect(dangerFallback.verdict).toBe('DANGER');
    expect(dangerFallback.errors.some((e) => e.includes('RPC network unreachable'))).toBe(true);
  });

  it('flags individual freezeAuthority, transferHook, and transferFee mints as medium / CAUTION', async () => {
    const wallet = randomPubkey();
    const userAta = randomPubkey();
    const swapTx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: userAta, isSigner: false, isWritable: true },
        ],
        data: ixData([1]),
      }),
    );

    // Freeze authority alone -> medium
    const freezeMint = randomPubkey();
    const freezeRpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(2_000_000_000n),
        [freezeMint.toBase58()]: makeMintRpcAccount({ decimals: 6, freezeAuthority: randomPubkey().toBase58() }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_500_000_000n),
        [userAta.toBase58()]: makeTokenRpcAccount({ mint: freezeMint.toBase58(), owner: wallet.toBase58(), amount: 1_000n }),
      },
    });
    const freezeRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [swapTx] },
      { rpc: freezeRpc },
    );
    expect(freezeRes.severity).toBe('medium');
    expect(freezeRes.verdict).toBe('CAUTION');
    expect(freezeRes.findings.map((f) => f.id)).toEqual(['received-mint-freeze-authority']);

    // Transfer hook alone -> medium
    const hookMint = randomPubkey();
    const hookRpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(2_000_000_000n),
        [hookMint.toBase58()]: makeMintRpcAccount({
          decimals: 6,
          programId: TOKEN_2022_PROGRAM_ID,
          transferHookProgram: randomPubkey().toBase58(),
        }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_500_000_000n),
        [userAta.toBase58()]: makeTokenRpcAccount({
          mint: hookMint.toBase58(),
          owner: wallet.toBase58(),
          amount: 1_000n,
          programId: TOKEN_2022_PROGRAM_ID,
        }),
      },
    });
    const hookRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [swapTx] },
      { rpc: hookRpc },
    );
    expect(hookRes.severity).toBe('medium');
    expect(hookRes.verdict).toBe('CAUTION');
    expect(hookRes.findings.map((f) => f.id)).toEqual(['received-mint-transfer-extension']);

    // Transfer fee alone -> medium
    const feeMint = randomPubkey();
    const feeRpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(2_000_000_000n),
        [feeMint.toBase58()]: makeMintRpcAccount({
          decimals: 6,
          programId: TOKEN_2022_PROGRAM_ID,
          transferFeeBps: 250, // 2.5%
        }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_500_000_000n),
        [userAta.toBase58()]: makeTokenRpcAccount({
          mint: feeMint.toBase58(),
          owner: wallet.toBase58(),
          amount: 1_000n,
          programId: TOKEN_2022_PROGRAM_ID,
        }),
      },
    });
    const feeRes = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [swapTx] },
      { rpc: feeRpc },
    );
    expect(feeRes.severity).toBe('medium');
    expect(feeRes.verdict).toBe('CAUTION');
    expect(feeRes.findings.map((f) => f.id)).toEqual(['received-mint-transfer-extension']);
  });

  it('detects post-simulation close-authority and delegate changes even without static outer Token instructions', async () => {
    const wallet = randomPubkey();
    const userAta = randomPubkey();
    const mint = randomPubkey();
    const attacker = randomPubkey();
    const cpiTx = serializeLegacy(
      wallet,
      new TransactionInstruction({
        programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
        keys: [
          { pubkey: wallet, isSigner: true, isWritable: true },
          { pubkey: userAta, isSigner: false, isWritable: true },
        ],
        data: ixData([7]),
      }),
    );

    const rpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
        [userAta.toBase58()]: makeTokenRpcAccount({ mint: mint.toBase58(), owner: wallet.toBase58(), amount: 500n }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(999_995_000n),
        [userAta.toBase58()]: makeTokenRpcAccount({
          mint: mint.toBase58(),
          owner: wallet.toBase58(),
          amount: 500n,
          closeAuthority: attacker.toBase58(),
          delegate: attacker.toBase58(),
          delegatedAmount: 500n,
        }),
      },
    });

    const report = await analyzeTransactions(
      { origin: ORIGIN, method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [cpiTx] },
      { rpc },
    );
    expect(report.severity).toBe('high');
    expect(report.verdict).toBe('DANGER');
    const ids = report.findings.map((f) => f.id);
    expect(ids).toContain('close-authority-change');
    expect(ids).toContain('lingering-delegate-approval');
  });

  it('handles malformed wire bytes gracefully as UNVERIFIED without throwing', async () => {
    const report = await analyzeTransactions(
      {
        origin: ORIGIN,
        method: 'signTransaction',
        transactions: [new Uint8Array([0x01, 0x02, 0x03])],
      },
      { rpc: createMockRpc() },
    );
    expect(report.verdict).toBe('UNVERIFIED');
    expect(report.rpcUsed).toBe(false);
    expect(report.errors.length).toBeGreaterThan(0);
    expect(report.findings.some((f) => f.id === 'malformed-transaction')).toBe(true);
  });
});

describe('deep-dive approval breakdown, buy/sell swap fast-path & wallet connect scan', () => {
  it('populates rich approvalDetails for u64::MAX unlimited USDC approval and reports ALL approvals in a batch', async () => {
    const wallet = randomPubkey();
    const usdcAta = randomPubkey();
    const usdtAta = randomPubkey();
    const drainer = randomPubkey();
    const u64Max = 18_446_744_073_709_551_615n;

    const txBytes = serializeLegacy(
      wallet,
      ixTokenApprove(usdcAta, drainer, wallet, u64Max),
      ixTokenApprove(usdtAta, drainer, wallet, 250_000_000n),
    );

    const rpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(2_000_000_000n),
        [usdcAta.toBase58()]: makeTokenRpcAccount({
          mint: USDC_MINT,
          owner: wallet.toBase58(),
          amount: 1_500_000_000n, // 1,500 USDC
        }),
        [usdtAta.toBase58()]: makeTokenRpcAccount({
          mint: USDT_MINT,
          owner: wallet.toBase58(),
          amount: 800_000_000n, // 800 USDT
        }),
        [USDC_MINT]: makeMintRpcAccount({ decimals: 6 }),
        [USDT_MINT]: makeMintRpcAccount({ decimals: 6 }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_999_995_000n),
        [usdcAta.toBase58()]: makeTokenRpcAccount({
          mint: USDC_MINT,
          owner: wallet.toBase58(),
          amount: 1_500_000_000n,
          delegate: drainer.toBase58(),
          delegatedAmount: u64Max,
        }),
        [usdtAta.toBase58()]: makeTokenRpcAccount({
          mint: USDT_MINT,
          owner: wallet.toBase58(),
          amount: 800_000_000n,
          delegate: drainer.toBase58(),
          delegatedAmount: 250_000_000n,
        }),
      },
    });

    const report = await analyzeTransactions(
      { origin: 'https://jup.ag', method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [txBytes] },
      { rpc },
    );

    expect(report.verdict).toBe('DANGER');
    const approvalFindings = report.findings.filter((f) => f.id === 'lingering-delegate-approval');
    expect(approvalFindings).toHaveLength(2);

    const details = report.transactions?.[0]?.approvalDetails ?? [];
    expect(details).toHaveLength(2);
    const usdcDetail = details.find((d) => d.mint === USDC_MINT);
    const usdtDetail = details.find((d) => d.mint === USDT_MINT);

    expect(usdcDetail?.symbol).toBe('USDC');
    expect(usdcDetail?.isUnlimited).toBe(true);
    expect(usdcDetail?.allowanceLabel).toContain('UNLIMITED USDC');
    expect(usdcDetail?.currentBalanceAtRisk).toBe('1500 USDC');
    expect(usdcDetail?.spender).toBe(drainer.toBase58());
    expect(usdcDetail?.spenderKnown).toBe(false);

    expect(usdtDetail?.symbol).toBe('USDT');
    expect(usdtDetail?.isUnlimited).toBeUndefined();
    expect(usdtDetail?.allowanceLabel).toBe('250 USDT');
    expect(usdtDetail?.currentBalanceAtRisk).toBe('800 USDT');
  });

  it('fast-paths clean DEX buy and sell swaps while blocking Trojan Approve swaps, lookalike sites, and non-DEX transfers', async () => {
    const wallet = randomPubkey();
    const userTokenAta = randomPubkey();
    const memeMint = randomPubkey();
    const drainer = randomPubkey();

    const swapIx = new TransactionInstruction({
      programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
      keys: [
        { pubkey: wallet, isSigner: true, isWritable: true },
        { pubkey: userTokenAta, isSigner: false, isWritable: true },
      ],
      data: ixData([0xe4, 0x45, 0xa5, 0x2e]),
    });

    // 1. Clean BUY swap (1 SOL -> 50,000 MEME) on jup.ag -> fast-path true
    const buyBytes = serializeLegacy(wallet, swapIx);
    const buyRpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n),
        [userTokenAta.toBase58()]: null,
        [memeMint.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'MEME' }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(4_000_000_000n),
        [userTokenAta.toBase58()]: makeTokenRpcAccount({
          mint: memeMint.toBase58(),
          owner: wallet.toBase58(),
          amount: 50_000_000_000n,
        }),
      },
    });
    const buyReport = await analyzeTransactions(
      { origin: 'https://jup.ag', method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [buyBytes] },
      { rpc: buyRpc },
    );
    const jupSite = evaluateSite('https://jup.ag');
    const reqBase = {
      type: 'gate' as const,
      origin: 'https://jup.ag',
      method: 'signTransaction',
      wallet: 'Solflare',
      walletPubkey: wallet.toBase58(),
    };
    expect(isCleanBuyOrSellSwap(buyReport, reqBase, jupSite, 'warn')).toBe(true);

    // 2. Clean SELL swap (50,000 MEME -> +0.95 SOL) on pump.fun -> fast-path true
    const sellRpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_000_000_000n),
        [userTokenAta.toBase58()]: makeTokenRpcAccount({
          mint: memeMint.toBase58(),
          owner: wallet.toBase58(),
          amount: 50_000_000_000n,
        }),
        [memeMint.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'MEME' }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(1_950_000_000n),
        [userTokenAta.toBase58()]: makeTokenRpcAccount({
          mint: memeMint.toBase58(),
          owner: wallet.toBase58(),
          amount: 0n,
        }),
      },
    });
    const sellReport = await analyzeTransactions(
      { origin: 'https://pump.fun', method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [buyBytes] },
      { rpc: sellRpc },
    );
    expect(isCleanBuyOrSellSwap(sellReport, { ...reqBase, origin: 'https://pump.fun' }, evaluateSite('https://pump.fun'), 'warn')).toBe(true);

    // 3. Same clean swap on a phishing lookalike domain (purnp.fun) -> NEVER fast-path
    expect(isCleanBuyOrSellSwap(buyReport, { ...reqBase, origin: 'https://purnp.fun' }, evaluateSite('https://purnp.fun'), 'warn')).toBe(false);

    // 4. Trojan BUY swap + hidden Token: Approve -> NEVER fast-path
    const trojanBytes = serializeLegacy(wallet, swapIx, ixTokenApprove(userTokenAta, drainer, wallet, 999_999_999n));
    const trojanRpc = createMockRpc({
      preAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n),
        [userTokenAta.toBase58()]: null,
        [memeMint.toBase58()]: makeMintRpcAccount({ decimals: 6, symbol: 'MEME' }),
      },
      postAccounts: {
        [wallet.toBase58()]: makeSystemRpcAccount(4_000_000_000n),
        [userTokenAta.toBase58()]: makeTokenRpcAccount({
          mint: memeMint.toBase58(),
          owner: wallet.toBase58(),
          amount: 50_000_000_000n,
          delegate: drainer.toBase58(),
          delegatedAmount: 999_999_999n,
        }),
      },
    });
    const trojanReport = await analyzeTransactions(
      { origin: 'https://jup.ag', method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [trojanBytes] },
      { rpc: trojanRpc },
    );
    expect(trojanReport.verdict).toBe('DANGER');
    expect(isCleanBuyOrSellSwap(trojanReport, reqBase, jupSite, 'warn')).toBe(false);

    // 5. Bare SystemProgram.transfer (not a DEX trade) -> NEVER fast-path
    const directSolBytes = serializeLegacy(
      wallet,
      SystemProgram.transfer({ fromPubkey: wallet, toPubkey: drainer, lamports: 10_000_000 }),
    );
    const directSolRpc = createMockRpc({
      preAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(5_000_000_000n) },
      postAccounts: { [wallet.toBase58()]: makeSystemRpcAccount(4_989_995_000n) },
    });
    const directSolReport = await analyzeTransactions(
      { origin: 'https://jup.ag', method: 'signTransaction', walletPubkey: wallet.toBase58(), transactions: [directSolBytes] },
      { rpc: directSolRpc },
    );
    expect(isCleanBuyOrSellSwap(directSolReport, reqBase, jupSite, 'warn')).toBe(false);
  });

  it('builds comprehensive ConnectDetails for connect and SIWS signIn requests', () => {
    const officialSite = evaluateSite('https://pump.fun');
    const connectReq = {
      type: 'gate' as const,
      origin: 'https://pump.fun',
      method: 'connect',
      wallet: 'Solflare',
      walletPubkey: '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU',
    };
    const dummyConnectReport = {
      kind: 'connect' as const,
      origin: 'https://pump.fun',
      method: 'connect',
      severity: 'safe' as const,
      verdict: 'SAFE' as const,
      findings: [],
      rpcUsed: false,
      errors: [],
      analyzedAt: Date.now(),
      durationMs: 1,
    };
    const cd = buildConnectDetails(connectReq, officialSite, dummyConnectReport);
    expect(cd.requestKind).toBe('connect');
    expect(cd.isHttps).toBe(true);
    expect(cd.siteStatus).toBe('official');
    expect(cd.officialBrand).toBe('Pump.fun');
    expect(cd.permissionsGranted.length).toBeGreaterThanOrEqual(3);
    expect(cd.protectionsKept.length).toBeGreaterThanOrEqual(3);

    const spoofSiwsDetails = buildConnectDetails(
      {
        type: 'gate',
        origin: 'https://evil-login.xyz',
        method: 'signIn',
        wallet: 'Phantom',
        signInDomain: 'phantom.app',
        signInFields: {
          domain: 'phantom.app',
          uri: 'https://phantom.app/login',
          statement: 'Approve Phantom session',
          nonce: 'abc999',
        },
      },
      evaluateSite('https://evil-login.xyz'),
      { ...dummyConnectReport, origin: 'https://evil-login.xyz', method: 'signIn' },
    );
    expect(spoofSiwsDetails.requestKind).toBe('signIn');
    expect(spoofSiwsDetails.siws?.domainMatchesOrigin).toBe(false);
    expect(spoofSiwsDetails.siws?.uriMatchesOrigin).toBe(false);
    expect(spoofSiwsDetails.siws?.statement).toBe('Approve Phantom session');
    expect(spoofSiwsDetails.siws?.nonce).toBe('abc999');
  });
});
