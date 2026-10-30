/**
 * wire-and-decoders.test.ts
 * Unit tests for wire-format decoding (legacy + v0 + lookup tables),
 * instruction decoders across all supported Solana programs, and rpc.ts.
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
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  BPF_UPGRADEABLE_LOADER_ID,
  JUPITER_V6_PROGRAM_ID,
  MEMO_PROGRAM_ID,
  MEMO_V1_PROGRAM_ID,
  STAKE_PROGRAM_ID,
  SYSTEM_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
} from '../../../src/shared/known-programs';
import { DecodeError, encodeBase58 } from '../../../src/background/analysis/bytes';
import { decodeInstruction } from '../../../src/background/analysis/decoders';
import { RpcError, createRpcClient } from '../../../src/background/analysis/rpc';
import {
  decodeMessage,
  decodeTransaction,
  isPlaceholder,
  parseLookupTableAddresses,
  resolveAccountKeys,
} from '../../../src/background/analysis/wire';
import {
  BLOCKHASH,
  ixData,
  ixTokenApprove,
  ixTokenCloseAccount,
  ixTokenRevoke,
  ixTokenSetAuthority,
  ixTokenTransfer,
  ixTokenTransferChecked,
  makeLookupTableRpcAccount,
  randomPubkey,
  writeU32LE,
  writeU64LE,
} from './helpers';
import { parseRpcAccount } from '../../../src/background/analysis/accounts';

describe('wire format decoder round-trips against @solana/web3.js', () => {
  it('decodes unsigned and signed legacy transactions accurately', () => {
    const payer = Keypair.generate();
    const recipient = randomPubkey();
    const tx = new Transaction({
      feePayer: payer.publicKey,
      recentBlockhash: BLOCKHASH,
    }).add(
      SystemProgram.transfer({
        fromPubkey: payer.publicKey,
        toPubkey: recipient,
        lamports: 123_456_789,
      }),
    );

    const unsignedBytes = new Uint8Array(tx.serialize({ requireAllSignatures: false, verifySignatures: false }));
    const decodedUnsigned = decodeTransaction(unsignedBytes);
    expect(decodedUnsigned.message.version).toBe('legacy');
    expect(decodedUnsigned.signatures).toEqual([null]);
    expect(decodedUnsigned.message.header).toEqual({
      numRequiredSignatures: 1,
      numReadonlySignedAccounts: 0,
      numReadonlyUnsignedAccounts: 1,
    });
    expect(decodedUnsigned.message.staticAccountKeys).toEqual([
      payer.publicKey.toBase58(),
      recipient.toBase58(),
      SYSTEM_PROGRAM_ID,
    ]);
    expect(decodedUnsigned.message.recentBlockhash).toBe(BLOCKHASH);
    expect(decodedUnsigned.message.instructions).toHaveLength(1);
    expect(decodedUnsigned.messageBytes).toEqual(new Uint8Array(tx.serializeMessage()));

    tx.sign(payer);
    const signedBytes = tx.serialize();
    const decodedSigned = decodeTransaction(signedBytes);
    expect(decodedSigned.signatures[0]).toBe(encodeBase58(tx.signature!));
    expect(decodeMessage(decodedSigned.messageBytes).staticAccountKeys).toEqual(
      decodedUnsigned.message.staticAccountKeys,
    );
  });

  it('decodes multi-signer legacy transactions with partial signatures', () => {
    const user = Keypair.generate();
    const coSigner = Keypair.generate();
    const tx = new Transaction({
      feePayer: user.publicKey,
      recentBlockhash: BLOCKHASH,
    }).add(
      new TransactionInstruction({
        programId: new PublicKey(MEMO_PROGRAM_ID),
        keys: [
          { pubkey: user.publicKey, isSigner: true, isWritable: true },
          { pubkey: coSigner.publicKey, isSigner: true, isWritable: false },
        ],
        data: ixData(new TextEncoder().encode('co-signed memo')),
      }),
    );
    tx.partialSign(coSigner);
    const raw = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
    const decoded = decodeTransaction(raw);
    expect(decoded.message.header.numRequiredSignatures).toBe(2);
    expect(decoded.message.header.numReadonlySignedAccounts).toBe(1);
    expect(decoded.signatures[0]).toBeNull();
    expect(decoded.signatures[1]).not.toBeNull();
  });

  it('decodes v0 VersionedTransactions and resolves Address Lookup Tables in exact Solana key order', () => {
    const payer = Keypair.generate();
    const lutWritableA = randomPubkey();
    const lutWritableB = randomPubkey();
    const lutReadonlyA = randomPubkey();
    const lutReadonlyB = randomPubkey();
    const lutAddress = randomPubkey();

    const lutAccount = new AddressLookupTableAccount({
      key: lutAddress,
      state: {
        deactivationSlot: BigInt('18446744073709551615'),
        lastExtendedSlot: 100,
        lastExtendedSlotStartIndex: 0,
        authority: undefined,
        addresses: [lutWritableA, lutReadonlyA, lutWritableB, lutReadonlyB],
      },
    });

    const customProg = new PublicKey(JUPITER_V6_PROGRAM_ID);
    const v0Msg = new TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: BLOCKHASH,
      instructions: [
        new TransactionInstruction({
          programId: customProg,
          keys: [
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: lutWritableB, isSigner: false, isWritable: true },
            { pubkey: lutReadonlyA, isSigner: false, isWritable: false },
            { pubkey: lutWritableA, isSigner: false, isWritable: true },
            { pubkey: lutReadonlyB, isSigner: false, isWritable: false },
          ],
          data: ixData([1, 2, 3, 4]),
        }),
      ],
    }).compileToV0Message([lutAccount]);

    const vtx = new VersionedTransaction(v0Msg);
    vtx.sign([payer]);
    const wireBytes = vtx.serialize();

    const decoded = decodeTransaction(wireBytes);
    expect(decoded.message.version).toBe(0);
    expect(decoded.signatures).toHaveLength(1);
    expect(decoded.signatures[0]).not.toBeNull();
    expect(decoded.message.addressTableLookups).toHaveLength(1);
    expect(decoded.message.addressTableLookups[0]?.accountKey).toBe(lutAddress.toBase58());

    // Unresolved lookup tables produce placeholders and complete=false
    const unresolved = resolveAccountKeys(decoded.message);
    expect(unresolved.complete).toBe(false);
    expect(unresolved.keys.some((k) => isPlaceholder(k))).toBe(true);

    // Resolved lookup tables match @solana/web3.js static + writable + readonly key order
    const rpcLut = parseRpcAccount(
      makeLookupTableRpcAccount([
        lutWritableA.toBase58(),
        lutReadonlyA.toBase58(),
        lutWritableB.toBase58(),
        lutReadonlyB.toBase58(),
      ]),
    )!;
    const parsedAddresses = parseLookupTableAddresses(rpcLut.data);
    const resolved = resolveAccountKeys(decoded.message, new Map([[lutAddress.toBase58(), parsedAddresses]]));
    expect(resolved.complete).toBe(true);

    const web3Resolved = v0Msg.getAccountKeys({ addressLookupTableAccounts: [lutAccount] });
    const expectedKeys = [
      ...web3Resolved.staticAccountKeys,
      ...(web3Resolved.accountKeysFromLookups?.writable ?? []),
      ...(web3Resolved.accountKeysFromLookups?.readonly ?? []),
    ].map((k) => k.toBase58());
    expect(resolved.keys).toEqual(expectedKeys);
  });

  it('rejects malformed wire inputs cleanly with DecodeError', () => {
    expect(() => decodeTransaction(new Uint8Array([]))).toThrow(DecodeError);
    expect(() => decodeTransaction(new Uint8Array([1, 2, 3]))).toThrow(DecodeError);
    // Unsupported v1 transaction prefix (0x81)
    const badVersion = new Uint8Array(65 + 40);
    badVersion[0] = 1; // 1 sig
    badVersion[65] = 0x81; // version 1
    expect(() => decodeTransaction(badVersion)).toThrow(DecodeError);
    // Trailing byte on otherwise valid tx
    const payer = Keypair.generate();
    const tx = new Transaction({ feePayer: payer.publicKey, recentBlockhash: BLOCKHASH }).add(
      SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: payer.publicKey, lamports: 1 }),
    );
    const raw = tx.serialize({ requireAllSignatures: false });
    const withTrailing = new Uint8Array(raw.length + 1);
    withTrailing.set(raw, 0);
    expect(() => decodeTransaction(withTrailing)).toThrow(DecodeError);
  });
});

describe('instruction decoders cover all required Solana programs', () => {
  it('decodes System Program instructions (Transfer, Assign, CreateAccount, AdvanceNonceAccount)', () => {
    const a = randomPubkey();
    const b = randomPubkey();
    const owner = randomPubkey();

    const transferIx = SystemProgram.transfer({ fromPubkey: a, toPubkey: b, lamports: 2_500_000_000 });
    const dTransfer = decodeInstruction(
      transferIx.programId.toBase58(),
      transferIx.keys.map((k) => k.pubkey.toBase58()),
      transferIx.data,
    );
    expect(dTransfer.name).toBe('System: Transfer');
    expect(dTransfer.type).toBe('system:transfer');
    expect(dTransfer.params).toEqual({
      from: a.toBase58(),
      to: b.toBase58(),
      lamports: '2500000000',
      sol: '2.5',
    });

    const assignIx = SystemProgram.assign({ accountPubkey: a, programId: owner });
    const dAssign = decodeInstruction(
      assignIx.programId.toBase58(),
      assignIx.keys.map((k) => k.pubkey.toBase58()),
      assignIx.data,
    );
    expect(dAssign.name).toBe('System: Assign');
    expect(dAssign.type).toBe('system:assign');
    expect(dAssign.params).toEqual({ account: a.toBase58(), owner: owner.toBase58() });

    const createIx = SystemProgram.createAccount({
      fromPubkey: a,
      newAccountPubkey: b,
      lamports: 1_000_000,
      space: 165,
      programId: new PublicKey(TOKEN_PROGRAM_ID),
    });
    const dCreate = decodeInstruction(
      createIx.programId.toBase58(),
      createIx.keys.map((k) => k.pubkey.toBase58()),
      createIx.data,
    );
    expect(dCreate.name).toBe('System: CreateAccount');
    expect(dCreate.params.space).toBe('165');
    expect(dCreate.params.owner).toBe(TOKEN_PROGRAM_ID);

    const nonceIx = SystemProgram.nonceAdvance({ noncePubkey: b, authorizedPubkey: a });
    const dNonce = decodeInstruction(
      nonceIx.programId.toBase58(),
      nonceIx.keys.map((k) => k.pubkey.toBase58()),
      nonceIx.data,
    );
    expect(dNonce.name).toBe('System: AdvanceNonceAccount');
    expect(dNonce.type).toBe('system:advanceNonceAccount');
  });

  it('decodes SPL Token and Token-2022 instructions', () => {
    const src = randomPubkey();
    const dst = randomPubkey();
    const mint = randomPubkey();
    const owner = randomPubkey();
    const delegate = randomPubkey();

    const tIx = ixTokenTransfer(src, dst, owner, 500_000n);
    const dt = decodeInstruction(TOKEN_PROGRAM_ID, tIx.keys.map((k) => k.pubkey.toBase58()), tIx.data);
    expect(dt.name).toBe('Token: Transfer');
    expect(dt.params.amount).toBe('500000');

    const tcIx = ixTokenTransferChecked(src, mint, dst, owner, 1_234_567n, 6, TOKEN_2022_PROGRAM_ID);
    const dtc = decodeInstruction(TOKEN_2022_PROGRAM_ID, tcIx.keys.map((k) => k.pubkey.toBase58()), tcIx.data, true);
    expect(dtc.name).toBe('Token-2022: TransferChecked');
    expect(dtc.inner).toBe(true);
    expect(dtc.params.decimals).toBe('6');

    const appIx = ixTokenApprove(src, delegate, owner, 999n);
    expect(decodeInstruction(TOKEN_PROGRAM_ID, appIx.keys.map((k) => k.pubkey.toBase58()), appIx.data).name).toBe('Token: Approve');

    const revIx = ixTokenRevoke(src, owner);
    expect(decodeInstruction(TOKEN_PROGRAM_ID, revIx.keys.map((k) => k.pubkey.toBase58()), revIx.data).name).toBe('Token: Revoke');

    const saIx = ixTokenSetAuthority(src, owner, 2, delegate); // 2 = AccountOwner
    const dsa = decodeInstruction(TOKEN_PROGRAM_ID, saIx.keys.map((k) => k.pubkey.toBase58()), saIx.data);
    expect(dsa.name).toBe('Token: SetAuthority(AccountOwner)');
    expect(dsa.type).toBe('token:setAuthority');
    expect(dsa.params.newAuthority).toBe(delegate.toBase58());

    const closeIx = ixTokenCloseAccount(src, dst, owner);
    expect(decodeInstruction(TOKEN_PROGRAM_ID, closeIx.keys.map((k) => k.pubkey.toBase58()), closeIx.data).name).toBe('Token: CloseAccount');

    // Token-2022 InitializePermanentDelegate (tag 35)
    const permData = new Uint8Array(33);
    permData[0] = 35;
    permData.set(delegate.toBytes(), 1);
    const dPerm = decodeInstruction(TOKEN_2022_PROGRAM_ID, [mint.toBase58()], permData);
    expect(dPerm.name).toBe('Token-2022: InitializePermanentDelegate');
    expect(dPerm.params.delegate).toBe(delegate.toBase58());
  });

  it('decodes Stake, Upgradeable Loader, Compute Budget, ATA, Memo, Known DEX, and Unknown instructions', () => {
    const stakeAcct = randomPubkey();
    const auth = randomPubkey();
    const newAuth = randomPubkey();

    // Stake: Authorize (Withdrawer)
    const stakeTx = StakeProgram.authorize({
      stakePubkey: stakeAcct,
      authorizedPubkey: auth,
      newAuthorizedPubkey: newAuth,
      stakeAuthorizationType: { index: 1 },
    });
    const sIx = stakeTx.instructions[0]!;
    const dStake = decodeInstruction(STAKE_PROGRAM_ID, sIx.keys.map((k) => k.pubkey.toBase58()), sIx.data);
    expect(dStake.name).toBe('Stake: Authorize');
    expect(dStake.params.authorityType).toBe('Withdrawer');
    expect(dStake.params.newAuthority).toBe(newAuth.toBase58());

    // Upgradeable Loader: SetAuthority (tag 4)
    const loaderData = new Uint8Array(4);
    writeU32LE(loaderData, 0, 4);
    const dLoader = decodeInstruction(
      BPF_UPGRADEABLE_LOADER_ID,
      [stakeAcct.toBase58(), auth.toBase58(), newAuth.toBase58()],
      loaderData,
    );
    expect(dLoader.name).toBe('Loader: SetAuthority');
    expect(dLoader.type).toBe('loader:setAuthority');
    expect(dLoader.params.newAuthority).toBe(newAuth.toBase58());

    // Upgradeable Loader: DeployWithMaxDataLen (tag 2)
    const deployData = new Uint8Array(12);
    writeU32LE(deployData, 0, 2);
    writeU64LE(deployData, 4, 81920n);
    const dDeploy = decodeInstruction(
      BPF_UPGRADEABLE_LOADER_ID,
      Array.from({ length: 8 }, () => randomPubkey().toBase58()),
      deployData,
    );
    expect(dDeploy.name).toBe('Loader: DeployWithMaxDataLen');
    expect(dDeploy.params.maxDataLen).toBe('81920');

    // Compute Budget: SetComputeUnitLimit & SetComputeUnitPrice
    const cuLimitIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 });
    const cuPriceIx = ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 250_000 });
    expect(decodeInstruction(cuLimitIx.programId.toBase58(), [], cuLimitIx.data)).toMatchObject({
      name: 'ComputeBudget: SetComputeUnitLimit',
      params: { units: '400000' },
    });
    expect(decodeInstruction(cuPriceIx.programId.toBase58(), [], cuPriceIx.data)).toMatchObject({
      name: 'ComputeBudget: SetComputeUnitPrice',
      params: { microLamports: '250000' },
    });

    // Associated Token Account: CreateIdempotent ([1])
    const dAta = decodeInstruction(
      ASSOCIATED_TOKEN_PROGRAM_ID,
      [auth.toBase58(), stakeAcct.toBase58(), auth.toBase58(), newAuth.toBase58()],
      new Uint8Array([1]),
    );
    expect(dAta.name).toBe('ATA: CreateIdempotent');
    expect(dAta.params.owner).toBe(auth.toBase58());

    // Memo v2 & v1
    const dMemo = decodeInstruction(MEMO_PROGRAM_ID, [], new TextEncoder().encode('Hello Solana'));
    expect(dMemo.name).toBe('Memo: Memo');
    expect(dMemo.params.text).toBe('Hello Solana');
    const dMemoBin = decodeInstruction(MEMO_V1_PROGRAM_ID, [], new Uint8Array([0xff, 0xfe]));
    expect(dMemoBin.params.bytes).toBe('2');

    // Known DEX vs Unknown vs Malformed
    const dJup = decodeInstruction(JUPITER_V6_PROGRAM_ID, [auth.toBase58()], new Uint8Array([1, 2, 3]));
    expect(dJup.name).toBe('Jupiter v6: Instruction');
    expect(dJup.type).toBe('known');

    const unknownProg = randomPubkey().toBase58();
    const dUnknown = decodeInstruction(unknownProg, [auth.toBase58()], new Uint8Array([9, 9]));
    expect(dUnknown.name).toBe('Unknown');
    expect(dUnknown.type).toBe('unknown');

    // Truncated System instruction does not throw
    const dMalformed = decodeInstruction(SYSTEM_PROGRAM_ID, [], new Uint8Array([2, 0]));
    expect(dMalformed.name).toBe('System: Unparseable');
  });
});

describe('createRpcClient JSON-RPC 2.0 client', () => {
  it('sends credential-less POST requests and handles RPC errors and timeouts', async () => {
    let capturedInit: RequestInit | undefined;
    const okFetch: typeof fetch = async (_input, init) => {
      capturedInit = init;
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: 12345 }), { status: 200 });
    };
    const client = createRpcClient('https://rpc.example.invalid', okFetch);
    const slot = await client.call<number>('getSlot', []);
    expect(slot).toBe(12345);
    expect(capturedInit?.credentials).toBe('omit');

    const errFetch: typeof fetch = async () =>
      new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32002, message: 'sim error' } }), {
        status: 200,
      });
    await expect(createRpcClient('https://rpc.example.invalid', errFetch).call('getSlot', [])).rejects.toThrow(
      RpcError,
    );

    const slowFetch: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
      });
    await expect(createRpcClient('https://rpc.example.invalid', slowFetch, 20).call('getSlot', [])).rejects.toThrow(
      /timeout/i,
    );
  });
});
