/**
 * message.test.ts
 * Unit tests for analyzeMessage: plain UTF-8 text, Sign-In With Solana (SIWS)
 * matching vs mismatching domain, disguised serialized transactions, and
 * unreadable binary messages.
 */
import { describe, expect, it } from 'vitest';
import {
  Keypair,
  SystemProgram,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
} from '@solana/web3.js';
import { analyzeMessage } from '../../../src/background/analysis';
import { BLOCKHASH, randomPubkey } from './helpers';

describe('analyzeMessage', () => {
  it('shows plain readable UTF-8 text as SAFE', () => {
    const text = 'Verify wallet ownership for Aegis Trade\nTimestamp: 1730000000';
    const report = analyzeMessage({
      origin: 'https://trade.example.com',
      method: 'signMessage',
      message: new TextEncoder().encode(text),
    });
    expect(report.kind).toBe('message');
    expect(report.severity).toBe('safe');
    expect(report.verdict).toBe('SAFE');
    expect(report.findings).toEqual([]);
    expect(report.message).toEqual({
      text,
      byteLength: new TextEncoder().encode(text).byteLength,
      isSignInWithSolana: false,
      looksLikeTransaction: false,
    });
  });

  it('accepts Sign-In With Solana (SIWS) when domain matches origin host (including port)', () => {
    const addr = randomPubkey().toBase58();
    const siws = [
      'localhost:5173 wants you to sign in with your Solana account:',
      addr,
      '',
      'Sign in to local dev portal.',
      '',
      'URI: http://localhost:5173',
      'Version: 1',
      'Nonce: 9f8e7d6c',
    ].join('\n');

    const report = analyzeMessage({
      origin: 'http://localhost:5173',
      method: 'signMessage',
      walletPubkey: addr,
      message: new TextEncoder().encode(siws),
    });
    expect(report.severity).toBe('safe');
    expect(report.verdict).toBe('SAFE');
    expect(report.message?.isSignInWithSolana).toBe(true);
    expect(report.message?.siwsDomain).toBe('localhost:5173');
    expect(report.findings).toEqual([]);
  });

  it('flags Sign-In With Solana (SIWS) domain mismatch as high / DANGER', () => {
    const addr = randomPubkey().toBase58();
    const siws = [
      'jup.ag wants you to sign in with your Solana account:',
      addr,
      '',
      'Claim reward.',
      'Nonce: abc12345',
    ].join('\n');

    const report = analyzeMessage({
      origin: 'https://jupiter-claim-bonus.example',
      method: 'signMessage',
      walletPubkey: addr,
      message: new TextEncoder().encode(siws),
    });
    expect(report.severity).toBe('high');
    expect(report.verdict).toBe('DANGER');
    expect(report.message?.isSignInWithSolana).toBe(true);
    expect(report.message?.siwsDomain).toBe('jup.ag');
    expect(report.findings.some((f) => f.id === 'siws-domain-mismatch')).toBe(true);
  });

  it('flags serialized legacy, bare message, and v0 transactions disguised as messages as critical / DANGER', () => {
    const victim = Keypair.generate();
    const attacker = randomPubkey();

    const legacyTx = new Transaction({
      feePayer: victim.publicKey,
      recentBlockhash: BLOCKHASH,
    }).add(
      SystemProgram.transfer({
        fromPubkey: victim.publicKey,
        toPubkey: attacker,
        lamports: 5_000_000_000,
      }),
    );

    const fullWire = legacyTx.serialize({ requireAllSignatures: false, verifySignatures: false });
    const bareMsg = new Uint8Array(legacyTx.serializeMessage());

    const v0Msg = new TransactionMessage({
      payerKey: victim.publicKey,
      recentBlockhash: BLOCKHASH,
      instructions: [
        SystemProgram.transfer({
          fromPubkey: victim.publicKey,
          toPubkey: attacker,
          lamports: 1_000_000_000,
        }),
      ],
    }).compileToV0Message();
    const v0Wire = new VersionedTransaction(v0Msg).serialize();

    for (const payload of [fullWire, bareMsg, v0Wire]) {
      const report = analyzeMessage({
        origin: 'https://phish.example',
        method: 'signMessage',
        walletPubkey: victim.publicKey.toBase58(),
        message: payload,
      });
      expect(report.severity).toBe('critical');
      expect(report.verdict).toBe('DANGER');
      expect(report.message?.looksLikeTransaction).toBe(true);
      expect(report.message?.text).toBeUndefined();
      expect(report.findings.some((f) => f.id === 'message-is-transaction')).toBe(true);
    }
  });

  it('flags unreadable binary bytes as medium / CAUTION', () => {
    const invalidUtf8 = new Uint8Array([0xff, 0xfe, 0x80, 0x99, 0x00, 0x42]);
    const controlBinary = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x07, 0x1b]);

    for (const bytes of [invalidUtf8, controlBinary]) {
      const report = analyzeMessage({
        origin: 'https://app.example.com',
        method: 'signMessage',
        message: bytes,
      });
      expect(report.severity).toBe('medium');
      expect(report.verdict).toBe('CAUTION');
      expect(report.message?.text).toBeUndefined();
      expect(report.message?.looksLikeTransaction).toBe(false);
      expect(report.findings.some((f) => f.id === 'binary-message')).toBe(true);
    }
  });
});
