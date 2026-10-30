/**
 * secret-detector.test.ts
 * All keys and seed phrases here are generated at test time from random bytes.
 * They are throwaway test values and never belong to a real wallet.
 */
import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { base58, hex } from '@scure/base';
import { generateMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist as english } from '@scure/bip39/wordlists/english';
import { containsConfirmedSecret, detectSecrets } from '../../src/shared/detectors/secret-detector';
import { fingerprint, resetSessionKeyForTests } from '../../src/shared/detectors/fingerprint';

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function makeTestKeypair(): { secret: Uint8Array; pub: Uint8Array } {
  const seed = randomBytes(32);
  const pub = ed25519.getPublicKey(seed);
  const secret = new Uint8Array(64);
  secret.set(seed, 0);
  secret.set(pub, 32);
  return { secret, pub };
}

const shortOf = (pub: Uint8Array) => {
  const s = base58.encode(pub);
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
};

const N = 300;

describe('secret keys are detected in every format', () => {
  it('base58 (wallet export format)', () => {
    for (let i = 0; i < N; i++) {
      const { secret, pub } = makeTestKeypair();
      const r = detectSecrets(base58.encode(secret));
      expect(r.findings).toEqual([{ kind: 'solana-secret-key', format: 'base58', publicKeyShort: shortOf(pub) }]);
    }
  });

  it('JSON byte array (solana-keygen id.json)', () => {
    for (let i = 0; i < 50; i++) {
      const { secret } = makeTestKeypair();
      const r = detectSecrets(JSON.stringify(Array.from(secret)));
      expect(r.findings[0]?.format).toBe('json-array');
    }
  });

  it('JSON byte array with spaces and newlines', () => {
    const { secret } = makeTestKeypair();
    const pretty = `[\n  ${Array.from(secret).join(',\n  ')}\n]`;
    expect(detectSecrets(pretty).findings[0]?.kind).toBe('solana-secret-key');
  });

  it('hex (lowercase, uppercase, 0x prefix)', () => {
    const { secret } = makeTestKeypair();
    const h = hex.encode(secret);
    expect(detectSecrets(h).findings[0]?.format).toBe('hex');
    expect(detectSecrets(h.toUpperCase()).findings[0]?.format).toBe('hex');
    expect(detectSecrets(`0x${h}`).findings[0]?.format).toBe('hex');
  });

  it('embedded inside a .env file', () => {
    const { secret } = makeTestKeypair();
    const env = `RPC_URL=https://example.invalid\nPRIVATE_KEY=${base58.encode(secret)}\nFEE_BPS=200\n`;
    const r = detectSecrets(env);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]?.kind).toBe('solana-secret-key');
  });

  it('multiple different keys in one text', () => {
    const a = makeTestKeypair();
    const b = makeTestKeypair();
    const r = detectSecrets(`wallet1: ${base58.encode(a.secret)}\nwallet2: ${base58.encode(b.secret)}`);
    expect(r.findings).toHaveLength(2);
  });
});

describe('no false positives on public, non-secret values', () => {
  const knownAddresses = [
    'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
    'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
    'So11111111111111111111111111111111111111112',
    '11111111111111111111111111111111',
    'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
    'ComputeBudget111111111111111111111111111111',
  ];

  it('known program / mint addresses', () => {
    for (const a of knownAddresses) expect(detectSecrets(a).findings).toEqual([]);
  });

  it('random wallet / token addresses (32 bytes), incl. pump.fun-style suffix text', () => {
    for (let i = 0; i < N; i++) {
      const addr = base58.encode(randomBytes(32));
      expect(detectSecrets(addr).findings).toEqual([]);
      expect(detectSecrets(`CA: ${addr}pump`).findings).toEqual([]);
    }
  });

  it('real ed25519 transaction-style signatures (64 bytes)', () => {
    for (let i = 0; i < N; i++) {
      const { secret } = makeTestKeypair();
      const sig = ed25519.sign(randomBytes(100), secret.slice(0, 32));
      expect(detectSecrets(base58.encode(sig)).findings).toEqual([]);
      expect(detectSecrets(`https://solscan.io/tx/${base58.encode(sig)}`).findings).toEqual([]);
    }
  });

  it('random 64-byte values in every encoding', () => {
    for (let i = 0; i < N; i++) {
      const b = randomBytes(64);
      expect(detectSecrets(base58.encode(b)).findings).toEqual([]);
      expect(detectSecrets(hex.encode(b)).findings).toEqual([]);
      expect(detectSecrets(JSON.stringify(Array.from(b))).findings).toEqual([]);
    }
  });

  it('a 64-byte value whose halves are swapped (pub || seed)', () => {
    const { secret } = makeTestKeypair();
    const swapped = new Uint8Array(64);
    swapped.set(secret.slice(32), 0);
    swapped.set(secret.slice(0, 32), 32);
    expect(detectSecrets(base58.encode(swapped)).findings).toEqual([]);
  });

  it('normal English text and trading chatter', () => {
    const samples = [
      'Just aped into this new coin, chart looks clean and the dev seems based. Lets see if it bonds today.',
      'The quick brown fox jumps over the lazy dog while the market moves sideways for the whole afternoon.',
      'Remember to check the contract address before buying and never share your wallet recovery details.',
      'about above absent absorb abstract absurd abuse access accident account accuse achieve acid',
    ];
    for (const s of samples) expect(containsConfirmedSecret(detectSecrets(s))).toBe(false);
  });
});

describe('seed phrases', () => {
  it('detects valid 12 and 24 word phrases', () => {
    for (let i = 0; i < 100; i++) {
      const m12 = generateMnemonic(english, 128);
      const m24 = generateMnemonic(english, 256);
      expect(detectSecrets(m12).findings).toEqual([{ kind: 'seed-phrase', format: 'mnemonic', wordCount: 12 }]);
      expect(detectSecrets(m24).findings).toEqual([{ kind: 'seed-phrase', format: 'mnemonic', wordCount: 24 }]);
    }
  });

  it('detects 15, 18 and 21 word phrases', () => {
    for (const [bits, words] of [[160, 15], [192, 18], [224, 21]] as const) {
      const m = generateMnemonic(english, bits);
      expect(detectSecrets(m).findings[0]).toEqual({ kind: 'seed-phrase', format: 'mnemonic', wordCount: words });
    }
  });

  it('handles numbered lists, commas, newlines and uppercase', () => {
    const words = generateMnemonic(english, 128).split(' ');
    const numbered = words.map((w, i) => `${i + 1}. ${w}`).join('\n');
    const commas = words.join(', ');
    const upper = words.join(' ').toUpperCase();
    for (const t of [numbered, commas, upper]) expect(detectSecrets(t).findings[0]?.kind).toBe('seed-phrase');
  });

  it('detects a phrase embedded in a note', () => {
    const m = generateMnemonic(english, 128);
    const r = detectSecrets(`backup for my main wallet:\n${m}\ndo not lose`);
    expect(r.findings.some((f) => f.kind === 'seed-phrase')).toBe(true);
  });

  it('reports a 12-word phrase with a bad checksum only as "possible"', () => {
    let phrase = '';
    do {
      phrase = Array.from({ length: 12 }, () => english[Math.floor(Math.random() * english.length)]).join(' ');
    } while (validateMnemonic(phrase, english));
    const r = detectSecrets(phrase);
    expect(r.findings).toEqual([{ kind: 'possible-seed-phrase', format: 'mnemonic', wordCount: 12 }]);
    expect(containsConfirmedSecret(r)).toBe(false);
  });

  it('does not flag an 11-word fragment', () => {
    const words = generateMnemonic(english, 128).split(' ').slice(0, 11).join(' ');
    expect(detectSecrets(words).findings).toEqual([]);
  });
});

describe('opsec guarantees', () => {
  it('results never contain the secret material', () => {
    const { secret } = makeTestKeypair();
    const keyText = base58.encode(secret);
    const seed = generateMnemonic(english, 128);
    const serialized = JSON.stringify(detectSecrets(`${keyText}\n${seed}`));
    expect(serialized).not.toContain(keyText);
    expect(serialized).not.toContain(keyText.slice(0, 20));
    for (const word of seed.split(' ')) expect(serialized).not.toContain(` ${word} `);
  });

  it('respects maxLength and reports truncation', () => {
    const r = detectSecrets('a'.repeat(100), { maxLength: 10 });
    expect(r.truncated).toBe(true);
  });

  it('fingerprints are stable within a session and change across sessions', async () => {
    resetSessionKeyForTests();
    const a1 = await fingerprint('same text');
    const a2 = await fingerprint('same text');
    expect(a1).toBe(a2);
    expect(a1).not.toContain('same');
    resetSessionKeyForTests();
    const b = await fingerprint('same text');
    expect(b).not.toBe(a1);
  });
});

