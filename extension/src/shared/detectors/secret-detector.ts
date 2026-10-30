/**
 * secret-detector.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Detects Solana secret keys and BIP-39 seed phrases inside a piece
 *           of text (clipboard content, a pasted value, a file's contents).
 *
 * ACCESS:   Pure functions. Receives a string, returns a verdict.
 *
 * NEVER:    - No network access. No storage. No logging.
 *           - The returned result NEVER contains the secret itself. It only
 *             contains the kind of secret, its format, and (for secret keys)
 *             a shortened PUBLIC key, which is not sensitive.
 *           - Seed phrases are NEVER converted into addresses or keys.
 *
 * HOW FALSE POSITIVES ARE AVOIDED:
 *   - Wallet addresses / token contract addresses (incl. pump.fun CAs) are
 *     32 bytes. They are never treated as secrets.
 *   - A Solana secret key is 64 bytes: [32-byte seed][32-byte public key].
 *     We only flag 64-byte values whose second half is the ed25519 public key
 *     of the first half. Transaction signatures (also 64 bytes) fail this.
 *   - Seed phrases must be 12/15/18/21/24 consecutive BIP-39 words with a
 *     valid checksum. A same-length run with a bad checksum is only reported
 *     as "possible" when it makes up essentially the whole input.
 * ---------------------------------------------------------------------------
 */

import { ed25519 } from '@noble/curves/ed25519';
import { base58, hex } from '@scure/base';
import { validateMnemonic } from '@scure/bip39';
import { wordlist as english } from '@scure/bip39/wordlists/english';

export type SecretKind = 'solana-secret-key' | 'seed-phrase' | 'possible-seed-phrase';
export type SecretFormat = 'base58' | 'json-array' | 'hex' | 'mnemonic';

export interface SecretFinding {
  kind: SecretKind;
  format: SecretFormat;
  /** Seed phrases only: number of words. */
  wordCount?: number;
  /** Secret keys only: shortened PUBLIC key, e.g. "7xKp…9Qm4" (not sensitive). */
  publicKeyShort?: string;
}

export interface DetectionResult {
  findings: SecretFinding[];
  /** True when the input was longer than maxLength and only the start was scanned. */
  truncated: boolean;
}

export interface DetectOptions {
  /** Maximum number of characters to scan. Default 50,000. */
  maxLength?: number;
}

const DEFAULT_MAX_LENGTH = 50_000;
const VALID_MNEMONIC_SIZES = [24, 21, 18, 15, 12] as const;
const BIP39_SET: ReadonlySet<string> = new Set(english);

// Base58 alphabet (Bitcoin/Solana). A 64-byte value normally encodes to 86-88
// chars (down to ~72 chars when leading 0x00 seed bytes become '1's); lengths
// and ed25519 public-key derivation are strictly verified after decoding.
const B58 = '1-9A-HJ-NP-Za-km-z';
const BASE58_RUN = new RegExp(`(?<![${B58}])[${B58}]{72,90}(?![${B58}])`, 'g');
// 64 comma-separated integers inside brackets (solana-keygen id.json format).
const JSON_ARRAY_64 = /\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/g;
// 128 hex characters (optionally 0x-prefixed), not part of a longer hex run.
const HEX_128 = /(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{128})(?![0-9a-fA-F])/g;

/** Shorten a public key for display: first 4 + "…" + last 4. */
function shortKey(pubkey: Uint8Array): string {
  const s = base58.encode(pubkey);
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

/**
 * Returns the public key if `bytes` is a genuine Solana secret key
 * (64 bytes where bytes[32..64] == ed25519 public key of bytes[0..32]).
 * Returns null otherwise.
 *
 * AEGIS-SECURITY: works on a private copy and wipes it before returning.
 */
export function verifySolanaSecretKey(bytes: Uint8Array): Uint8Array | null {
  if (bytes.length !== 64) return null;
  const seed = bytes.slice(0, 32);
  const claimedPub = bytes.slice(32, 64);
  try {
    const derived = ed25519.getPublicKey(seed);
    let diff = 0;
    for (let i = 0; i < 32; i++) diff |= (derived[i] ?? 0) ^ (claimedPub[i] ?? 0);
    return diff === 0 ? claimedPub : null;
  } catch {
    return null;
  } finally {
    seed.fill(0); // AEGIS-SECURITY: wipe the seed copy from memory
  }
}

function tryBase58(candidate: string): Uint8Array | null {
  try {
    return base58.decode(candidate);
  } catch {
    return null;
  }
}

function detectSecretKeys(text: string, out: SecretFinding[]): void {
  const seen = new Set<string>();
  const push = (pub: Uint8Array, format: SecretFormat) => {
    const short = shortKey(pub);
    const id = `${format}:${short}`;
    if (seen.has(id)) return;
    seen.add(id);
    out.push({ kind: 'solana-secret-key', format, publicKeyShort: short });
  };

  for (const m of text.matchAll(BASE58_RUN)) {
    const bytes = tryBase58(m[0]);
    if (!bytes) continue;
    const pub = verifySolanaSecretKey(bytes);
    bytes.fill(0);
    if (pub) push(pub, 'base58');
  }

  for (const m of text.matchAll(JSON_ARRAY_64)) {
    const nums = m[0].slice(1, -1).split(',').map((n) => Number(n.trim()));
    if (nums.length !== 64 || nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) continue;
    const bytes = Uint8Array.from(nums);
    const pub = verifySolanaSecretKey(bytes);
    bytes.fill(0);
    nums.fill(0);
    if (pub) push(pub, 'json-array');
  }

  for (const m of text.matchAll(HEX_128)) {
    const hexStr = m[1];
    if (!hexStr) continue;
    let bytes: Uint8Array;
    try {
      bytes = hex.decode(hexStr.toLowerCase());
    } catch {
      continue;
    }
    const pub = verifySolanaSecretKey(bytes);
    bytes.fill(0);
    if (pub) push(pub, 'hex');
  }
}

/**
 * Splits text into lowercase alphabetic words. Numbers and punctuation act as
 * separators, so "1. abandon 2. ability" and "abandon, ability" both work.
 */
function tokenizeWords(text: string): string[] {
  return text.toLowerCase().match(/[a-z]+/g) ?? [];
}

function detectSeedPhrases(text: string, out: SecretFinding[]): void {
  const words = tokenizeWords(text);
  if (words.length < 12) return;

  // Find maximal runs of consecutive BIP-39 words.
  const runs: Array<[number, number]> = [];
  let start = -1;
  for (let i = 0; i <= words.length; i++) {
    const isWord = i < words.length && BIP39_SET.has(words[i] as string);
    if (isWord && start === -1) start = i;
    if (!isWord && start !== -1) {
      if (i - start >= 12) runs.push([start, i]);
      start = -1;
    }
  }

  for (const [runStart, runEnd] of runs) {
    let i = runStart;
    let foundInRun = false;
    while (i + 12 <= runEnd) {
      let matched = 0;
      for (const size of VALID_MNEMONIC_SIZES) {
        if (i + size > runEnd) continue;
        const phrase = words.slice(i, i + size).join(' ');
        if (validateMnemonic(phrase, english)) {
          matched = size;
          break;
        }
      }
      if (matched > 0) {
        out.push({ kind: 'seed-phrase', format: 'mnemonic', wordCount: matched });
        foundInRun = true;
        i += matched;
      } else {
        i += 1;
      }
    }

    // Soft signal: the run has a valid mnemonic length, makes up (almost) the
    // whole input, but its checksum fails, e.g. a seed phrase with a typo.
    const runLength = runEnd - runStart;
    const coversInput = runLength >= words.length - 1;
    if (!foundInRun && coversInput && (VALID_MNEMONIC_SIZES as readonly number[]).includes(runLength)) {
      out.push({ kind: 'possible-seed-phrase', format: 'mnemonic', wordCount: runLength });
    }
  }
}

/**
 * Scans text for Solana secret keys and seed phrases.
 * The result never contains the secret itself.
 */
export function detectSecrets(input: string, options: DetectOptions = {}): DetectionResult {
  const maxLength = options.maxLength ?? DEFAULT_MAX_LENGTH;
  const truncated = input.length > maxLength;
  const text = truncated ? input.slice(0, maxLength) : input;

  const findings: SecretFinding[] = [];
  detectSecretKeys(text, findings);
  detectSeedPhrases(text, findings);
  return { findings, truncated };
}

/** Convenience: true when at least one confirmed (non-"possible") secret is present. */
export function containsConfirmedSecret(result: DetectionResult): boolean {
  return result.findings.some((f) => f.kind !== 'possible-seed-phrase');
}

