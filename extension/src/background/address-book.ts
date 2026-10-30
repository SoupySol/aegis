/**
 * address-book.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Detects two common Solana address-paste hazards locally:
 *           1) Clipboard-swap malware: user copies address A and pastes
 *              address B within 2 minutes.
 *           2) Address poisoning / lookalikes: pasted address matches the
 *              first 4 and last 4 case-sensitive base58 characters of a
 *              previously used address, while differing in the middle.
 * ACCESS:   chrome.storage.local (stores up to 300 public Solana addresses and
 *           the most recently copied public address + timestamp).
 * NEVER:    Never stores secrets, private keys, or seed phrases (strictly
 *           gated by looksLikeAddress()). No network access.
 * ---------------------------------------------------------------------------
 */

import { looksLikeAddress } from '../shared/prefilter';
import type { AddressPastedResponse } from '../shared/messages';

export const SWAP_WINDOW_MS = 2 * 60 * 1000; // 2 minutes
export const MAX_RECENT_ADDRESSES = 300;

const RECENT_ADDRESSES_KEY = 'recentAddresses';
const LAST_COPIED_KEY = 'lastCopiedAddress';

export interface CopiedAddressRecord {
  address: string;
  copiedAt: number;
}

/**
 * Pure check: detects when an address pasted within 2 minutes of copying an
 * address does not match the copied address (clipboard-hijack signature).
 */
export function checkAddressSwap(
  pasted: string,
  lastCopied: CopiedAddressRecord | null | undefined,
  now = Date.now(),
): { swapped: boolean; expected?: string } {
  const cleanPasted = pasted.trim();
  if (!lastCopied || !looksLikeAddress(cleanPasted) || !looksLikeAddress(lastCopied.address)) {
    return { swapped: false };
  }
  const cleanCopied = lastCopied.address.trim();
  const age = now - lastCopied.copiedAt;
  if (age < 0 || age > SWAP_WINDOW_MS) {
    return { swapped: false };
  }
  if (cleanPasted === cleanCopied) {
    return { swapped: false };
  }
  return { swapped: true, expected: cleanCopied };
}

/**
 * Pure check: detects address-poisoning lookalikes sharing the same first 4
 * and last 4 case-sensitive base58 characters as a known address, while
 * having different full text.
 */
export function checkAddressLookalike(
  pasted: string,
  knownAddresses: readonly string[],
): { lookalike: boolean; expected?: string } {
  const cleanPasted = pasted.trim();
  if (!looksLikeAddress(cleanPasted) || cleanPasted.length < 32) {
    return { lookalike: false };
  }
  // Exact match to an already-known address is safe.
  if (knownAddresses.includes(cleanPasted)) {
    return { lookalike: false };
  }

  const prefix = cleanPasted.slice(0, 4);
  const suffix = cleanPasted.slice(-4);
  for (const rawKnown of knownAddresses) {
    const known = rawKnown.trim();
    if (known.length < 32 || known === cleanPasted) continue;
    if (known.slice(0, 4) === prefix && known.slice(-4) === suffix) {
      return { lookalike: true, expected: known };
    }
  }
  return { lookalike: false };
}

/**
 * Pure helper: inserts a public Solana address at the front of the MRU list,
 * deduplicating and capping at `max` entries (default 300).
 */
export function upsertRecentAddress(
  existing: readonly string[],
  address: string,
  max = MAX_RECENT_ADDRESSES,
): string[] {
  const clean = address.trim();
  // AEGIS-SECURITY: refuse anything that is not a 32-44 char base58 public address.
  if (!looksLikeAddress(clean)) {
    return existing.slice(0, max);
  }
  const filtered = existing.filter((a) => a !== clean);
  return [clean, ...filtered].slice(0, max);
}

export async function recordAddressCopied(address: string, now = Date.now()): Promise<void> {
  const clean = address.trim();
  if (!looksLikeAddress(clean)) return;

  // AEGIS-PERMISSION: stores public Solana addresses locally for swap/lookalike comparison.
  const stored = (await chrome.storage.local.get(RECENT_ADDRESSES_KEY)) as {
    recentAddresses?: unknown;
  };
  const current = Array.isArray(stored.recentAddresses)
    ? stored.recentAddresses.filter((x): x is string => typeof x === 'string')
    : [];

  // AEGIS-SECURITY: do not whitelist a lookalike of an already-known address on copy,
  // so copying a poisoned address from an explorer/webpage still triggers the lookalike warning on paste.
  const isLookalike = checkAddressLookalike(clean, current).lookalike;
  const nextRecent = isLookalike ? current : upsertRecentAddress(current, clean, MAX_RECENT_ADDRESSES);
  const lastCopied: CopiedAddressRecord = { address: clean, copiedAt: now };

  await chrome.storage.local.set({
    [RECENT_ADDRESSES_KEY]: nextRecent,
    [LAST_COPIED_KEY]: lastCopied,
  });
}

export async function evaluateAddressPaste(
  address: string,
  now = Date.now(),
): Promise<AddressPastedResponse> {
  const clean = address.trim();
  if (!looksLikeAddress(clean)) return {};

  const stored = (await chrome.storage.local.get([RECENT_ADDRESSES_KEY, LAST_COPIED_KEY])) as {
    recentAddresses?: unknown;
    lastCopiedAddress?: CopiedAddressRecord | null;
  };
  const recent = Array.isArray(stored.recentAddresses)
    ? stored.recentAddresses.filter((x): x is string => typeof x === 'string')
    : [];
  const lastCopied = stored.lastCopiedAddress ?? null;

  const swap = checkAddressSwap(clean, lastCopied, now);
  if (swap.swapped) {
    // AEGIS-SECURITY: do not add suspected clipper address to the user's known-good list.
    return { warning: 'clipboard-swap', expected: swap.expected };
  }

  const lookalike = checkAddressLookalike(clean, recent);
  if (lookalike.lookalike) {
    return { warning: 'lookalike', expected: lookalike.expected };
  }

  const nextRecent = upsertRecentAddress(recent, clean, MAX_RECENT_ADDRESSES);
  await chrome.storage.local.set({ [RECENT_ADDRESSES_KEY]: nextRecent });
  return {};
}
