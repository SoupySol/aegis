/**
 * address-book.test.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Unit tests for clipboard-swap detection, lookalike (address
 *           poisoning) detection, and 300-entry MRU address book capping in
 *           src/background/address-book.ts.
 * ACCESS:   Pure functions only.
 * NEVER:    No network access, all addresses generated from random bytes.
 * ---------------------------------------------------------------------------
 */

import { base58 } from '@scure/base';
import { describe, expect, it, vi } from 'vitest';
import {
  MAX_RECENT_ADDRESSES,
  SWAP_WINDOW_MS,
  checkAddressLookalike,
  checkAddressSwap,
  evaluateAddressPaste,
  recordAddressCopied,
  upsertRecentAddress,
} from '../../src/background/address-book';

function randomAddress(): string {
  return base58.encode(crypto.getRandomValues(new Uint8Array(32)));
}

describe('address-book.ts — clipboard swap detection', () => {
  it('flags a different address pasted within the 2-minute window', () => {
    const addrA = randomAddress();
    const addrB = randomAddress();
    const t0 = 1_700_000_000_000;

    const res = checkAddressSwap(addrB, { address: addrA, copiedAt: t0 }, t0 + 45_000);
    expect(res).toEqual({ swapped: true, expected: addrA });
  });

  it('does NOT flag when the same copied address is pasted', () => {
    const addrA = randomAddress();
    const t0 = 1_700_000_000_000;

    const res = checkAddressSwap(addrA, { address: addrA, copiedAt: t0 }, t0 + 5_000);
    expect(res).toEqual({ swapped: false });
  });

  it('does NOT flag when more than 2 minutes have elapsed since copying', () => {
    const addrA = randomAddress();
    const addrB = randomAddress();
    const t0 = 1_700_000_000_000;

    const res = checkAddressSwap(
      addrB,
      { address: addrA, copiedAt: t0 },
      t0 + SWAP_WINDOW_MS + 1,
    );
    expect(res).toEqual({ swapped: false });
  });
});

describe('address-book.ts — lookalike (address poisoning) detection', () => {
  it('flags an address with identical case-sensitive first 4 and last 4 base58 chars but different body', () => {
    const known = '7xKp9mN2vQr4sLw8zBn5cDf3gHj6kLm9pQr2sTu49Qm4';
    const poisoned = '7xKpZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ9Qm4';

    const res = checkAddressLookalike(poisoned, [known]);
    expect(res).toEqual({ lookalike: true, expected: known });
  });

  it('does NOT flag an exact match that already exists in known addresses', () => {
    const known = '7xKp9mN2vQr4sLw8zBn5cDf3gHj6kLm9pQr2sTu49Qm4';
    const res = checkAddressLookalike(known, [known]);
    expect(res).toEqual({ lookalike: false });
  });

  it('is case-sensitive on base58 prefix/suffix and ignores non-matching addresses', () => {
    const known = '7xKp9mN2vQr4sLw8zBn5cDf3gHj6kLm9pQr2sTu49Qm4';
    const diffCase = '7XKP1111111111111111111111111111111111119qm4';
    const unrelated = randomAddress();

    expect(checkAddressLookalike(diffCase, [known])).toEqual({ lookalike: false });
    expect(checkAddressLookalike(unrelated, [known])).toEqual({ lookalike: false });
  });
});

describe('address-book.ts — 300-entry MRU cap & secret rejection', () => {
  it('caps recent addresses at 300 entries and moves re-used addresses to the front', () => {
    let list: string[] = [];
    const generated: string[] = [];
    for (let i = 0; i < 325; i++) {
      const addr = randomAddress();
      generated.push(addr);
      list = upsertRecentAddress(list, addr);
    }

    expect(list.length).toBe(MAX_RECENT_ADDRESSES);
    expect(list[0]).toBe(generated[324]);
    expect(list.includes(generated[0]!)).toBe(false);

    // Re-inserting an existing entry moves it to index 0 without duplicating
    const target = list[150]!;
    const updated = upsertRecentAddress(list, target);
    expect(updated.length).toBe(MAX_RECENT_ADDRESSES);
    expect(updated[0]).toBe(target);
    expect(updated.filter((x) => x === target).length).toBe(1);
  });

  it('never accepts 64-byte base58 secret-key-length strings into recent addresses', () => {
    const fake64ByteString = base58.encode(crypto.getRandomValues(new Uint8Array(64)));
    const list = upsertRecentAddress([], fake64ByteString);
    expect(list).toEqual([]);
  });
});

describe('address-book.ts — copy-then-paste of poisoned lookalike address', () => {
  it('triggers lookalike warning when copying a poisoned lookalike in-browser and then pasting it', async () => {
    const store: Record<string, unknown> = {};
    vi.stubGlobal('chrome', {
      storage: {
        local: {
          get: async (keys: string | string[]) => {
            if (typeof keys === 'string') return { [keys]: store[keys] };
            const out: Record<string, unknown> = {};
            for (const k of keys) out[k] = store[k];
            return out;
          },
          set: async (patch: Record<string, unknown>) => {
            Object.assign(store, patch);
          },
        },
      },
    });

    try {
      const known = '7xKp9mN2vQr4sLw8zBn5cDf3gHj6kLm9pQr2sTu49Qm4';
      const poisoned = '7xKpZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ9Qm4';
      const t0 = 1_700_000_000_000;

      // 1. User previously copied/used legitimate recipient `known`
      await recordAddressCopied(known, t0);
      expect(store.recentAddresses).toEqual([known]);

      // 2. Later, user copies `poisoned` lookalike from an explorer/activity page
      await recordAddressCopied(poisoned, t0 + 10_000);
      expect(store.recentAddresses).toEqual([known]);

      // 3. User pastes `poisoned`: must NOT be whitelisted; must trigger `lookalike` warning!
      const pasteRes = await evaluateAddressPaste(poisoned, t0 + 12_000);
      expect(pasteRes).toEqual({ warning: 'lookalike', expected: known });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
