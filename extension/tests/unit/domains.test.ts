/**
 * domains.test.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Unit tests for evaluateSite(), decodePunycodeLabel(), and
 *           normalizeSkeleton() in src/background/domains.ts.
 * ACCESS:   Pure functions only.
 * NEVER:    No network access, no real user data.
 * ---------------------------------------------------------------------------
 */

import { describe, expect, it } from 'vitest';
import {
  PROTECTED_BRANDS,
  decodePunycodeLabel,
  evaluateSite,
  normalizeSkeleton,
} from '../../src/background/domains';

describe('domains.ts — official domains & subdomains', () => {
  it('classifies every bundled official domain as official', () => {
    for (const entry of PROTECTED_BRANDS) {
      const res = evaluateSite(`https://${entry.domain}/swap`);
      expect(res.status, entry.domain).toBe('official');
      expect(res.brand).toBe(entry.brand);
    }
  });

  it('classifies subdomains of official domains as official', () => {
    const subdomains = [
      ['https://app.jup.ag', 'Jupiter'],
      ['https://station.jup.ag/docs', 'Jupiter'],
      ['https://v2.raydium.io/liquidity', 'Raydium'],
      ['https://trade.pump.fun', 'Pump.fun'],
      ['https://docs.phantom.app', 'Phantom'],
      ['https://api.helius.dev', 'Helius'],
      ['https://pro.birdeye.so', 'Birdeye'],
      ['https://bullx.io', 'BullX'],
    ] as const;

    for (const [url, expectedBrand] of subdomains) {
      const res = evaluateSite(url);
      expect(res.status, url).toBe('official');
      expect(res.brand).toBe(expectedBrand);
    }
  });
});

describe('domains.ts — typosquats & confusable digraphs (edit distance <= 2)', () => {
  it('flags visual digraph and character typosquats as lookalike', () => {
    const typosquats: Array<[string, string, string]> = [
      ['https://purnp.fun', 'Pump.fun', 'pump.fun'],
      ['https://raydiurn.io', 'Raydium', 'raydium.io'],
      ['https://phanlom.app', 'Phantom', 'phantom.app'],
      ['https://solflar.com', 'Solflare', 'solflare.com'],
      ['https://backpak.app', 'Backpack', 'backpack.app'],
      ['https://dexscreenr.com', 'DEX Screener', 'dexscreener.com'],
      ['https://magicedn.io', 'Magic Eden', 'magiceden.io'],
      ['https://mete0ra.ag', 'Meteora', 'meteora.ag'],
      ['https://solscann.io', 'Solscan', 'solscan.io'],
      ['https://phantom.com', 'Phantom', 'phantom.app'],
      ['https://jup.com', 'Jupiter', 'jup.ag'],
    ];

    for (const [url, expectedBrand, expectedOfficial] of typosquats) {
      const res = evaluateSite(url);
      expect(res.status, url).toBe('lookalike');
      expect(res.brand, url).toBe(expectedBrand);
      expect(res.officialDomain, url).toBe(expectedOfficial);
      expect(res.reason).toBeTruthy();
    }
  });
});

describe('domains.ts — punycode & Unicode IDN homographs', () => {
  it('decodes RFC 3492 punycode labels and normalizes confusable skeletons', () => {
    // URL parser converts Unicode IDNs into xn-- punycode labels automatically
    const cyrillicPhantomHost = new URL('https://\u0440hantom.app').hostname; // Cyrillic 'р'
    expect(cyrillicPhantomHost.startsWith('xn--')).toBe(true);
    const decoded = decodePunycodeLabel(cyrillicPhantomHost.split('.')[0]!);
    expect(normalizeSkeleton(decoded)).toBe('phantom');
  });

  it('flags punycode homographs of protected Solana brands as lookalike', () => {
    const idnUrls = [
      ['https://\u0440hantom.app', 'Phantom', 'phantom.app'], // Cyrillic р
      ['https://ph\u00e4ntom.app', 'Phantom', 'phantom.app'], // Latin ä
      ['https://p\u00fcmp.fun', 'Pump.fun', 'pump.fun'], // Latin ü
      ['https://r\u0430ydium.io', 'Raydium', 'raydium.io'], // Cyrillic а
      ['https://s\u043efl\u0430re.com', 'Solflare', 'solflare.com'], // Cyrillic о, а -> edit dist 1 to solflare
    ] as const;

    for (const [url, expectedBrand, expectedOfficial] of idnUrls) {
      const res = evaluateSite(url);
      expect(res.status, url).toBe('lookalike');
      expect(res.brand, url).toBe(expectedBrand);
      expect(res.officialDomain, url).toBe(expectedOfficial);
    }
  });
});

describe('domains.ts — brand + lure keyword phishing domains', () => {
  it('flags brand tokens paired with airdrop/claim/migrate/verify lure keywords', () => {
    const lures: Array<[string, string]> = [
      ['https://jup-airdrop-claim.com', 'Jupiter'],
      ['https://jupiter-rewards.xyz', 'Jupiter'],
      ['https://phantom-verify.org', 'Phantom'],
      ['https://claim-raydium.net', 'Raydium'],
      ['https://pump-bonus-drop.io', 'Pump.fun'],
      ['https://solflare-restore.app', 'Solflare'],
      ['https://backpacksupport.com', 'Backpack'],
      ['https://tensor-migrate.com', 'Tensor'],
    ];

    for (const [url, expectedBrand] of lures) {
      const res = evaluateSite(url);
      expect(res.status, url).toBe('lookalike');
      expect(res.brand, url).toBe(expectedBrand);
    }
  });
});

describe('domains.ts — unrelated unknown websites (no false positives)', () => {
  it('returns unknown for ordinary websites and localhost', () => {
    const benign = [
      'https://example.com',
      'https://github.com/solana-labs',
      'https://www.google.com',
      'https://en.wikipedia.org/wiki/Solana',
      'https://news.ycombinator.com',
      'https://cloudflare.com',
      'https://app.com',
      'https://map.com',
      'https://form.com',
      'http://127.0.0.1:8787',
      'http://localhost:3000',
    ];

    for (const url of benign) {
      const res = evaluateSite(url);
      expect(res.status, url).toBe('unknown');
    }
  });
});
