/**
 * domains.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Evaluates website origins/URLs against bundled official Solana
 *           app domains and detects typosquats, punycode/Unicode homograph
 *           lookalikes, and brand + lure-keyword phishing domains.
 * ACCESS:   Pure string evaluation only (zero Chrome permissions, zero storage).
 * NEVER:    No network requests. Never logs or stores browsing URLs.
 * ---------------------------------------------------------------------------
 */

import type { SiteInfo } from '../shared/messages';

export interface ProtectedBrand {
  domain: string;
  brand: string;
  /** Primary registrable label of the official domain (e.g. "phantom", "pump"). */
  registrableLabel: string;
  /** Official TLD / public suffix (e.g. "app", "fun", "ag"). */
  tld: string;
  /** Brand tokens matched against hyphenated/compound lure domains. */
  tokens: readonly string[];
  /** Apex domain if official domain is a subdomain (e.g. bullx.io for neo.bullx.io). */
  allowedApex?: string;
}

export const PROTECTED_BRANDS: readonly ProtectedBrand[] = [
  { domain: 'pump.fun', brand: 'Pump.fun', registrableLabel: 'pump', tld: 'fun', tokens: ['pump', 'pumpfun'] },
  { domain: 'raydium.io', brand: 'Raydium', registrableLabel: 'raydium', tld: 'io', tokens: ['raydium'] },
  { domain: 'jup.ag', brand: 'Jupiter', registrableLabel: 'jup', tld: 'ag', tokens: ['jup', 'jupiter'] },
  { domain: 'phantom.app', brand: 'Phantom', registrableLabel: 'phantom', tld: 'app', tokens: ['phantom'] },
  { domain: 'solflare.com', brand: 'Solflare', registrableLabel: 'solflare', tld: 'com', tokens: ['solflare'] },
  { domain: 'backpack.app', brand: 'Backpack', registrableLabel: 'backpack', tld: 'app', tokens: ['backpack'] },
  { domain: 'axiom.trade', brand: 'Axiom', registrableLabel: 'axiom', tld: 'trade', tokens: ['axiom'] },
  {
    domain: 'photon-sol.tinyastro.io',
    brand: 'Photon',
    registrableLabel: 'photon-sol',
    tld: 'io',
    tokens: ['photonsol', 'tinyastro'],
    allowedApex: 'tinyastro.io',
  },
  {
    domain: 'neo.bullx.io',
    brand: 'BullX',
    registrableLabel: 'bullx',
    tld: 'io',
    tokens: ['bullx'],
    allowedApex: 'bullx.io',
  },
  { domain: 'gmgn.ai', brand: 'GMGN', registrableLabel: 'gmgn', tld: 'ai', tokens: ['gmgn'] },
  { domain: 'dexscreener.com', brand: 'DEX Screener', registrableLabel: 'dexscreener', tld: 'com', tokens: ['dexscreener'] },
  { domain: 'birdeye.so', brand: 'Birdeye', registrableLabel: 'birdeye', tld: 'so', tokens: ['birdeye'] },
  { domain: 'meteora.ag', brand: 'Meteora', registrableLabel: 'meteora', tld: 'ag', tokens: ['meteora'] },
  { domain: 'orca.so', brand: 'Orca', registrableLabel: 'orca', tld: 'so', tokens: ['orca'] },
  { domain: 'magiceden.io', brand: 'Magic Eden', registrableLabel: 'magiceden', tld: 'io', tokens: ['magiceden'] },
  { domain: 'tensor.trade', brand: 'Tensor', registrableLabel: 'tensor', tld: 'trade', tokens: ['tensor'] },
  { domain: 'solscan.io', brand: 'Solscan', registrableLabel: 'solscan', tld: 'io', tokens: ['solscan'] },
  { domain: 'helius.dev', brand: 'Helius', registrableLabel: 'helius', tld: 'dev', tokens: ['helius'] },
  { domain: 'solana.com', brand: 'Solana', registrableLabel: 'solana', tld: 'com', tokens: ['solana'] },
  { domain: 'kamino.finance', brand: 'Kamino', registrableLabel: 'kamino', tld: 'finance', tokens: ['kamino'] },
  { domain: 'marginfi.com', brand: 'marginfi', registrableLabel: 'marginfi', tld: 'com', tokens: ['marginfi'] },
  { domain: 'drift.trade', brand: 'Drift', registrableLabel: 'drift', tld: 'trade', tokens: ['drift'] },
  { domain: 'sanctum.so', brand: 'Sanctum', registrableLabel: 'sanctum', tld: 'so', tokens: ['sanctum'] },
  { domain: 'jito.wtf', brand: 'Jito', registrableLabel: 'jito', tld: 'wtf', tokens: ['jito'] },
  { domain: 'marinade.finance', brand: 'Marinade', registrableLabel: 'marinade', tld: 'finance', tokens: ['marinade'] },
  { domain: 'moonshot.cc', brand: 'Moonshot', registrableLabel: 'moonshot', tld: 'cc', tokens: ['moonshot'] },
];

const LURE_KEYWORDS = new Set([
  'claim',
  'claims',
  'airdrop',
  'airdrops',
  'reward',
  'rewards',
  'migrate',
  'migration',
  'validate',
  'validator',
  'bonus',
  'restore',
  'verify',
  'verification',
  'sync',
  'support',
  'recovery',
  'giveaway',
  'allocation',
  'checker',
]);

const MULTI_PART_TLDS = new Set([
  'co.uk',
  'org.uk',
  'com.au',
  'net.au',
  'co.jp',
  'co.kr',
  'com.br',
  'com.sg',
]);

const CONFUSABLE_CHAR_MAP: Readonly<Record<string, string>> = {
  // Cyrillic homographs
  '\u0430': 'a',
  '\u0432': 'b',
  '\u0435': 'e',
  '\u0456': 'i',
  '\u0457': 'i',
  '\u0458': 'j',
  '\u043a': 'k',
  '\u043c': 'm',
  '\u043d': 'h',
  '\u043e': 'o',
  '\u0440': 'p',
  '\u0441': 'c',
  '\u0442': 't',
  '\u0443': 'y',
  '\u0445': 'x',
  '\u0455': 's',
  '\u0501': 'd',
  '\u051b': 'q',
  '\u051d': 'w',
  // Greek homographs
  '\u03b1': 'a',
  '\u03b2': 'b',
  '\u03b5': 'e',
  '\u03b9': 'i',
  '\u03ba': 'k',
  '\u03bd': 'v',
  '\u03bf': 'o',
  '\u03c1': 'p',
  '\u03c4': 't',
  '\u03c5': 'u',
  '\u03c7': 'x',
  // Latin special letters & digit substitutions
  '\u0131': 'i',
  '\u0142': 'l',
  '\u00f8': 'o',
  '\u00df': 'ss',
  '0': 'o',
  '1': 'l',
};

/** RFC 3492 Punycode label decoder ("xn--..." -> Unicode string). */
export function decodePunycodeLabel(label: string): string {
  const lower = label.toLowerCase();
  if (!lower.startsWith('xn--')) return lower;
  const input = lower.slice(4);
  const delim = input.lastIndexOf('-');
  const output: number[] = [];

  if (delim > 0) {
    for (let j = 0; j < delim; j++) {
      output.push(input.charCodeAt(j));
    }
  }

  let n = 128;
  let i = 0;
  let bias = 72;
  let pos = delim >= 0 ? delim + 1 : 0;

  const adapt = (delta: number, numPoints: number, firstTime: boolean): number => {
    let d = firstTime ? Math.floor(delta / 700) : delta >> 1;
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > 455) {
      d = Math.floor(d / 35);
      k += 36;
    }
    return k + Math.floor((36 * d) / (d + 38));
  };

  while (pos < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = 36; ; k += 36) {
      if (pos >= input.length) return lower;
      const cp = input.charCodeAt(pos++);
      const digit = cp >= 48 && cp <= 57 ? cp - 22 : cp >= 97 && cp <= 122 ? cp - 97 : 36;
      if (digit >= 36) return lower;
      i += digit * w;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) break;
      w *= 36 - t;
    }
    const outLen = output.length + 1;
    bias = adapt(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    output.splice(i, 0, n);
    i++;
  }

  try {
    return String.fromCodePoint(...output);
  } catch {
    return lower;
  }
}

/** Normalizes accents, Unicode confusables, and multi-letter visual lookalikes (rn->m, vv->w). */
export function normalizeSkeleton(raw: string, collapseDigraphs = false): string {
  const stripped = raw.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  let out = '';
  for (const ch of stripped) {
    out += CONFUSABLE_CHAR_MAP[ch] ?? ch;
  }
  if (collapseDigraphs) {
    out = out.replace(/rn/g, 'm').replace(/vv/g, 'w');
  }
  return out;
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  if (Math.abs(a.length - b.length) > 4) return Math.abs(a.length - b.length);

  const prev = new Array<number>(b.length + 1);
  const curr = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      curr[j] = Math.min(
        (prev[j] ?? i) + 1,
        (curr[j - 1] ?? j) + 1,
        (prev[j - 1] ?? 0) + cost,
      );
    }
    for (let j = 0; j <= b.length; j++) prev[j] = curr[j]!;
  }
  return prev[b.length] ?? 0;
}

export function extractHostname(urlOrOrigin: string): string | null {
  const trimmed = urlOrOrigin.trim();
  if (!trimmed) return null;
  try {
    const parsed = trimmed.includes('://') ? new URL(trimmed) : new URL(`https://${trimmed}`);
    const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
    return host || null;
  } catch {
    return null;
  }
}

function splitRegistrable(hostname: string): { registrable: string; tld: string; nonTldLabels: string[] } {
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length < 2) {
    return { registrable: hostname, tld: '', nonTldLabels: parts };
  }
  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (parts.length >= 3 && MULTI_PART_TLDS.has(lastTwo)) {
    return {
      registrable: parts[parts.length - 3]!,
      tld: lastTwo,
      nonTldLabels: parts.slice(0, -2),
    };
  }
  return {
    registrable: parts[parts.length - 2]!,
    tld: parts[parts.length - 1]!,
    nonTldLabels: parts.slice(0, -1),
  };
}

function hasMixedUnicodeAndAscii(decoded: string): boolean {
  let hasAsciiLetter = false;
  let hasNonAscii = false;
  for (const ch of decoded) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp >= 97 && cp <= 122) hasAsciiLetter = true;
    else if (cp > 127) hasNonAscii = true;
  }
  return hasAsciiLetter && hasNonAscii;
}

function containsLureWithBrand(nonTldLabels: string[], brand: ProtectedBrand): string | null {
  const rawJoined = nonTldLabels.map((l) => normalizeSkeleton(decodePunycodeLabel(l), false)).join('.');
  const segments = rawJoined.split(/[._-]+/).filter(Boolean);

  const hasLureToken = segments.some((s) => LURE_KEYWORDS.has(s));
  for (const token of brand.tokens) {
    // 1. Exact hyphen/dot-separated brand token + lure keyword (e.g. jup-airdrop-claim.com)
    if (segments.includes(token) && hasLureToken) {
      return `Uses ${brand.brand} name ("${token}") with a lure keyword on an unofficial domain`;
    }
    // 2. Concatenated brand + lure keyword in a single label (e.g. phantomclaim.com, claimjup.io)
    for (const seg of segments) {
      if (seg.startsWith(token) && LURE_KEYWORDS.has(seg.slice(token.length))) {
        return `Uses ${brand.brand} name with "${seg.slice(token.length)}" on an unofficial domain`;
      }
      if (seg.endsWith(token) && LURE_KEYWORDS.has(seg.slice(0, seg.length - token.length))) {
        return `Uses "${seg.slice(0, seg.length - token.length)}" with ${brand.brand} name on an unofficial domain`;
      }
      if (token.length >= 5 && seg.includes(token) && hasLureToken) {
        return `Uses ${brand.brand} name with lure terms on an unofficial domain`;
      }
    }
  }
  return null;
}

/**
 * Pure domain classification: returns 'official', 'lookalike', or 'unknown'.
 */
export function evaluateSite(urlOrOrigin: string): SiteInfo {
  const hostname = extractHostname(urlOrOrigin);
  if (!hostname) {
    return { status: 'unknown', hostname: urlOrOrigin.trim() };
  }

  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || /^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    return { status: 'unknown', hostname };
  }

  // 1. Exact or subdomain match against official domains
  for (const b of PROTECTED_BRANDS) {
    if (hostname === b.domain || hostname.endsWith(`.${b.domain}`)) {
      return {
        status: 'official',
        hostname,
        brand: b.brand,
        officialDomain: b.domain,
      };
    }
  }

  // Allow official parent apexes (e.g. bullx.io for neo.bullx.io) without false lookalike alerts
  for (const b of PROTECTED_BRANDS) {
    if (b.allowedApex && (hostname === b.allowedApex || hostname.endsWith(`.${b.allowedApex}`))) {
      return {
        status: 'official',
        hostname,
        brand: b.brand,
        officialDomain: b.domain,
      };
    }
  }

  const { registrable, tld, nonTldLabels } = splitRegistrable(hostname);
  const isPunycode = hostname.split('.').some((lbl) => lbl.startsWith('xn--'));
  const decodedRegistrable = decodePunycodeLabel(registrable);
  const skelBasic = normalizeSkeleton(decodedRegistrable, false);
  const skelVisual = normalizeSkeleton(decodedRegistrable, true);

  // 2. Check against each protected brand for punycode homographs, confusables, typosquats, and lures
  for (const b of PROTECTED_BRANDS) {
    const target = b.registrableLabel;
    const sameTld = tld === b.tld;

    // 2a. Exact registrable label on wrong TLD or Punycode/confusable exact skeleton match
    if (registrable === target && !sameTld) {
      return {
        status: 'lookalike',
        hostname,
        brand: b.brand,
        officialDomain: b.domain,
        reason: `Uses "${registrable}.${tld}", while ${b.brand}'s official domain is ${b.domain}.`,
      };
    }

    if (skelBasic === target || skelVisual === target) {
      return {
        status: 'lookalike',
        hostname,
        brand: b.brand,
        officialDomain: b.domain,
        reason: isPunycode
          ? `Punycode domain ("${decodedRegistrable}") impersonating ${b.brand} (${b.domain}).`
          : `Lookalike domain ("${registrable}") resembling ${b.brand} (${b.domain}).`,
      };
    }

    // 2b. Brand + lure keyword combinations across labels
    const lureReason = containsLureWithBrand(nonTldLabels, b);
    if (lureReason) {
      return {
        status: 'lookalike',
        hostname,
        brand: b.brand,
        officialDomain: b.domain,
        reason: `${lureReason}. Official site: ${b.domain}.`,
      };
    }

    // 2c. Levenshtein edit distance on registrable label (scaled for short 3-5 char brands)
    const rawDist = Math.min(
      levenshtein(decodedRegistrable, target),
      levenshtein(skelBasic, target),
      levenshtein(skelVisual, target),
    );
    const maxAllowedDist =
      target.length >= 6
        ? 2
        : target.length >= 4
          ? sameTld || isPunycode
            ? 2
            : 1
          : sameTld || isPunycode
            ? 1
            : 0;

    if (rawDist > 0 && rawDist <= maxAllowedDist) {
      return {
        status: 'lookalike',
        hostname,
        brand: b.brand,
        officialDomain: b.domain,
        reason: isPunycode
          ? `Punycode domain closely resembles ${b.brand} (${b.domain}).`
          : `Domain "${hostname}" is within ${rawDist} character edit${rawDist === 1 ? '' : 's'} of ${b.brand} (${b.domain}).`,
      };
    }
  }

  // 3. Mixed-script punycode homographs even when heavily mutated
  if (isPunycode && nonTldLabels.some((lbl) => lbl.startsWith('xn--') && hasMixedUnicodeAndAscii(decodePunycodeLabel(lbl)))) {
    return {
      status: 'lookalike',
      hostname,
      reason: 'Domain uses mixed-script punycode characters commonly used in homograph phishing.',
    };
  }

  return { status: 'unknown', hostname };
}

