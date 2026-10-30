/**
 * prefilter.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Very cheap check that decides whether a piece of text MIGHT
 *           contain a secret key or seed phrase. Used inside web pages so the
 *           page-level script stays tiny; real verification happens in the
 *           service worker with the full detector (secret-detector.ts).
 * ACCESS:   Pure function.
 * NEVER:    No network, no storage. Over-matching is fine (the full detector
 *           decides); under-matching is not.
 * ---------------------------------------------------------------------------
 */

const B58 = '1-9A-HJ-NP-Za-km-z';
const BASE58_64ISH = new RegExp(`[${B58}]{72,90}`);
const JSON_64 = /\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/;
const HEX_128 = /[0-9a-fA-F]{128}/;
const ADDRESS_ONLY = new RegExp(`^\\s*[${B58}]{32,44}\\s*$`);

export function mightContainSecret(text: string): boolean {
  if (!text || text.length < 40) return false;
  if (BASE58_64ISH.test(text) || JSON_64.test(text) || HEX_128.test(text)) return true;
  // 12+ alphabetic words of 3-8 letters (BIP-39 words are 3-8 letters long)
  const words = text.toLowerCase().match(/[a-z]+/g);
  if (!words || words.length < 12) return false;
  let run = 0;
  for (const w of words) {
    run = w.length >= 3 && w.length <= 8 ? run + 1 : 0;
    if (run >= 12) return true;
  }
  return false;
}

/** True if text is a single Solana address-shaped value (32-44 base58 chars). */
export function looksLikeAddress(text: string): boolean {
  return ADDRESS_ONLY.test(text);
}

