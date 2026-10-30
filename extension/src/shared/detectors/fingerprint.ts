/**
 * fingerprint.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Creates a salted, one-way fingerprint of a piece of text so Aegis
 *           can later recognize "this is the same secret as before" (e.g. to
 *           check whether a key is still on the clipboard) without keeping
 *           the secret itself.
 *
 * ACCESS:   Web Crypto (HMAC-SHA256), in memory only.
 *
 * NEVER:    - The salt is random per session and never persisted, so
 *             fingerprints can't be linked across sessions or reversed.
 *           - No network. No storage.
 * ---------------------------------------------------------------------------
 */

let sessionKeyPromise: Promise<CryptoKey> | null = null;

function getSessionKey(): Promise<CryptoKey> {
  if (!sessionKeyPromise) {
    // AEGIS-SECURITY: non-extractable random key, lives only in this process's memory.
    // Cached as a synchronous promise so concurrent cold-start calls share the same key.
    sessionKeyPromise = crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  }
  return sessionKeyPromise;
}

/** Returns a hex HMAC-SHA256 fingerprint of `text` under the session key. */
export async function fingerprint(text: string): Promise<string> {
  const key = await getSessionKey();
  const data = new TextEncoder().encode(text);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
  data.fill(0); // AEGIS-SECURITY: wipe the encoded copy
  return Array.from(sig, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Test helper: forget the session key (simulates a new session). */
export function resetSessionKeyForTests(): void {
  sessionKeyPromise = null;
}

