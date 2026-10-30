/**
 * settings.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Zero-config local protection settings with automatic Solana
 *           Mainnet simulation defaults, stored in chrome.storage.local.
 * ACCESS:   chrome.storage.local (this device only, never synced).
 * NEVER:    Never stores secrets, clipboard text, or detection inputs.
 * ---------------------------------------------------------------------------
 */

export const DEFAULT_MAINNET_RPC_URL = 'https://api.mainnet-beta.solana.com';
export const FALLBACK_MAINNET_RPC_URL = 'https://solana.publicnode.com';

export interface AegisSettings {
  clipboardGuard: boolean;
  clipboardSeconds: number;
  /** Text written to the clipboard when clearing. Empty string = leave it empty. */
  clipboardPlaceholder: string;
  pasteGuard: boolean;
  seedFormWarning: boolean;
  addressChecks: boolean;
  transactionGate: boolean;
  /** Behaviour when the RPC can't be reached: 'warn' shows UNVERIFIED review, 'block' rejects. */
  rpcFailure: 'warn' | 'block';
  /** Solana HTTPS JSON-RPC URL used for pre-wallet transaction simulation. */
  rpcUrl: string;
  /** Origins where pasting a secret was explicitly allowed by the user. */
  trustedPasteOrigins: string[];
  onboardingDone: boolean;
}

export const DEFAULT_SETTINGS: AegisSettings = {
  clipboardGuard: true,
  clipboardSeconds: 30,
  clipboardPlaceholder: '[Aegis: cleared]',
  pasteGuard: true,
  seedFormWarning: true,
  addressChecks: true,
  transactionGate: true,
  rpcFailure: 'warn',
  rpcUrl: DEFAULT_MAINNET_RPC_URL,
  trustedPasteOrigins: [],
  onboardingDone: true,
};

export function isAllowedRpcUrl(raw: string): boolean {
  const trimmed = raw.trim();
  if (trimmed === '') return true;
  try {
    const u = new URL(trimmed);
    if (u.protocol === 'https:') return true;
    if (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1')) return true;
    return false;
  } catch {
    return false;
  }
}

export async function getSettings(): Promise<AegisSettings> {
  const stored = (await chrome.storage.local.get('settings')) as { settings?: Partial<AegisSettings> };
  return { ...DEFAULT_SETTINGS, ...(stored.settings ?? {}) };
}

export async function updateSettings(patch: Partial<AegisSettings>): Promise<AegisSettings> {
  if (patch.rpcUrl !== undefined) {
    const cleaned = patch.rpcUrl.trim();
    if (!isAllowedRpcUrl(cleaned)) {
      throw new Error('RPC URL must use https:// (or http://localhost / http://127.0.0.1 for local testing).');
    }
    patch = { ...patch, rpcUrl: cleaned };
  }
  const next = { ...(await getSettings()), ...patch };
  if (next.clipboardSeconds < 10) next.clipboardSeconds = 10;
  if (next.clipboardSeconds > 120) next.clipboardSeconds = 120;
  await chrome.storage.local.set({ settings: next });
  return next;
}
