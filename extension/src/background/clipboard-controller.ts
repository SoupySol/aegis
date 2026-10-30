/**
 * clipboard-controller.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Coordinates the MV3 offscreen clipboard poller, updates the
 *           toolbar countdown badge, displays notifications with [Clear now]
 *           and [+30s] controls, and records a local non-secret reminder about
 *           Windows Clipboard History (Win+V) after a clipboard secret finishes
 *           its countdown or is displaced until dismissed by the user.
 * ACCESS:   chrome.offscreen, chrome.notifications, chrome.action, and
 *           chrome.storage.local (non-secret status metadata only).
 * NEVER:    No network access, no nativeMessaging. Never receives, logs, or
 *           persists clipboard text, keys, seed phrases, or fingerprints.
 * ---------------------------------------------------------------------------
 */

import type { SecretFinding } from '../shared/detectors/secret-detector';
import type { OffscreenCommand, OffscreenEvent } from '../shared/messages';
import { getSettings } from '../shared/settings';

const SECRET_NOTIF_ID = 'aegis-clipboard-secret';
const PENDING_WIN_HISTORY_KEY = 'pendingWinHistoryWarning';

export interface ActiveClipboardCountdown {
  secondsLeft: number;
  totalSeconds: number;
  label: string;
}

export interface PendingWinHistoryWarning {
  pending: boolean;
  count: number;
  lastDisplaced: boolean;
  updatedAt: number;
}

let creatingOffscreen: Promise<void> | null = null;
let activeCountdown: ActiveClipboardCountdown | null = null;
let listenersBound = false;

function describeFindings(findings: SecretFinding[]): string {
  const first = findings[0];
  if (!first) return 'Sensitive wallet data';
  if (first.kind === 'solana-secret-key') {
    return first.publicKeyShort
      ? `Secret key (wallet ${first.publicKeyShort})`
      : 'Solana secret key';
  }
  if (first.kind === 'seed-phrase') {
    return `Seed phrase (${first.wordCount ?? 12} words)`;
  }
  return `Possible seed phrase (${first.wordCount ?? 12} words)`;
}

function sendToOffscreen(
  cmd:
    | OffscreenCommand
    | { target: 'offscreen'; type: 'clip:shorten'; seconds: number }
    | { target: 'offscreen'; type: 'clip:force-clear' },
): Promise<void> {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(cmd, () => {
        void chrome.runtime.lastError;
        resolve();
      });
    } catch {
      resolve();
    }
  });
}

// AEGIS-PERMISSION: manages the single MV3 offscreen document used for clipboard countdown checks.
export async function ensureOffscreen(): Promise<void> {
  if (!chrome.offscreen) return;
  try {
    const existing = await chrome.runtime.getContexts({
      contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT],
    });
    if (existing.length > 0) return;
  } catch {
    /* proceed to create */
  }

  if (creatingOffscreen) {
    await creatingOffscreen;
    return;
  }

  creatingOffscreen = chrome.offscreen
    .createDocument({
      url: 'offscreen.html',
      reasons: [chrome.offscreen.Reason.CLIPBOARD],
      justification: 'Detect Solana keys and seed phrases on the clipboard locally and auto-clear after countdown.',
    })
    .catch(() => {
      /* ignore race if already created */
    })
    .finally(() => {
      creatingOffscreen = null;
    });

  await creatingOffscreen;
}

export async function syncOffscreenConfig(): Promise<void> {
  const settings = await getSettings();
  await ensureOffscreen();
  await sendToOffscreen({
    target: 'offscreen',
    type: 'clip:configure',
    seconds: settings.clipboardSeconds,
    placeholder: settings.clipboardPlaceholder,
    enabled: settings.clipboardGuard,
  });
  if (!settings.clipboardGuard) {
    activeCountdown = null;
    void chrome.action.setBadgeText({ text: '' });
    chrome.notifications.clear(SECRET_NOTIF_ID);
  }
}

export function getActiveClipboardCountdown(): ActiveClipboardCountdown | null {
  return activeCountdown;
}

export async function getPendingWinHistoryWarning(): Promise<PendingWinHistoryWarning | null> {
  const stored = (await chrome.storage.local.get(PENDING_WIN_HISTORY_KEY)) as {
    pendingWinHistoryWarning?: PendingWinHistoryWarning | null;
  };
  return stored.pendingWinHistoryWarning?.pending ? stored.pendingWinHistoryWarning : null;
}

export async function dismissPendingWinHistoryWarning(): Promise<void> {
  await chrome.storage.local.set({ [PENDING_WIN_HISTORY_KEY]: null });
}

async function markPendingWinHistoryWarning(displaced: boolean): Promise<void> {
  const prev = await getPendingWinHistoryWarning();
  // AEGIS-SECURITY: stores only a boolean/count reminder — never secret text or fingerprints.
  const next: PendingWinHistoryWarning = {
    pending: true,
    count: (prev?.count ?? 0) + 1,
    lastDisplaced: displaced,
    updatedAt: Date.now(),
  };
  await chrome.storage.local.set({ [PENDING_WIN_HISTORY_KEY]: next });
}

export async function handleOffscreenEvent(
  event: OffscreenEvent,
): Promise<{ seconds: number; placeholder: string; enabled: boolean } | void> {
  if (event.type === 'clip:ready') {
    const settings = await getSettings();
    return {
      seconds: settings.clipboardSeconds,
      placeholder: settings.clipboardPlaceholder,
      enabled: settings.clipboardGuard,
    };
  }

  if (event.type === 'clip:secret-detected') {
    const settings = await getSettings();
    if (!settings.clipboardGuard) return;

    const label = describeFindings(event.findings);
    activeCountdown = {
      secondsLeft: event.seconds,
      totalSeconds: event.seconds,
      label,
    };

    const badgeColor = event.seconds <= 10 ? '#dc2626' : '#d97706';
    void chrome.action.setBadgeBackgroundColor({ color: badgeColor });
    void chrome.action.setBadgeText({ text: String(event.seconds) });

    // AEGIS-PERMISSION: shows desktop notification with Clear Now and +30s buttons.
    chrome.notifications.create(SECRET_NOTIF_ID, {
      type: 'basic',
      iconUrl: 'icon128.png',
      title: `${label} in clipboard`,
      message: `Clears automatically in ${event.seconds}s.`,
      buttons: [{ title: 'Clear now' }, { title: '+30s' }],
      requireInteraction: true,
      priority: 2,
    });
    return;
  }

  if (event.type === 'clip:tick') {
    if (activeCountdown) {
      activeCountdown.secondsLeft = event.secondsLeft;
    }
    if (event.secondsLeft > 0) {
      const badgeColor = event.secondsLeft <= 10 ? '#dc2626' : '#d97706';
      void chrome.action.setBadgeBackgroundColor({ color: badgeColor });
      void chrome.action.setBadgeText({ text: String(event.secondsLeft) });
    } else {
      void chrome.action.setBadgeText({ text: '' });
    }
    return;
  }

  if (event.type === 'clip:finished') {
    activeCountdown = null;
    void chrome.action.setBadgeText({ text: '' });
    chrome.notifications.clear(SECRET_NOTIF_ID);

    // Persist a gentle local reminder so Popup & Options remind the user to check Win+V until dismissed.
    await markPendingWinHistoryWarning(event.displaced);

    const doneId = `aegis-clip-done-${Date.now()}`;
    chrome.notifications.create(doneId, {
      type: 'basic',
      iconUrl: 'icon128.png',
      title: event.cleared ? 'Clipboard cleared' : 'Clipboard replaced',
      message: event.cleared
        ? 'Clipboard cleared. Press Win+V if Windows Clipboard History is enabled.'
        : 'You copied a new item. Press Win+V to clear any saved secret from history.',
    });
  }
}

export async function clearClipboardNow(): Promise<void> {
  await ensureOffscreen();
  await sendToOffscreen({ target: 'offscreen', type: 'clip:clear-now' });
}

export async function extendClipboardTimer(seconds = 30): Promise<void> {
  await ensureOffscreen();
  await sendToOffscreen({ target: 'offscreen', type: 'clip:extend', seconds });
}

export async function shortenClipboardTimer(seconds = 3): Promise<void> {
  await ensureOffscreen();
  await sendToOffscreen({ target: 'offscreen', type: 'clip:shorten', seconds });
}

export async function emergencyClearClipboard(): Promise<{ ok: boolean }> {
  await ensureOffscreen();
  await sendToOffscreen({ target: 'offscreen', type: 'clip:force-clear' });
  activeCountdown = null;
  void chrome.action.setBadgeText({ text: '' });
  chrome.notifications.clear(SECRET_NOTIF_ID);
  return { ok: true };
}

export function initClipboardController(): void {
  if (!listenersBound) {
    listenersBound = true;

    chrome.notifications.onButtonClicked.addListener((notifId, buttonIndex) => {
      if (notifId !== SECRET_NOTIF_ID) return;
      if (buttonIndex === 0) {
        void clearClipboardNow();
      } else if (buttonIndex === 1) {
        void extendClipboardTimer(30);
      }
    });
  }

  void ensureOffscreen().then(() => syncOffscreenConfig());
}
