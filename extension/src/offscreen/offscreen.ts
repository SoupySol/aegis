/**
 * offscreen.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Polls the system clipboard (~1000ms) inside an MV3 offscreen
 *           document to detect Solana private keys and BIP-39 seed phrases,
 *           runs a reliable countdown timer, and clears the clipboard only if
 *           the same secret is still present when the timer finishes.
 * ACCESS:   System clipboard (read/write) and chrome.runtime messaging to the
 *           Aegis service worker.
 * NEVER:    No network access, no storage, no logging of clipboard contents.
 *           Plaintext clipboard strings are wiped immediately after hashing;
 *           only a session-salted HMAC-SHA256 fingerprint is kept in memory.
 * ---------------------------------------------------------------------------
 */

import {
  containsConfirmedSecret,
  detectSecrets,
  type SecretFinding,
} from '../shared/detectors/secret-detector';
import { fingerprint } from '../shared/detectors/fingerprint';
import type { OffscreenCommand, OffscreenEvent } from '../shared/messages';

type ExtendedOffscreenCommand =
  | OffscreenCommand
  | { target: 'offscreen'; type: 'clip:shorten'; seconds: number }
  | { target: 'offscreen'; type: 'clip:force-clear' };

interface PollerConfig {
  seconds: number;
  placeholder: string;
  enabled: boolean;
}

const POLL_MS = 1000;
const buf = document.getElementById('buf') as HTMLTextAreaElement;

let config: PollerConfig = {
  seconds: 30,
  placeholder: '[Aegis: cleared]',
  enabled: true,
};

let lastFp = '';
let tracked: { fp: string; secondsLeft: number; findings: SecretFinding[] } | null = null;
let busy = false;

function emit(event: OffscreenEvent): Promise<unknown> {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(event, (res) => {
        void chrome.runtime.lastError;
        resolve(res);
      });
    } catch {
      resolve(undefined);
    }
  });
}

// AEGIS-PERMISSION: reads current system clipboard text via hidden textarea (requires "clipboardRead").
function readClipboard(): string {
  buf.value = '';
  buf.focus();
  document.execCommand('paste');
  const text = buf.value;
  buf.value = ''; // AEGIS-SECURITY: wipe DOM buffer immediately
  return text;
}

// AEGIS-PERMISSION: writes replacement text to the system clipboard (requires "clipboardWrite").
function writeClipboard(replacement: string): void {
  const onCopy = (e: ClipboardEvent) => {
    e.preventDefault();
    e.clipboardData?.setData('text/plain', replacement);
  };
  buf.value = '';
  buf.focus();
  document.addEventListener('copy', onCopy, { once: true });
  document.execCommand('copy');
  buf.value = '';
}

function applyConfig(partial: Partial<PollerConfig>): void {
  if (typeof partial.seconds === 'number' && Number.isFinite(partial.seconds)) {
    config.seconds = Math.max(1, Math.min(120, Math.round(partial.seconds)));
  }
  if (typeof partial.placeholder === 'string') {
    config.placeholder = partial.placeholder;
  }
  if (typeof partial.enabled === 'boolean') {
    config.enabled = partial.enabled;
  }
  if (!config.enabled && tracked) {
    tracked = null;
  } else if (tracked && tracked.secondsLeft > config.seconds) {
    tracked.secondsLeft = config.seconds;
  }
}

async function finishCountdown(): Promise<void> {
  if (!tracked || busy) return;
  busy = true;
  try {
    const active = tracked;
    let current = readClipboard();
    const currentFp = current ? await fingerprint(current) : '';
    current = ''; // AEGIS-SECURITY: drop plaintext reference immediately

    // AEGIS-SECURITY: never overwrite clipboard if the user copied something else meanwhile.
    if (currentFp !== '' && currentFp === active.fp) {
      writeClipboard(config.placeholder);
      lastFp = config.placeholder ? await fingerprint(config.placeholder) : '';
      tracked = null;
      await emit({ type: 'clip:finished', cleared: true, displaced: false });
    } else {
      lastFp = currentFp;
      tracked = null;
      await emit({ type: 'clip:finished', cleared: false, displaced: true });
    }
  } finally {
    busy = false;
  }
}

async function forceClearClipboard(): Promise<void> {
  if (busy) return;
  busy = true;
  try {
    const wasTracking = tracked !== null;
    writeClipboard(config.placeholder);
    lastFp = config.placeholder ? await fingerprint(config.placeholder) : '';
    tracked = null;
    if (wasTracking) {
      await emit({ type: 'clip:finished', cleared: true, displaced: false });
    }
  } finally {
    busy = false;
  }
}

async function poll(): Promise<void> {
  if (!config.enabled || busy) return;
  busy = true;
  try {
    let text = readClipboard();
    const fp = text ? await fingerprint(text) : '';

    if (fp !== lastFp) {
      // If we were tracking a secret and the clipboard changed before timer expiry, notify displacement.
      if (tracked && fp !== tracked.fp) {
        tracked = null;
        await emit({ type: 'clip:finished', cleared: false, displaced: true });
      }

      lastFp = fp;
      if (text) {
        const result = detectSecrets(text);
        if (result.findings.length > 0) {
          tracked = {
            fp,
            secondsLeft: config.seconds,
            findings: result.findings,
          };
          await emit({
            type: 'clip:secret-detected',
            findings: result.findings,
            confirmed: containsConfirmedSecret(result),
            seconds: config.seconds,
          });
        }
      }
    }
    text = ''; // AEGIS-SECURITY: wipe local reference
  } finally {
    busy = false;
  }
}

async function tick(): Promise<void> {
  if (!config.enabled || !tracked || busy) return;
  tracked.secondsLeft -= 1;
  await emit({ type: 'clip:tick', secondsLeft: Math.max(0, tracked.secondsLeft) });
  if (tracked && tracked.secondsLeft <= 0) {
    await finishCountdown();
  }
}

chrome.runtime.onMessage.addListener((msg: ExtendedOffscreenCommand, sender, sendResponse) => {
  if (!msg || msg.target !== 'offscreen') return false;
  // AEGIS-SECURITY: accept offscreen commands strictly from the extension service worker (never from content scripts or tabs).
  if (sender.id !== chrome.runtime.id || sender.tab) return false;

  if (msg.type === 'clip:configure') {
    applyConfig({ seconds: msg.seconds, placeholder: msg.placeholder, enabled: msg.enabled });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'clip:clear-now') {
    if (tracked) {
      tracked.secondsLeft = 0;
      void finishCountdown().then(() => sendResponse({ ok: true }));
    } else {
      void forceClearClipboard().then(() => sendResponse({ ok: true }));
    }
    return true;
  }

  if (msg.type === 'clip:force-clear') {
    void forceClearClipboard().then(() => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === 'clip:extend') {
    if (tracked) {
      tracked.secondsLeft = Math.min(300, Math.max(1, tracked.secondsLeft + msg.seconds));
      void emit({ type: 'clip:tick', secondsLeft: tracked.secondsLeft });
    }
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'clip:shorten') {
    if (tracked && tracked.secondsLeft > msg.seconds) {
      tracked.secondsLeft = Math.max(1, msg.seconds);
      void emit({ type: 'clip:tick', secondsLeft: tracked.secondsLeft });
    }
    sendResponse({ ok: true });
    return false;
  }

  return false;
});

// Handshake with service worker to load initial user settings BEFORE first poll
void emit({ type: 'clip:ready' }).then((initialCfg) => {
  if (initialCfg && typeof initialCfg === 'object') {
    applyConfig(initialCfg as Partial<PollerConfig>);
  }
  void poll();
  setInterval(() => void poll(), POLL_MS);
  setInterval(() => void tick(), 1000);
});
