/**
 * Spike: service worker.
 * PURPOSE:  Keeps the offscreen clipboard poller alive, shows notifications
 *           and the badge countdown.
 * NEVER:    No network. Receives findings only (no secret material).
 */
import type { SecretFinding } from '../../../src/shared/detectors/secret-detector';

const NOTIF_ID = 'aegis-secret';

async function ensureOffscreen(): Promise<void> {
  const existing = await chrome.runtime.getContexts({ contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT] });
  if (existing.length > 0) return;
  await chrome.offscreen.createDocument({
    url: 'offscreen.html',
    reasons: [chrome.offscreen.Reason.CLIPBOARD],
    justification: 'Detect secret keys / seed phrases on the clipboard and clear them after a countdown.',
  });
}

function describe(findings: SecretFinding[]): string {
  const f = findings[0];
  if (!f) return 'Sensitive data';
  if (f.kind === 'solana-secret-key') return `Private key for wallet ${f.publicKeyShort}`;
  if (f.kind === 'seed-phrase') return `Seed phrase (${f.wordCount} words)`;
  return `Possible seed phrase (${f.wordCount} words)`;
}

chrome.runtime.onInstalled.addListener(() => void ensureOffscreen());
chrome.runtime.onStartup.addListener(() => void ensureOffscreen());

chrome.runtime.onMessage.addListener((msg: any) => {
  if (msg.type === 'secret-detected') {
    chrome.notifications.create(NOTIF_ID, {
      type: 'basic',
      iconUrl: 'icon128.png',
      title: `${describe(msg.findings)} detected in clipboard`,
      message: `Clearing in ${msg.seconds}s. Finish your import now.`,
      buttons: [{ title: 'Clear now' }, { title: '+30s' }],
      requireInteraction: true,
      priority: 2,
    });
    void chrome.action.setBadgeBackgroundColor({ color: '#d93025' });
    void chrome.action.setBadgeText({ text: String(msg.seconds) });
  }
  if (msg.type === 'countdown') {
    void chrome.action.setBadgeText({ text: msg.secondsLeft > 0 ? String(msg.secondsLeft) : '' });
  }
  if (msg.type === 'countdown-finished') {
    void chrome.action.setBadgeText({ text: '' });
    chrome.notifications.clear(NOTIF_ID);
    chrome.notifications.create(`aegis-done-${Date.now()}`, {
      type: 'basic',
      iconUrl: 'icon128.png',
      title: msg.cleared ? 'Clipboard cleared' : 'Secret no longer in clipboard',
      message: msg.cleared
        ? 'Windows clipboard history (Win+V) may still hold a copy.'
        : 'You copied something else. Windows clipboard history (Win+V) may still hold a copy.',
    });
  }
});

chrome.notifications.onButtonClicked.addListener((id, index) => {
  if (id !== NOTIF_ID) return;
  void chrome.runtime.sendMessage({ type: index === 0 ? 'clear-now' : 'extend' });
});

void ensureOffscreen();
