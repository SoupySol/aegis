/**
 * popup.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Drives the compact zero-input Aegis toolbar popup: live clipboard
 *           countdown bar, pending Windows Clipboard History reminder, 4 core
 *           protection switches, 1-click trusted-paste reset, and 1-click
 *           Clear Clipboard Now.
 * ACCESS:   chrome.runtime messaging and chrome.tabs (Win+V settings shortcut).
 * NEVER:    No manual inputs, no network calls, no nativeMessaging, no secret
 *           access or persistence.
 * ---------------------------------------------------------------------------
 */

import type { AegisSettings } from '../shared/settings';
import type {
  ActiveClipboardCountdown,
  PendingWinHistoryWarning,
} from '../background/clipboard-controller';

interface DashboardPayload {
  settings: AegisSettings;
  clipboardCountdown: ActiveClipboardCountdown | null;
  pendingWinHistoryWarning: PendingWinHistoryWarning | null;
}

const shieldStatusPill = document.getElementById('shieldStatusPill') as HTMLElement;
const countdownCard = document.getElementById('countdownCard') as HTMLElement;
const countdownLabel = document.getElementById('countdownLabel') as HTMLElement;
const countdownSeconds = document.getElementById('countdownSeconds') as HTMLElement;
const countdownFill = document.getElementById('countdownFill') as HTMLElement;
const btnClipClearNow = document.getElementById('btnClipClearNow') as HTMLButtonElement;
const btnClipExtend = document.getElementById('btnClipExtend') as HTMLButtonElement;

const winHistoryBanner = document.getElementById('winHistoryBanner') as HTMLElement;
const btnOpenWinClip = document.getElementById('btnOpenWinClip') as HTMLButtonElement;
const btnDismissWinClip = document.getElementById('btnDismissWinClip') as HTMLButtonElement;

const togTxGate = document.getElementById('togTxGate') as HTMLInputElement;
const togClipGuard = document.getElementById('togClipGuard') as HTMLInputElement;
const togPasteGuard = document.getElementById('togPasteGuard') as HTMLInputElement;
const togAddressChecks = document.getElementById('togAddressChecks') as HTMLInputElement;

const trustedResetRow = document.getElementById('trustedResetRow') as HTMLElement;
const trustedCountLabel = document.getElementById('trustedCountLabel') as HTMLElement;
const btnResetTrusted = document.getElementById('btnResetTrusted') as HTMLButtonElement;

const btnEmergencyClear = document.getElementById('btnEmergencyClear') as HTMLButtonElement;
const statusToast = document.getElementById('statusToast') as HTMLElement;

function sendMsg<T>(msg: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (res: T) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(res);
    });
  });
}

function showToast(text: string): void {
  statusToast.textContent = text;
  statusToast.classList.remove('hidden');
  setTimeout(() => {
    statusToast.classList.add('hidden');
  }, 2400);
}

function renderShieldStatus(s: AegisSettings): void {
  const enabledCount = [
    s.transactionGate,
    s.clipboardGuard,
    s.pasteGuard,
    s.addressChecks,
  ].filter(Boolean).length;
  if (enabledCount === 4) {
    shieldStatusPill.className = 'pill pill-safe';
    shieldStatusPill.textContent = 'Shield Active';
  } else if (enabledCount > 0) {
    shieldStatusPill.className = 'pill pill-caution';
    shieldStatusPill.textContent = `${enabledCount}/4 Active`;
  } else {
    shieldStatusPill.className = 'pill pill-danger';
    shieldStatusPill.textContent = 'Paused';
  }
}

function renderCountdown(cd: ActiveClipboardCountdown | null): void {
  if (!cd || cd.secondsLeft <= 0) {
    countdownCard.classList.add('hidden');
    return;
  }
  countdownCard.classList.remove('hidden');
  countdownLabel.textContent = cd.label;
  countdownSeconds.textContent = `${cd.secondsLeft}s`;
  const pct = Math.max(0, Math.min(100, (cd.secondsLeft / Math.max(1, cd.totalSeconds)) * 100));
  countdownFill.style.width = `${pct}%`;
}

function renderTrustedSites(origins: string[]): void {
  const count = Array.isArray(origins) ? origins.length : 0;
  if (count <= 0) {
    trustedResetRow.classList.add('hidden');
    return;
  }
  trustedResetRow.classList.remove('hidden');
  trustedCountLabel.textContent =
    count === 1 ? 'Paste allowed on 1 site' : `Paste allowed on ${count} sites`;
}

function renderDashboard(d: DashboardPayload): void {
  if (!d?.settings) return;
  togTxGate.checked = d.settings.transactionGate;
  togClipGuard.checked = d.settings.clipboardGuard;
  togPasteGuard.checked = d.settings.pasteGuard;
  togAddressChecks.checked = d.settings.addressChecks;

  renderShieldStatus(d.settings);
  renderCountdown(d.clipboardCountdown);
  renderTrustedSites(d.settings.trustedPasteOrigins);

  if (d.pendingWinHistoryWarning?.pending) {
    winHistoryBanner.classList.remove('hidden');
  } else {
    winHistoryBanner.classList.add('hidden');
  }
}

async function refresh(): Promise<void> {
  try {
    const data = await sendMsg<DashboardPayload>({ type: 'ui:get-dashboard' });
    renderDashboard(data);
  } catch {
    /* ignore transient wakeup error */
  }
}

function bindPatchToggle(
  el: HTMLInputElement,
  buildPatch: (checked: boolean) => Partial<AegisSettings>,
): void {
  el.addEventListener('change', () => {
    void sendMsg<{ settings: AegisSettings }>({
      type: 'ui:update-settings',
      patch: buildPatch(el.checked),
    }).then((res) => {
      if (res?.settings) {
        renderShieldStatus(res.settings);
        renderTrustedSites(res.settings.trustedPasteOrigins);
      }
    });
  });
}

bindPatchToggle(togTxGate, (checked) => ({ transactionGate: checked }));
bindPatchToggle(togClipGuard, (checked) => ({ clipboardGuard: checked }));
bindPatchToggle(togPasteGuard, (checked) => ({ pasteGuard: checked, seedFormWarning: checked }));
bindPatchToggle(togAddressChecks, (checked) => ({ addressChecks: checked }));

btnResetTrusted.addEventListener('click', () => {
  void sendMsg<{ settings?: AegisSettings }>({ type: 'ui:reset-trusted-sites' }).then((res) => {
    if (res?.settings) {
      renderTrustedSites(res.settings.trustedPasteOrigins);
    }
    showToast('Site permissions reset');
  });
});

btnClipClearNow.addEventListener('click', () => {
  void sendMsg({ type: 'ui:clip-clear-now' }).then(() => {
    showToast('Clipboard cleared');
    void refresh();
  });
});

btnClipExtend.addEventListener('click', () => {
  void sendMsg({ type: 'ui:clip-extend', seconds: 30 }).then(() => refresh());
});

btnOpenWinClip.addEventListener('click', () => {
  void chrome.tabs.create({ url: 'ms-settings:clipboard' });
});

btnDismissWinClip.addEventListener('click', () => {
  void sendMsg({ type: 'ui:dismiss-win-history-warning' }).then(() => {
    winHistoryBanner.classList.add('hidden');
  });
});

btnEmergencyClear.addEventListener('click', () => {
  void sendMsg<{ ok?: boolean }>({ type: 'ui:emergency-clear' }).then(() => {
    showToast('Clipboard cleared');
    void refresh();
  });
});

void refresh();
setInterval(() => void refresh(), 1000);
