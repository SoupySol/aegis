/**
 * service-worker.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Central MV3 background service worker for Aegis Wallet Shield.
 *           Initializes zero-config offscreen clipboard protection and injects
 *           protection hooks into open tabs immediately on install/startup,
 *           routing typed messages between content scripts, offscreen poller,
 *           review window, and compact toolbar popup.
 * ACCESS:   chrome.runtime, chrome.tabs, chrome.scripting, chrome.storage,
 *           secret-detector.ts, settings.ts, and background controllers.
 * NEVER:    No nativeMessaging. Never opens unsolicited setup tabs. Never logs
 *           or persists candidate secret strings. Restricts management,
 *           offscreen, and review-decision messages strictly to privileged
 *           extension-owned contexts.
 * ---------------------------------------------------------------------------
 */

import { wordlist as english } from '@scure/bip39/wordlists/english';
import { containsConfirmedSecret, detectSecrets } from '../shared/detectors/secret-detector';
import type {
  AddressCopiedMessage,
  AddressPastedRequest,
  DetectRequest,
  DetectResponse,
  GateRequest,
  OffscreenEvent,
  PasteTrustRequest,
  ReviewDecision,
  ReviewFetchRequest,
  SeedFormCheckRequest,
  SeedFormCheckResponse,
} from '../shared/messages';
import { looksLikeAddress } from '../shared/prefilter';
import {
  DEFAULT_MAINNET_RPC_URL,
  getSettings,
  updateSettings,
  type AegisSettings,
} from '../shared/settings';
import { evaluateAddressPaste, recordAddressCopied } from './address-book';
import {
  clearClipboardNow,
  dismissPendingWinHistoryWarning,
  emergencyClearClipboard,
  extendClipboardTimer,
  getActiveClipboardCountdown,
  getPendingWinHistoryWarning,
  handleOffscreenEvent,
  initClipboardController,
  shortenClipboardTimer,
  syncOffscreenConfig,
} from './clipboard-controller';
import { decidePendingReview, getPendingReview, handleGateRequest } from './review-manager';

const BIP39_WORD_SET: ReadonlySet<string> = new Set(english);

function getSenderOrigin(sender: chrome.runtime.MessageSender): string {
  if (typeof sender.origin === 'string' && sender.origin) return sender.origin;
  if (typeof sender.url === 'string' && sender.url) {
    try {
      return new URL(sender.url).origin;
    } catch {
      return '';
    }
  }
  return '';
}

function isExtensionUiSender(sender: chrome.runtime.MessageSender): boolean {
  if (sender.id !== chrome.runtime.id) return false;
  const extPrefix = chrome.runtime.getURL('');
  return typeof sender.url === 'string' && sender.url.startsWith(extPrefix);
}

function isReviewPageSender(sender: chrome.runtime.MessageSender): boolean {
  if (sender.id !== chrome.runtime.id) return false;
  const reviewPrefix = chrome.runtime.getURL('review.html');
  return typeof sender.url === 'string' && sender.url.startsWith(reviewPrefix);
}

/**
 * Upgrades pre-zero-config profiles that still hold `{ onboardingDone: false, rpcUrl: '' }`
 * so live Solana Mainnet simulation works automatically upon extension reload.
 */
async function migrateLegacyEmptyRpc(): Promise<void> {
  try {
    const stored = (await chrome.storage.local.get('settings')) as {
      settings?: Partial<AegisSettings>;
    };
    if (
      stored.settings &&
      stored.settings.onboardingDone === false &&
      stored.settings.rpcUrl === ''
    ) {
      await updateSettings({
        rpcUrl: DEFAULT_MAINNET_RPC_URL,
        onboardingDone: true,
      });
    }
  } catch {
    /* ignore storage race */
  }
}

/**
 * Injects content.js (ISOLATED) and inpage.js (MAIN) into already-open HTTP(S)
 * tabs when Aegis is installed, updated, or reloaded so users don't have to
 * manually refresh existing dApp tabs before protection takes effect.
 */
async function injectIntoExistingTabs(): Promise<void> {
  if (!chrome.scripting?.executeScript || !chrome.tabs?.query) return;
  try {
    const tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });
    for (const tab of tabs) {
      if (typeof tab.id !== 'number') continue;
      // AEGIS-PERMISSION: injects Aegis content + inpage hooks into existing web tabs on install/reload.
      chrome.scripting
        .executeScript({
          target: { tabId: tab.id, allFrames: true },
          files: ['content.js'],
          world: 'ISOLATED',
        })
        .catch(() => {});
      chrome.scripting
        .executeScript({
          target: { tabId: tab.id, allFrames: true },
          files: ['inpage.js'],
          world: 'MAIN',
        })
        .catch(() => {});
    }
  } catch {
    /* ignore restricted tabs */
  }
}

chrome.runtime.onInstalled.addListener(() => {
  void migrateLegacyEmptyRpc();
  initClipboardController();
  void injectIntoExistingTabs();
});

chrome.runtime.onStartup.addListener(() => {
  void migrateLegacyEmptyRpc();
  initClipboardController();
  void injectIntoExistingTabs();
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && changes.settings) {
    void syncOffscreenConfig();
  }
});

chrome.runtime.onMessage.addListener((rawMsg: unknown, sender, sendResponse) => {
  if (!rawMsg || typeof rawMsg !== 'object') return false;
  const msg = rawMsg as { type?: string; target?: string };

  // Ignore messages addressed explicitly to the offscreen document
  if (msg.target === 'offscreen') return false;

  const dispatch = async (): Promise<unknown> => {
    switch (msg.type) {
      // ---- Content script messages ----------------------------------------
      case 'detect': {
        const req = rawMsg as DetectRequest;
        const text = typeof req.text === 'string' ? req.text : '';
        const settings = await getSettings();
        const origin = getSenderOrigin(sender);
        const originTrusted = Boolean(origin && settings.trustedPasteOrigins.includes(origin));
        const trusted = !settings.pasteGuard || originTrusted;

        const detection = detectSecrets(text);
        const confirmed = containsConfirmedSecret(detection);

        if (confirmed && originTrusted) {
          void shortenClipboardTimer(3);
        }

        const res: DetectResponse = {
          confirmed,
          findings: detection.findings,
          trusted,
        };
        return res;
      }

      case 'paste-trust': {
        const req = rawMsg as PasteTrustRequest;
        const senderOrigin = getSenderOrigin(sender);
        // AEGIS-SECURITY: content scripts can only grant trust to their own actual origin;
        // extension UI pages can manage arbitrary origins.
        const targetOrigin = isExtensionUiSender(sender)
          ? (req.origin || '').trim()
          : senderOrigin;

        if (!targetOrigin) return { trusted: false };
        const current = await getSettings();
        const nextSet = new Set(current.trustedPasteOrigins);
        if (req.grant === false) {
          nextSet.delete(targetOrigin);
        } else {
          nextSet.add(targetOrigin);
        }
        const updated = await updateSettings({ trustedPasteOrigins: Array.from(nextSet) });
        return { trusted: updated.trustedPasteOrigins.includes(targetOrigin) };
      }

      case 'seed-form-check': {
        const req = rawMsg as SeedFormCheckRequest;
        const settings = await getSettings();
        const origin = getSenderOrigin(sender);
        if (!settings.seedFormWarning || (origin && settings.trustedPasteOrigins.includes(origin))) {
          return { bip39Count: 0 } satisfies SeedFormCheckResponse;
        }
        const words = Array.isArray(req.words) ? req.words.slice(0, 80) : [];
        let bip39Count = 0;
        for (const w of words) {
          if (typeof w === 'string' && BIP39_WORD_SET.has(w.toLowerCase())) {
            bip39Count += 1;
          }
        }
        return { bip39Count } satisfies SeedFormCheckResponse;
      }

      case 'address-copied': {
        const req = rawMsg as AddressCopiedMessage;
        const settings = await getSettings();
        if (settings.addressChecks && typeof req.address === 'string' && looksLikeAddress(req.address)) {
          await recordAddressCopied(req.address);
        }
        return { ok: true };
      }

      case 'address-pasted': {
        const req = rawMsg as AddressPastedRequest;
        const settings = await getSettings();
        if (!settings.addressChecks || typeof req.address !== 'string' || !looksLikeAddress(req.address)) {
          return {};
        }
        return await evaluateAddressPaste(req.address);
      }

      case 'gate': {
        const req = rawMsg as GateRequest;
        const senderOrigin = getSenderOrigin(sender);
        const effectiveReq: GateRequest = {
          ...req,
          origin: senderOrigin || req.origin || 'unknown',
        };
        return await handleGateRequest(effectiveReq);
      }

      // ---- Offscreen document events --------------------------------------
      case 'clip:ready':
      case 'clip:secret-detected':
      case 'clip:tick':
      case 'clip:finished': {
        // AEGIS-SECURITY: strictly restrict offscreen events to the background offscreen document (never content scripts or tabs).
        if (sender.id !== chrome.runtime.id || sender.tab) return { ok: false };
        return await handleOffscreenEvent(rawMsg as OffscreenEvent);
      }

      // ---- Review popup window messages -----------------------------------
      case 'review:get': {
        if (!isReviewPageSender(sender)) {
          return { request: null, report: null, pending: false, error: 'Unauthorized caller' };
        }
        const req = rawMsg as ReviewFetchRequest;
        return getPendingReview(req.reviewId);
      }

      case 'review:decide': {
        // AEGIS-SECURITY: only review.html inside this extension may approve or reject a gate request.
        if (!isReviewPageSender(sender)) {
          return { ok: false, error: 'Unauthorized caller' };
        }
        const req = rawMsg as ReviewDecision;
        const ok = decidePendingReview(req.reviewId, req.allow === true);
        return { ok };
      }

      // ---- Compact Toolbar Popup UI ---------------------------------------
      case 'ui:get-dashboard': {
        if (!isExtensionUiSender(sender)) return { error: 'Unauthorized' };
        const [settings, pendingWinHistoryWarning] = await Promise.all([
          getSettings(),
          getPendingWinHistoryWarning(),
        ]);
        return {
          settings,
          clipboardCountdown: getActiveClipboardCountdown(),
          pendingWinHistoryWarning,
        };
      }

      case 'ui:update-settings': {
        if (!isExtensionUiSender(sender)) return { error: 'Unauthorized' };
        const patch = (rawMsg as { patch?: Partial<AegisSettings> }).patch ?? {};
        const settings = await updateSettings(patch);
        await syncOffscreenConfig();
        return { settings };
      }

      case 'ui:reset-trusted-sites': {
        if (!isExtensionUiSender(sender)) return { error: 'Unauthorized' };
        const settings = await updateSettings({ trustedPasteOrigins: [] });
        return { settings };
      }

      case 'ui:clip-clear-now': {
        if (!isExtensionUiSender(sender)) return { error: 'Unauthorized' };
        await clearClipboardNow();
        return { ok: true };
      }

      case 'ui:clip-extend': {
        if (!isExtensionUiSender(sender)) return { error: 'Unauthorized' };
        const seconds = Number((rawMsg as { seconds?: number }).seconds ?? 30);
        await extendClipboardTimer(seconds);
        return { ok: true };
      }

      case 'ui:emergency-clear': {
        if (!isExtensionUiSender(sender)) return { error: 'Unauthorized' };
        return await emergencyClearClipboard();
      }

      case 'ui:dismiss-win-history-warning': {
        if (!isExtensionUiSender(sender)) return { error: 'Unauthorized' };
        await dismissPendingWinHistoryWarning();
        return { ok: true };
      }

      default:
        return undefined;
    }
  };

  void dispatch()
    .then((res) => sendResponse(res))
    .catch((err) => {
      sendResponse({ error: err instanceof Error ? err.message : String(err) });
    });

  return true;
});

// Ensure legacy empty-RPC storage is upgraded and offscreen poller is active whenever service worker wakes up
void migrateLegacyEmptyRpc();
initClipboardController();
