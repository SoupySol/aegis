/**
 * content/index.ts (runs in ISOLATED world at document_start)
 * ---------------------------------------------------------------------------
 * PURPOSE:  1) Relays wallet gate requests from inpage.js (MAIN world) to the
 *              service worker and posts allow/reject decisions back.
 *           2) Paste Guard: intercepts candidate secret pastes/drops in the
 *              capture phase before page scripts run, verifies via the service
 *              worker, blocks confirmed secrets on untrusted origins, and
 *              cleanly re-inserts safe or trusted text.
 *           3) Recovery-Phrase Form Notice: warns once per page when 4+ BIP-39
 *              words are typed into multi-input or textarea forms on an
 *              untrusted site.
 *           4) Address Checks: tracks copied public Solana addresses and warns
 *              on clipboard-swapped or lookalike pasted addresses.
 * ACCESS:   Page DOM events (paste, drop, copy, cut, input, message) and
 *           chrome.runtime messaging to the Aegis service worker.
 * NEVER:    No network access, no storage, never bundles heavy crypto libraries
 *           (stays < 25 KB), never retains candidate secret strings in closures.
 * ---------------------------------------------------------------------------
 */

import { looksLikeAddress, mightContainSecret } from '../shared/prefilter';
import type {
  AddressCopiedMessage,
  AddressPastedRequest,
  AddressPastedResponse,
  DetectRequest,
  DetectResponse,
  GateRequest,
  GateResponse,
  PasteTrustRequest,
  SeedFormCheckRequest,
  SeedFormCheckResponse,
  SignInFields,
} from '../shared/messages';
import type { SecretFinding } from '../shared/detectors/secret-detector';
import { showOverlayNotice } from './overlay';

function initAegisContentScript(): void {
  // AEGIS-SECURITY: idempotency guard so dynamic tab injection on extension install/reload never attaches duplicate listeners.
  if ((window as any).__aegisContentActive) return;
  (window as any).__aegisContentActive = true;

// AEGIS-SECURITY: capture pristine window messaging references at document_start.
const postMessageRef = window.postMessage.bind(window);
const addWindowListener = window.addEventListener.bind(window);

function sendRuntimeMessage<TRes>(msg: unknown): Promise<TRes | null> {
  return new Promise((resolve) => {
    try {
      // AEGIS-PERMISSION: sends structured message to extension service worker.
      chrome.runtime.sendMessage(msg, (response: TRes) => {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }
        resolve(response ?? null);
      });
    } catch {
      resolve(null);
    }
  });
}

// ---- 1. Wallet Standard / Legacy Gate Bridge ------------------------------
addWindowListener('message', (event: MessageEvent) => {
  if (event.source !== window) return;
  const d = event.data;
  if (!d || d.__aegis !== 'gate-req' || typeof d.id !== 'string' || !d.payload || typeof d.payload !== 'object') {
    return;
  }
  const reqId: string = d.id;
  const raw = d.payload as Partial<GateRequest>;

  const rawSi = raw.signInFields;
  let signInFields: SignInFields | undefined;
  if (rawSi && typeof rawSi === 'object') {
    const clean: SignInFields = {};
    for (const k of ['domain', 'statement', 'uri', 'nonce', 'issuedAt', 'expirationTime', 'chainId'] as const) {
      if (typeof rawSi[k] === 'string') clean[k] = rawSi[k];
    }
    if (Array.isArray(rawSi.resources)) {
      clean.resources = rawSi.resources.filter((r): r is string => typeof r === 'string').slice(0, 10);
    }
    if (Object.keys(clean).length > 0) signInFields = clean;
  }

  // ARCHITECTURAL DESIGN NOTE: Main-to-Isolated World Security Boundary
  // Untrusted webpage scripts running in the MAIN world can attempt to spoof their origin
  // in postMessage payloads. The isolated content script overrides any caller-supplied origin
  // with the browser-enforced `location.origin` from this execution context.
  const gateReq: GateRequest = {
    type: 'gate',
    origin: location.origin,
    method: typeof raw.method === 'string' ? raw.method : 'unknown',
    wallet: typeof raw.wallet === 'string' ? raw.wallet : 'Wallet',
    walletPubkey: typeof raw.walletPubkey === 'string' ? raw.walletPubkey : undefined,
    transactions: Array.isArray(raw.transactions)
      ? raw.transactions.filter((t): t is string => typeof t === 'string')
      : undefined,
    message: typeof raw.message === 'string' ? raw.message : undefined,
    signInDomain: typeof raw.signInDomain === 'string' ? raw.signInDomain : undefined,
    signInFields,
    silentConnect: raw.silentConnect === true ? true : undefined,
    unreadableCount:
      typeof raw.unreadableCount === 'number' && Number.isFinite(raw.unreadableCount) && raw.unreadableCount > 0
        ? Math.floor(raw.unreadableCount)
        : undefined,
    note: typeof raw.note === 'string' ? raw.note : undefined,
  };

  void sendRuntimeMessage<GateResponse>(gateReq).then((res) => {
    postMessageRef({ __aegis: 'gate-res', id: reqId, allow: res?.allow === true }, '*');
  });
});

// ---- 2. Paste Guard & Address Paste Checks --------------------------------
interface SavedTargetSelection {
  target: EventTarget | null;
  selStart: number | null;
  selEnd: number | null;
}

function captureTargetSelection(event: Event): SavedTargetSelection {
  const path = typeof event.composedPath === 'function' ? event.composedPath() : [];
  const target = (path[0] ?? event.target ?? document.activeElement) as EventTarget | null;
  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) {
    try {
      return { target, selStart: target.selectionStart, selEnd: target.selectionEnd };
    } catch {
      return { target, selStart: null, selEnd: null };
    }
  }
  return { target, selStart: null, selEnd: null };
}

function reinsertText(saved: SavedTargetSelection, text: string): void {
  const el = saved.target;
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
    if (el.readOnly || el.disabled) return;
    el.focus();
    try {
      if (saved.selStart !== null && saved.selEnd !== null) {
        el.setRangeText(text, saved.selStart, saved.selEnd, 'end');
      } else {
        el.value += text;
      }
    } catch {
      const start = saved.selStart ?? el.value.length;
      const end = saved.selEnd ?? el.value.length;
      el.value = el.value.slice(0, start) + text + el.value.slice(end);
    }
    el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertFromPaste', data: text }));
    return;
  }
  if (el instanceof HTMLElement && el.isContentEditable) {
    el.focus();
    if (!document.execCommand('insertText', false, text)) {
      el.textContent = (el.textContent ?? '') + text;
      el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertFromPaste', data: text }));
    }
  }
}

function describeFinding(f: SecretFinding | undefined): string {
  if (!f) return 'wallet recovery data';
  if (f.kind === 'solana-secret-key') {
    return f.publicKeyShort ? `a private key (${f.publicKeyShort})` : 'a private key';
  }
  return `a ${f.wordCount ?? 12}-word seed phrase`;
}

function handlePasteOrDrop(event: ClipboardEvent | DragEvent): void {
  const transfer = 'clipboardData' in event ? event.clipboardData : event.dataTransfer;
  let text = transfer?.getData('text/plain') ?? '';
  if (!text) return;

  // ARCHITECTURAL DESIGN NOTE: Synchronous Capture-Phase Paste Interception
  // To protect users from phishing forms that capture clipboard input in onpaste listeners,
  // we attach in the CAPTURE phase (`useCapture = true`). Calling `preventDefault()` and
  // `stopImmediatePropagation()` synchronously halts the event before ANY page script listener
  // can execute or steal the clipboard buffer.
  //
  // If the secret detector confirms the text is benign or the site is explicitly trusted by
  // the user, `reinsertText` re-injects the content safely via DOM selection APIs.
  if (mightContainSecret(text)) {
    event.preventDefault();
    event.stopImmediatePropagation();
    const saved = captureTargetSelection(event);
    const candidate = text;
    // AEGIS-SECURITY: Immediately zero out `text` so the raw clipboard string does not
    // linger in parent stack frames or outer lexical scopes.
    text = '';

    const req: DetectRequest = { type: 'detect', text: candidate };
    void sendRuntimeMessage<DetectResponse>(req).then((res) => {
      if (!res || !res.confirmed || res.trusted) {
        reinsertText(saved, candidate);
        return;
      }
      const what = describeFinding(res.findings[0]);
      const hostLabel = location.hostname || location.origin;
      // AEGIS-SECURITY: The candidate secret is strictly excluded from UI callback closures
      // (`showOverlayNotice` actions). Button handlers receive only static metadata.
      showOverlayNotice({
        kind: 'paste-blocked',
        tone: 'danger',
        title: 'Secret paste blocked',
        message: `Blocked ${what} on ${hostLabel}. Solana apps never need your private key or seed phrase.`,
        timeoutMs: 25_000,
        actions: [
          {
            label: 'Allow on this site',
            onClick: () => {
              const trustReq: PasteTrustRequest = { type: 'paste-trust', origin: location.origin, grant: true };
              void sendRuntimeMessage(trustReq).then(() => {
                showOverlayNotice({
                  kind: 'info',
                  tone: 'caution',
                  title: 'Paste allowed on this site',
                  message: `Paste again to enter it on ${hostLabel}. You can reset allowed sites from the Aegis icon.`,
                  timeoutMs: 8_000,
                });
              });
            },
          },
          { label: 'Dismiss', primary: true },
        ],
      });
    });
    return;
  }

  // Public Solana address check: never blocks the paste; warns if swapped or lookalike.
  if (looksLikeAddress(text)) {
    const pastedAddress = text.trim();
    const addrReq: AddressPastedRequest = { type: 'address-pasted', address: pastedAddress };
    void sendRuntimeMessage<AddressPastedResponse>(addrReq).then((res) => {
      if (!res?.warning) return;
      if (res.warning === 'clipboard-swap') {
        showOverlayNotice({
          kind: 'clipboard-swap',
          tone: 'danger',
          title: 'Clipboard address changed',
          message:
            'The pasted address does not match the Solana address you copied. Malware may have replaced your clipboard.',
          comparison: [
            ...(res.expected ? [{ label: 'Copied', value: res.expected }] : []),
            { label: 'Pasted', value: pastedAddress },
          ],
          timeoutMs: 0,
          actions: [{ label: 'Dismiss', primary: true }],
        });
      } else if (res.warning === 'lookalike') {
        showOverlayNotice({
          kind: 'lookalike',
          tone: 'caution',
          title: 'Lookalike address',
          message:
            'This address matches the start and end of a previous address, but the middle is different. Check every character.',
          comparison: [
            ...(res.expected ? [{ label: 'Known', value: res.expected }] : []),
            { label: 'Pasted', value: pastedAddress },
          ],
          timeoutMs: 0,
          actions: [{ label: 'Dismiss', primary: true }],
        });
      }
    });
  }
}

addWindowListener('paste', handlePasteOrDrop as EventListener, true);
addWindowListener('drop', handlePasteOrDrop as EventListener, true);

// ---- 3. Address Copy / Cut Tracking ---------------------------------------
function readCopiedSelection(event: ClipboardEvent): string {
  const fromEvent = event.clipboardData?.getData('text/plain');
  if (fromEvent) return fromEvent;
  const active = document.activeElement;
  if (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement) {
    try {
      const start = active.selectionStart ?? 0;
      const end = active.selectionEnd ?? 0;
      if (end > start) return active.value.slice(start, end);
    } catch {
      /* ignore inputs without selection APIs */
    }
  }
  return document.getSelection()?.toString() ?? '';
}

function handleCopyOrCut(event: ClipboardEvent): void {
  const copied = readCopiedSelection(event).trim();
  if (!looksLikeAddress(copied)) return;
  const msg: AddressCopiedMessage = { type: 'address-copied', address: copied };
  void sendRuntimeMessage(msg);
}

addWindowListener('copy', handleCopyOrCut as EventListener, true);
addWindowListener('cut', handleCopyOrCut as EventListener, true);

// ---- 4. Recovery-Phrase Form Notice ---------------------------------------
const TEXT_INPUT_TYPES = new Set(['', 'text', 'password', 'search', 'email', 'url', 'tel']);
let seedWarningShown = false;
let seedDebounceTimer: ReturnType<typeof setTimeout> | null = null;

function collectCandidateSeedWords(): string[] | null {
  const allInputs = Array.from(document.querySelectorAll('input'));
  const textInputs = allInputs.filter((el) => TEXT_INPUT_TYPES.has((el.getAttribute('type') ?? '').toLowerCase().trim()));
  const textareas = Array.from(document.querySelectorAll('textarea'));
  if (textInputs.length < 12 && textareas.length === 0) return null;

  const words: string[] = [];
  const pushFrom = (raw: string) => {
    if (!raw || words.length >= 48) return;
    const matches = raw.toLowerCase().match(/\b[a-z]{3,8}\b/g);
    if (!matches) return;
    for (const w of matches) {
      words.push(w);
      if (words.length >= 48) break;
    }
  };

  for (const input of textInputs) pushFrom(input.value);
  for (const area of textareas) pushFrom(area.value);
  return words.length >= 4 ? words : null;
}

addWindowListener(
  'input',
  () => {
    if (seedWarningShown) return;
    if (seedDebounceTimer !== null) clearTimeout(seedDebounceTimer);
    seedDebounceTimer = setTimeout(() => {
      seedDebounceTimer = null;
      if (seedWarningShown) return;
      const words = collectCandidateSeedWords();
      if (!words) return;
      const req: SeedFormCheckRequest = { type: 'seed-form-check', words };
      void sendRuntimeMessage<SeedFormCheckResponse>(req).then((res) => {
        if (seedWarningShown || !res || res.bip39Count < 4) return;
        seedWarningShown = true;
        showOverlayNotice({
          kind: 'seed-form',
          tone: 'danger',
          title: 'Seed phrase input detected',
          message:
            'You are typing seed phrase words into a webpage. Legitimate Solana apps never ask for your 12- or 24-word recovery phrase.',
          timeoutMs: 0,
          actions: [{ label: 'Got it', primary: true }],
        });
      });
    }, 400);
  },
  true,
);
}

initAegisContentScript();
