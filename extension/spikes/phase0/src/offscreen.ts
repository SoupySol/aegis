/**
 * Spike: offscreen clipboard poller + countdown clear.
 * PURPOSE:  Prove an MV3 offscreen document can read the system clipboard
 *           every second and clear it when a secret is detected.
 * ACCESS:   System clipboard (read/write).
 * NEVER:    No network. No storage. Clipboard text stays in this function's
 *           local variables; only a salted fingerprint is kept between polls.
 */
import { containsConfirmedSecret, detectSecrets, type SecretFinding } from '../../../src/shared/detectors/secret-detector';
import { fingerprint } from '../../../src/shared/detectors/fingerprint';

const POLL_MS = 1000;
const DEFAULT_SECONDS = 30;

const buf = document.getElementById('buf') as HTMLTextAreaElement;

// AEGIS-PERMISSION: reads the system clipboard (requires "clipboardRead").
function readClipboard(): string {
  buf.value = '';
  buf.focus();
  document.execCommand('paste');
  const text = buf.value;
  buf.value = '';
  return text;
}

// AEGIS-PERMISSION: overwrites the system clipboard (requires "clipboardWrite").
function clearClipboard(): void {
  const onCopy = (e: ClipboardEvent) => {
    e.preventDefault();
    e.clipboardData?.setData('text/plain', '');
  };
  document.addEventListener('copy', onCopy, { once: true });
  document.execCommand('copy');
}

let lastFp = '';
let tracked: { fp: string; secondsLeft: number; findings: SecretFinding[] } | null = null;

async function poll(): Promise<void> {
  let text = readClipboard();
  const fp = text ? await fingerprint(text) : '';
  if (fp !== lastFp) {
    lastFp = fp;
    if (text) {
      const result = detectSecrets(text);
      if (result.findings.length > 0) {
        tracked = { fp, secondsLeft: DEFAULT_SECONDS, findings: result.findings };
        chrome.runtime.sendMessage({
          type: 'secret-detected',
          confirmed: containsConfirmedSecret(result),
          findings: result.findings, // contains NO secret material (see secret-detector.ts)
          seconds: DEFAULT_SECONDS,
        });
      }
    }
  }
  text = ''; // AEGIS-SECURITY: drop our reference to the clipboard text
}

function tick(): void {
  if (!tracked) return;
  tracked.secondsLeft -= 1;
  chrome.runtime.sendMessage({ type: 'countdown', secondsLeft: Math.max(tracked.secondsLeft, 0) });
  if (tracked.secondsLeft <= 0) void finishCountdown();
}

async function finishCountdown(): Promise<void> {
  if (!tracked) return;
  const current = readClipboard();
  const stillThere = current !== '' && (await fingerprint(current)) === tracked.fp;
  if (stillThere) {
    clearClipboard();
    lastFp = '';
  }
  // Spike note: the real build keeps tracking the secret for Windows clipboard history (Clip Guard).
  chrome.runtime.sendMessage({ type: 'countdown-finished', cleared: stillThere });
  tracked = null;
}

chrome.runtime.onMessage.addListener((msg: { type?: string }) => {
  if (msg.type === 'clear-now' && tracked) {
    tracked.secondsLeft = 0;
    void finishCountdown();
  }
  if (msg.type === 'extend' && tracked) tracked.secondsLeft += 30;
});

setInterval(() => void poll(), POLL_MS);
setInterval(tick, 1000);
void poll();
