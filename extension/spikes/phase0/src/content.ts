/**
 * Spike: paste guard (ISOLATED world content script, document_start).
 * PURPOSE:  Prove Aegis can stop a secret key / seed phrase from being pasted
 *           into a website, before the page's own scripts see it.
 * ACCESS:   The text of a paste/drop event on this page.
 * NEVER:    No network. No storage. Pasted text is checked and discarded.
 */
import { containsConfirmedSecret, detectSecrets } from '../../../src/shared/detectors/secret-detector';

const allowedThisSession = new Set<string>();

function showBanner(message: string, onAllow: () => void): void {
  const host = document.createElement('div');
  host.style.cssText = 'all:initial;position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:2147483647;';
  // AEGIS-SECURITY: closed shadow root so page scripts can't reach the banner's buttons.
  const root = host.attachShadow({ mode: 'closed' });
  root.innerHTML = `
    <style>
      .box{font:14px/1.4 system-ui,sans-serif;background:#1a0b0b;color:#fff;border:2px solid #d93025;
           border-radius:10px;padding:14px 16px;max-width:520px;box-shadow:0 8px 30px rgba(0,0,0,.5)}
      b{color:#ff6b6b} .row{margin-top:10px;display:flex;gap:8px;justify-content:flex-end}
      button{font:inherit;border-radius:6px;border:0;padding:6px 12px;cursor:pointer}
      .ok{background:#d93025;color:#fff} .allow{background:#333;color:#ddd}
    </style>
    <div class="box"><b>ðŸ›¡ï¸ Aegis blocked this paste</b><div class="msg"></div>
      <div class="row"><button class="allow">Allow on this site</button><button class="ok">Got it</button></div></div>`;
  (root.querySelector('.msg') as HTMLElement).textContent = message;
  const close = () => host.remove();
  root.querySelector('.ok')!.addEventListener('click', close);
  root.querySelector('.allow')!.addEventListener('click', (e) => {
    if (!(e as MouseEvent).isTrusted) return; // AEGIS-SECURITY: ignore scripted clicks
    onAllow();
    close();
  });
  (document.body ?? document.documentElement).appendChild(host);
  setTimeout(close, 15000);
}

function guard(event: ClipboardEvent | DragEvent): void {
  if (allowedThisSession.has(location.origin)) return;
  const data = 'clipboardData' in event ? event.clipboardData : (event as DragEvent).dataTransfer;
  const text = data?.getData('text/plain') ?? '';
  if (!text) return;
  const result = detectSecrets(text);
  if (!containsConfirmedSecret(result)) return;
  event.preventDefault();
  event.stopImmediatePropagation();
  const f = result.findings[0]!;
  const what = f.kind === 'solana-secret-key' ? `a private key (wallet ${f.publicKeyShort})` : `a ${f.wordCount}-word seed phrase`;
  showBanner(
    `You tried to paste ${what} into ${location.hostname}. Legitimate websites never ask for your key or seed phrase.`,
    () => allowedThisSession.add(location.origin),
  );
}

// Capture phase on window, registered at document_start: runs before page listeners.
window.addEventListener('paste', guard, true);
window.addEventListener('drop', guard, true);
