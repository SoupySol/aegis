/**
 * overlay.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Renders high-contrast dark security banners and notices inside a
 *           closed Shadow DOM root so page CSS cannot hide or restyle them and
 *           page scripts cannot click action buttons.
 * ACCESS:   DOM of the current page (attaches closed shadow host element).
 * NEVER:    No network, no storage, never displays or retains raw secrets,
 *           never accepts untrusted/synthetic click events.
 * ---------------------------------------------------------------------------
 */

export type NoticeTone = 'danger' | 'caution' | 'info';

export interface OverlayAction {
  label: string;
  primary?: boolean;
  onClick?: () => void;
}

export interface OverlayNoticeOptions {
  kind: 'paste-blocked' | 'seed-form' | 'clipboard-swap' | 'lookalike' | 'info';
  tone: NoticeTone;
  title: string;
  message: string;
  /** Optional public-address comparison rows (never secrets). */
  comparison?: Array<{ label: string; value: string }>;
  actions?: OverlayAction[];
  /** Auto-dismiss timeout in ms; 0 = keep open until user dismisses. */
  timeoutMs?: number;
}

const SHADOW_CSS = `
  :host {
    all: initial;
  }
  .card {
    font: 13px/1.45 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0d1117;
    color: #f1f4f9;
    border: 1px solid #2b3545;
    border-left-width: 3px;
    border-radius: 4px;
    padding: 13px 15px;
    width: min(440px, calc(100vw - 32px));
    box-shadow: 0 16px 36px rgba(0, 0, 0, 0.72), 0 0 0 1px rgba(9, 11, 15, 0.9);
    box-sizing: border-box;
  }
  .card.danger {
    border-color: rgba(239, 68, 68, 0.42);
    border-left-color: #ef4444;
    background: #120b0e;
  }
  .card.caution {
    border-color: rgba(234, 179, 8, 0.38);
    border-left-color: #eab308;
    background: #11100a;
  }
  .card.info {
    border-color: rgba(16, 185, 129, 0.38);
    border-left-color: #10b981;
  }
  .hdr {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
  }
  .mark {
    width: 16px;
    height: 16px;
    flex-shrink: 0;
  }
  .badge {
    font: 600 10px/1 'JetBrains Mono', 'Cascadia Code', ui-monospace, Consolas, monospace;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    padding: 3px 6px;
    border-radius: 3px;
    border: 1px solid rgba(239, 68, 68, 0.4);
    background: rgba(239, 68, 68, 0.12);
    color: #f87171;
  }
  .card.caution .badge {
    border-color: rgba(234, 179, 8, 0.38);
    background: rgba(234, 179, 8, 0.11);
    color: #facc15;
  }
  .card.info .badge {
    border-color: rgba(16, 185, 129, 0.38);
    background: rgba(16, 185, 129, 0.11);
    color: #34d399;
  }
  .title {
    font-size: 13px;
    font-weight: 600;
    color: #ffffff;
  }
  .msg {
    color: #bcc6d4;
    font-size: 12px;
    margin-top: 4px;
  }
  .cmp {
    margin-top: 9px;
    background: #06080b;
    border: 1px solid #1d2430;
    border-radius: 3px;
    padding: 8px 10px;
    display: grid;
    gap: 6px;
  }
  .cmp-row {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .cmp-lbl {
    font: 600 10px/1 'JetBrains Mono', 'Cascadia Code', ui-monospace, Consolas, monospace;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #7b8798;
  }
  .cmp-val {
    font-family: 'JetBrains Mono', 'Cascadia Code', ui-monospace, Consolas, monospace;
    font-size: 11.5px;
    color: #f8fafc;
    word-break: break-all;
  }
  .actions {
    margin-top: 11px;
    display: flex;
    gap: 7px;
    justify-content: flex-end;
    flex-wrap: wrap;
  }
  button {
    font: 600 11.5px/1 'Inter', 'Segoe UI', system-ui, sans-serif;
    padding: 7px 12px;
    border-radius: 3px;
    border: 1px solid #2b3545;
    background: #141922;
    color: #e2e8f0;
    cursor: pointer;
    transition: background 110ms ease, border-color 110ms ease;
  }
  button:hover {
    background: #1c2432;
    border-color: #3d4b61;
  }
  button.primary {
    background: #991b1b;
    border-color: #dc2626;
    color: #ffffff;
  }
  .card.caution button.primary {
    background: rgba(234, 179, 8, 0.18);
    border-color: #eab308;
    color: #fef08a;
  }
  .card.info button.primary {
    background: #0b7a56;
    border-color: #10b981;
    color: #ffffff;
  }
`;

function mountHost(host: HTMLElement): void {
  const attach = () => {
    const parent = document.body ?? document.documentElement;
    if (parent) parent.appendChild(host);
  };
  if (document.body || document.documentElement) {
    attach();
  } else {
    window.addEventListener('DOMContentLoaded', attach, { once: true });
  }
}

export function showOverlayNotice(opts: OverlayNoticeOptions): () => void {
  const host = document.createElement('div');
  host.setAttribute('data-aegis-alert', opts.kind);
  host.style.cssText =
    'all:initial;position:fixed;top:16px;right:16px;z-index:2147483647;display:block;pointer-events:auto;';

  // ARCHITECTURAL DESIGN NOTE: Closed Shadow DOM Root & CSS Encapsulation
  // 1. `mode: 'closed'`: Unlike open shadow roots where `host.shadowRoot` is accessible to page
  //    scripts via DOM traversal, `closed` mode returns `null`. Malicious scripts cannot inspect
  //    the warning banner DOM or programmatically select internal action buttons.
  // 2. `all: initial` in `:host`: Resets all inherited CSS styles to browser defaults, preventing
  //    host page stylesheets from hiding the alert with `opacity: 0`, `font-size: 0`, or `display: none`.
  const shadow = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = SHADOW_CSS;
  shadow.appendChild(style);

  const card = document.createElement('div');
  card.className = `card ${opts.tone}`;
  card.setAttribute('role', 'alert');

  const hdr = document.createElement('div');
  hdr.className = 'hdr';
  const svgNs = 'http://www.w3.org/2000/svg';
  const mark = document.createElementNS(svgNs, 'svg');
  mark.setAttribute('viewBox', '0 0 32 32');
  mark.setAttribute('fill', 'none');
  mark.setAttribute('aria-hidden', 'true');
  mark.setAttribute('class', 'mark');
  const shieldPath = document.createElementNS(svgNs, 'path');
  shieldPath.setAttribute('d', 'M16 2L28.2 5.8L27.2 17.2L16 30L4.8 17.2L3.8 5.8L16 2Z');
  shieldPath.setAttribute('fill', '#0E131B');
  shieldPath.setAttribute(
    'stroke',
    opts.tone === 'danger' ? '#EF4444' : opts.tone === 'caution' ? '#EAB308' : '#10B981',
  );
  shieldPath.setAttribute('stroke-width', '2');
  const aPath = document.createElementNS(svgNs, 'path');
  aPath.setAttribute('fill-rule', 'evenodd');
  aPath.setAttribute('clip-rule', 'evenodd');
  aPath.setAttribute(
    'd',
    'M16 7.8L10.3 20.6H12.8L13.95 17.8H18.05L19.2 20.6H21.7L16 7.8ZM14.75 15.6L16 12.55L17.25 15.6H14.75Z',
  );
  aPath.setAttribute('fill', '#F1F5F9');
  mark.append(shieldPath, aPath);

  const badge = document.createElement('span');
  badge.className = 'badge';
  badge.textContent = opts.tone === 'danger' ? 'Alert' : opts.tone === 'caution' ? 'Warning' : 'Info';
  const titleEl = document.createElement('span');
  titleEl.className = 'title';
  titleEl.textContent = opts.title;
  hdr.append(mark, badge, titleEl);

  const msgEl = document.createElement('div');
  msgEl.className = 'msg';
  msgEl.textContent = opts.message;
  card.append(hdr, msgEl);

  if (opts.comparison && opts.comparison.length > 0) {
    const cmp = document.createElement('div');
    cmp.className = 'cmp';
    for (const row of opts.comparison) {
      const rowEl = document.createElement('div');
      rowEl.className = 'cmp-row';
      const lbl = document.createElement('span');
      lbl.className = 'cmp-lbl';
      lbl.textContent = row.label;
      const val = document.createElement('span');
      val.className = 'cmp-val';
      val.textContent = row.value;
      rowEl.append(lbl, val);
      cmp.appendChild(rowEl);
    }
    card.appendChild(cmp);
  }

  let closed = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const close = () => {
    if (closed) return;
    closed = true;
    if (timer !== null) clearTimeout(timer);
    host.remove();
  };

  const actions = opts.actions && opts.actions.length > 0 ? opts.actions : [{ label: 'Dismiss', primary: true }];
  const actionsRow = document.createElement('div');
  actionsRow.className = 'actions';
  for (const act of actions) {
    const btn = document.createElement('button');
    btn.type = 'button';
    if (act.primary) btn.className = 'primary';
    btn.textContent = act.label;
    btn.addEventListener('click', (event: MouseEvent) => {
      // ARCHITECTURAL DESIGN NOTE: Synthetic Event Rejection via event.isTrusted
      // Malicious dApp scripts could attempt to locate the overlay and dispatch programmatic
      // clicks (`btn.dispatchEvent(new MouseEvent('click'))`) to auto-approve "Allow on this site".
      // The W3C specification guarantees that `event.isTrusted` is true ONLY when generated by a
      // genuine user hardware action (physical mouse click / keyboard entry). Synthetic events
      // are rejected immediately.
      if (!event.isTrusted) return;
      try {
        act.onClick?.();
      } finally {
        close();
      }
    });
    actionsRow.appendChild(btn);
  }
  card.appendChild(actionsRow);
  shadow.appendChild(card);

  mountHost(host);
  const timeout = opts.timeoutMs ?? 20_000;
  if (timeout > 0) {
    timer = setTimeout(close, timeout);
  }
  return close;
}
