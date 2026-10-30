/**
 * review.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Renders the pre-wallet analysis report inside review.html —
 *           including the Deep-Dive Approval Breakdown ("What You Are
 *           Approving") and Deep-Dive Connection Scan ("What You Are
 *           Connecting To") — and sends the user's Reject or Continue decision
 *           back to the service worker. Requires explicit risk acknowledgment
 *           checkbox on DANGER verdicts, defaults focus to Reject, and binds
 *           Escape to Reject.
 * ACCESS:   chrome.runtime.sendMessage (`review:get`, `review:decide`).
 * NEVER:    No network access, no storage, no innerHTML with untrusted text.
 * ---------------------------------------------------------------------------
 */

import type {
  AnalysisReport,
  ApprovalDetail,
  AuthorityChange,
  BalanceChange,
  ConnectDetails,
  Verdict,
} from '../shared/analysis-types';
import type {
  ReviewDecision,
  ReviewFetchRequest,
  ReviewFetchResponse,
  SiteInfo,
} from '../shared/messages';

const params = new URLSearchParams(location.search);
const reviewId = params.get('id') ?? '';

const loadingBox = document.getElementById('loadingBox') as HTMLElement;
const verdictBanner = document.getElementById('verdictBanner') as HTMLElement;
const verdictLabel = document.getElementById('verdictLabel') as HTMLElement;
const verdictSubtitle = document.getElementById('verdictSubtitle') as HTMLElement;
const rpcStatusPill = document.getElementById('rpcStatusPill') as HTMLElement;
const contextCard = document.getElementById('contextCard') as HTMLElement;
const originHost = document.getElementById('originHost') as HTMLElement;
const siteBadge = document.getElementById('siteBadge') as HTMLElement;
const siteReason = document.getElementById('siteReason') as HTMLElement;
const methodBadge = document.getElementById('methodBadge') as HTMLElement;
const walletLabel = document.getElementById('walletLabel') as HTMLElement;
const approvalCard = document.getElementById('approvalCard') as HTMLElement;
const approvalCountPill = document.getElementById('approvalCountPill') as HTMLElement;
const approvalDeepList = document.getElementById('approvalDeepList') as HTMLElement;
const connectCard = document.getElementById('connectCard') as HTMLElement;
const connectCardTitle = document.getElementById('connectCardTitle') as HTMLElement;
const connectKindPill = document.getElementById('connectKindPill') as HTMLElement;
const connectMetaGrid = document.getElementById('connectMetaGrid') as HTMLElement;
const connectAllowList = document.getElementById('connectAllowList') as HTMLElement;
const connectProtectWrap = document.getElementById('connectProtectWrap') as HTMLElement;
const connectProtectList = document.getElementById('connectProtectList') as HTMLElement;
const findingsCard = document.getElementById('findingsCard') as HTMLElement;
const findingsList = document.getElementById('findingsList') as HTMLElement;
const balancesCard = document.getElementById('balancesCard') as HTMLElement;
const balanceZeroApprovalNote = document.getElementById('balanceZeroApprovalNote') as HTMLElement;
const sendList = document.getElementById('sendList') as HTMLElement;
const receiveList = document.getElementById('receiveList') as HTMLElement;
const authorityBox = document.getElementById('authorityBox') as HTMLElement;
const authorityList = document.getElementById('authorityList') as HTMLElement;
const messageCard = document.getElementById('messageCard') as HTMLElement;
const siwsDomainNote = document.getElementById('siwsDomainNote') as HTMLElement;
const messageTextBox = document.getElementById('messageTextBox') as HTMLElement;
const techSection = document.getElementById('techSection') as HTMLDetailsElement;
const techBody = document.getElementById('techBody') as HTMLElement;
const dangerAckWrap = document.getElementById('dangerAckWrap') as HTMLElement;
const dangerAck = document.getElementById('dangerAck') as HTMLInputElement;
const btnReject = document.getElementById('btnReject') as HTMLButtonElement;
const btnApprove = document.getElementById('btnApprove') as HTMLButtonElement;
const expiryTimer = document.getElementById('expiryTimer') as HTMLElement;

let decided = false;
let countdownHandle: ReturnType<typeof setInterval> | null = null;

function shortAddr(addr: string): string {
  return addr.length > 14 ? `${addr.slice(0, 5)}…${addr.slice(-5)}` : addr;
}

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

async function submitDecision(allow: boolean): Promise<void> {
  if (decided || !reviewId) return;
  decided = true;
  btnReject.disabled = true;
  btnApprove.disabled = true;
  if (countdownHandle) clearInterval(countdownHandle);

  const payload: ReviewDecision = { type: 'review:decide', reviewId, allow };
  try {
    await sendMsg(payload);
  } finally {
    setTimeout(() => window.close(), 60);
  }
}

function hasAnyApprovalDetails(report: AnalysisReport): boolean {
  for (const tx of report.transactions ?? []) {
    if ((tx.approvalDetails?.length ?? 0) > 0 || (tx.authorityChanges?.length ?? 0) > 0) {
      return true;
    }
  }
  return false;
}

function describeVerdict(verdict: Verdict, report: AnalysisReport): string {
  const hasApproval = hasAnyApprovalDetails(report);
  switch (verdict) {
    case 'SAFE':
      if (report.connectDetails?.requestKind === 'connect') {
        return 'Read-only connection. Shares your public address only.';
      }
      if (report.connectDetails?.requestKind === 'signIn') {
        return 'Domain verified. Off-chain sign-in only.';
      }
      if (report.kind === 'message') {
        return 'Readable text signature. Moves no funds.';
      }
      return 'Simulation passed. No risky permissions or drains found.';
    case 'CAUTION':
      return 'Unverified details found. Check below before continuing.';
    case 'DANGER':
      return hasApproval
        ? 'Grants ongoing spending or account access. Check below before signing.'
        : 'High-risk warning. Reject unless you trust this action.';
    case 'UNVERIFIED':
      return 'Could not simulate on RPC. Static check only.';
  }
}

function appendKvRow(grid: HTMLElement, keyText: string, valNode: Node | string): void {
  const k = document.createElement('div');
  k.className = 'meta-key';
  k.textContent = keyText;
  const v = document.createElement('div');
  v.className = 'meta-val';
  if (typeof valNode === 'string') {
    v.textContent = valNode;
  } else {
    v.appendChild(valNode);
  }
  grid.append(k, v);
}

function makePill(text: string, tone: 'safe' | 'caution' | 'danger' | 'neutral', exactCase = false): HTMLSpanElement {
  const span = document.createElement('span');
  span.className = `pill pill-${tone}${exactCase ? ' case-exact' : ''} mono`;
  span.textContent = text;
  return span;
}

function renderSiteBadge(site: SiteInfo | undefined, fallbackOrigin: string): void {
  const host = site?.hostname || fallbackOrigin || 'unknown';
  originHost.textContent = host;

  if (!site || site.status === 'unknown') {
    siteBadge.className = 'pill pill-neutral';
    siteBadge.textContent = 'Unlisted';
    siteReason.classList.add('hidden');
    return;
  }

  if (site.status === 'official') {
    siteBadge.className = 'pill pill-safe';
    siteBadge.textContent = 'Verified';
    siteReason.classList.add('hidden');
    return;
  }

  siteBadge.className = 'pill pill-danger';
  siteBadge.textContent = 'Lookalike warning!';
  siteReason.textContent =
    site.reason ??
    `Looks like ${site.officialDomain ?? 'a known Solana app'}. Check the URL.`;
  siteReason.classList.remove('hidden');
}

function renderApprovalDeepDive(report: AnalysisReport): number {
  const details: ApprovalDetail[] = [];
  for (const tx of report.transactions ?? []) {
    if (tx.approvalDetails && tx.approvalDetails.length > 0) {
      details.push(...tx.approvalDetails);
    } else {
      for (const ac of tx.authorityChanges ?? []) {
        details.push({
          kind: ac.kind,
          permissionLabel: `${ac.kind} change`,
          account: ac.account,
          allowanceLabel: 'Ongoing account access',
          spender: ac.to,
          spenderKnown: false,
        });
      }
    }
  }

  if (details.length === 0) {
    approvalCard.classList.add('hidden');
    return 0;
  }

  approvalCard.classList.remove('hidden');
  approvalCountPill.textContent =
    details.length === 1 ? '1 approval' : `${details.length} approvals`;
  approvalDeepList.textContent = '';

  for (const item of details) {
    const box = document.createElement('div');
    box.className = 'approval-item';

    const hdr = document.createElement('div');
    hdr.className = 'approval-item-hdr';
    const titleSpan = document.createElement('span');
    titleSpan.textContent = item.permissionLabel;
    const badge = item.isUnlimited
      ? makePill('UNLIMITED', 'danger')
      : makePill('APPROVAL', 'danger');
    hdr.append(titleSpan, badge);

    const kv = document.createElement('div');
    kv.className = 'approval-kv';

    if (item.symbol || item.mint) {
      const assetWrap = document.createElement('span');
      assetWrap.className = 'mono';
      assetWrap.textContent =
        item.symbol && item.mint
          ? `${item.symbol} (${shortAddr(item.mint)})`
          : item.symbol ?? (item.mint ? shortAddr(item.mint) : '');
      if (item.mint) assetWrap.title = item.mint;
      appendKvRow(kv, 'Token', assetWrap);
    } else {
      const acctSpan = document.createElement('span');
      acctSpan.className = 'mono';
      acctSpan.textContent = shortAddr(item.account);
      acctSpan.title = item.account;
      appendKvRow(kv, 'Account', acctSpan);
    }

    const limitSpan = document.createElement('span');
    limitSpan.className = 'allowance-danger';
    limitSpan.textContent = item.allowanceLabel;
    appendKvRow(kv, 'Limit', limitSpan);

    if (item.currentBalanceAtRisk) {
      const riskSpan = document.createElement('span');
      riskSpan.className = 'mono';
      riskSpan.style.color = '#fde047';
      riskSpan.textContent = item.currentBalanceAtRisk;
      appendKvRow(kv, 'Balance', riskSpan);
    }

    const spenderWrap = document.createElement('div');
    spenderWrap.style.display = 'flex';
    spenderWrap.style.flexDirection = 'column';
    spenderWrap.style.gap = '4px';
    const spenderAddr = document.createElement('span');
    spenderAddr.className = 'mono';
    spenderAddr.style.fontSize = '11px';
    spenderAddr.textContent = item.spender;
    const spenderTagRow = document.createElement('div');
    spenderTagRow.appendChild(
      item.spenderKnown && item.spenderName
        ? makePill(`Known (${item.spenderName})`, 'neutral', true)
        : makePill('Unrecognized address', 'danger'),
    );
    spenderWrap.append(spenderAddr, spenderTagRow);
    appendKvRow(kv, 'Spender', spenderWrap);

    box.append(hdr, kv);
    approvalDeepList.appendChild(box);
  }

  return details.length;
}

function renderConnectDeepDive(cd: ConnectDetails | undefined, verdict: Verdict): void {
  if (!cd) {
    connectCard.classList.add('hidden');
    return;
  }

  const cardTone =
    verdict === 'DANGER'
      ? 'deep-card-danger'
      : verdict === 'CAUTION'
        ? 'deep-card-caution'
        : 'deep-card-safe';
  connectCard.className = `card ${cardTone}`;
  connectCard.classList.remove('hidden');

  connectCardTitle.textContent =
    cd.requestKind === 'signIn'
      ? 'Sign-In Details'
      : cd.requestKind === 'signMessage'
        ? 'Signature Scope'
        : 'Connection Details';

  const kindLabel =
    cd.requestKind === 'connect'
      ? 'Connect'
      : cd.requestKind === 'signIn'
        ? 'Sign-In'
        : cd.requestKind === 'signMessage'
          ? 'Message'
          : 'Request';
  connectKindPill.textContent = kindLabel;

  connectMetaGrid.textContent = '';

  const urlRow = document.createElement('div');
  urlRow.style.display = 'flex';
  urlRow.style.alignItems = 'center';
  urlRow.style.flexWrap = 'wrap';
  urlRow.style.gap = '6px';
  const originSpan = document.createElement('span');
  originSpan.className = 'mono';
  originSpan.textContent = cd.origin;
  urlRow.appendChild(originSpan);
  if (cd.isHttps) {
    urlRow.appendChild(makePill('HTTPS', 'safe'));
  } else if (cd.isLocalhost) {
    urlRow.appendChild(makePill('Localhost', 'neutral'));
  } else {
    urlRow.appendChild(makePill(`Unencrypted ${cd.protocol}`, 'caution'));
  }
  if (cd.hasPunycode) {
    urlRow.appendChild(makePill('Punycode IDN', 'danger'));
  }
  appendKvRow(connectMetaGrid, 'URL', urlRow);

  if (cd.siws) {
    const domRow = document.createElement('div');
    domRow.style.display = 'flex';
    domRow.style.alignItems = 'center';
    domRow.style.flexWrap = 'wrap';
    domRow.style.gap = '6px';
    const domTxt = document.createElement('span');
    domTxt.className = 'mono';
    domTxt.textContent = cd.siws.claimedDomain;
    domRow.append(
      domTxt,
      cd.siws.domainMatchesOrigin
        ? makePill('Matches site', 'safe')
        : makePill('Mismatch', 'danger'),
    );
    appendKvRow(connectMetaGrid, 'Sign-In Host', domRow);

    if (cd.siws.uri && cd.siws.uriMatchesOrigin === false) {
      const uriRow = document.createElement('div');
      uriRow.style.display = 'flex';
      uriRow.style.alignItems = 'center';
      uriRow.style.flexWrap = 'wrap';
      uriRow.style.gap = '6px';
      const uriTxt = document.createElement('span');
      uriTxt.className = 'mono';
      uriTxt.textContent = cd.siws.uri;
      uriRow.append(uriTxt, makePill('URI Mismatch', 'danger'));
      appendKvRow(connectMetaGrid, 'Sign-In URI', uriRow);
    }

    if (cd.siws.statement) {
      appendKvRow(connectMetaGrid, 'Statement', cd.siws.statement);
    }
    if (cd.siws.expirationTime) {
      const expSpan = document.createElement('span');
      expSpan.className = 'mono';
      expSpan.textContent = cd.siws.expirationTime;
      appendKvRow(connectMetaGrid, 'Expires', expSpan);
    }
  }

  connectAllowList.textContent = '';
  for (const item of cd.permissionsGranted) {
    const li = document.createElement('li');
    li.textContent = item;
    connectAllowList.appendChild(li);
  }

  connectProtectList.textContent = '';
  if (cd.protectionsKept.length === 0) {
    connectProtectWrap.classList.add('hidden');
  } else {
    connectProtectWrap.classList.remove('hidden');
    for (const item of cd.protectionsKept) {
      const li = document.createElement('li');
      li.textContent = item;
      connectProtectList.appendChild(li);
    }
  }
}

function renderBalancesAndAuthorities(report: AnalysisReport, renderedApprovalCount: number): void {
  const txs = report.transactions ?? [];
  if (report.kind !== 'transaction') return;

  balancesCard.classList.remove('hidden');
  const outgoing: BalanceChange[] = [];
  const incoming: BalanceChange[] = [];
  const authorities: AuthorityChange[] = [];

  for (const tx of txs) {
    for (const bc of tx.balanceChanges ?? []) {
      if (bc.rawChange.startsWith('-') || bc.uiChange.startsWith('-')) {
        outgoing.push(bc);
      } else if (bc.rawChange !== '0') {
        incoming.push(bc);
      }
    }
    for (const ac of tx.authorityChanges ?? []) {
      authorities.push(ac);
    }
  }

  const hasTokenDelta = [...outgoing, ...incoming].some((b) => b.asset !== 'SOL');
  if (renderedApprovalCount > 0 && !hasTokenDelta) {
    balanceZeroApprovalNote.textContent =
      'No tokens leave right now. The spender can pull approved tokens later without another prompt.';
    balanceZeroApprovalNote.classList.remove('hidden');
  } else {
    balanceZeroApprovalNote.classList.add('hidden');
  }

  sendList.textContent = '';
  receiveList.textContent = '';

  if (outgoing.length === 0) {
    const empty = document.createElement('div');
    empty.style.fontSize = '12px';
    empty.style.color = 'var(--text-dim)';
    empty.textContent = report.rpcUsed ? 'None' : 'Not simulated';
    sendList.appendChild(empty);
  } else {
    for (const item of outgoing) {
      const row = document.createElement('div');
      row.className = 'balance-row';
      const amt = document.createElement('span');
      amt.className = 'amt-out';
      amt.textContent = item.uiChange;
      const sym = document.createElement('span');
      sym.textContent = item.symbol ?? (item.asset === 'SOL' ? 'SOL' : shortAddr(item.asset));
      sym.title = item.asset;
      row.append(amt, sym);
      sendList.appendChild(row);
    }
  }

  if (incoming.length === 0) {
    const empty = document.createElement('div');
    empty.style.fontSize = '12px';
    empty.style.color = 'var(--text-dim)';
    empty.textContent = report.rpcUsed ? 'None' : 'Not simulated';
    receiveList.appendChild(empty);
  } else {
    for (const item of incoming) {
      const row = document.createElement('div');
      row.className = 'balance-row';
      const amt = document.createElement('span');
      amt.className = 'amt-in';
      amt.textContent = item.uiChange.startsWith('+') ? item.uiChange : `+${item.uiChange}`;
      const sym = document.createElement('span');
      sym.textContent = item.symbol ?? (item.asset === 'SOL' ? 'SOL' : shortAddr(item.asset));
      sym.title = item.asset;
      row.append(amt, sym);
      receiveList.appendChild(row);
    }
  }

  if (authorities.length > 0 && renderedApprovalCount === 0) {
    authorityBox.classList.remove('hidden');
    authorityList.textContent = '';
    for (const auth of authorities) {
      const card = document.createElement('div');
      card.className = 'finding-card sev-high';
      const title = document.createElement('div');
      title.className = 'finding-title';
      title.textContent = `${auth.kind}: ${shortAddr(auth.to)}`;
      const detail = document.createElement('div');
      detail.className = 'finding-detail mono';
      detail.textContent = `Account ${shortAddr(auth.account)} granted to ${auth.to}`;
      card.append(title, detail);
      authorityList.appendChild(card);
    }
  } else {
    authorityBox.classList.add('hidden');
  }
}

function renderMessageSection(report: AnalysisReport): void {
  if (!report.message) return;
  messageCard.classList.remove('hidden');
  if (report.message.isSignInWithSolana && report.message.siwsDomain) {
    siwsDomainNote.textContent = `Sign-in domain: ${report.message.siwsDomain}`;
    siwsDomainNote.classList.remove('hidden');
  }
  if (report.message.looksLikeTransaction) {
    messageTextBox.textContent =
      'Warning: Binary message bytes resemble a serialized Solana transaction.';
  } else if (typeof report.message.text === 'string') {
    messageTextBox.textContent = report.message.text || '(Empty message)';
  } else {
    messageTextBox.textContent = `Binary payload (${report.message.byteLength} bytes)`;
  }
}

function renderTechnicalDetails(report: AnalysisReport): void {
  const txs = report.transactions ?? [];
  if (txs.length === 0 && report.errors.length === 0) {
    techSection.classList.add('hidden');
    techBody.textContent = '';
    return;
  }

  techSection.classList.remove('hidden');
  techBody.textContent = '';

  for (const tx of txs) {
    const block = document.createElement('div');
    block.style.display = 'grid';
    block.style.gap = '6px';

    const hdr = document.createElement('div');
    hdr.className = 'section-title';
    hdr.style.marginBottom = '2px';
    const verLabel = tx.version === 0 ? 'v0' : tx.version === 1 ? 'v1' : 'Legacy';
    hdr.textContent = `Transaction #${tx.index + 1} (${verLabel}${tx.usesDurableNonce ? ', durable nonce' : ''})`;
    block.appendChild(hdr);

    // Programs
    if (tx.programs.length > 0) {
      const progWrap = document.createElement('div');
      progWrap.style.display = 'flex';
      progWrap.style.flexWrap = 'wrap';
      progWrap.style.gap = '6px';
      for (const p of tx.programs) {
        const tag = document.createElement('span');
        tag.className = `pill ${p.known ? 'pill-safe' : 'pill-caution'} mono`;
        tag.textContent = `${p.known ? 'Known' : 'Unknown'}: ${p.name ?? shortAddr(p.programId)}`;
        tag.title = p.programId;
        progWrap.appendChild(tag);
      }
      block.appendChild(progWrap);
    }

    // Decoded Instructions
    if (tx.instructions.length > 0) {
      const ixBox = document.createElement('div');
      ixBox.className = 'code-box';
      const lines: string[] = [];
      for (const [idx, ix] of tx.instructions.entries()) {
        const cpi = ix.inner ? ' [CPI]' : '';
        lines.push(`${idx + 1}. ${ix.name}${cpi} (${ix.programName ?? shortAddr(ix.programId)})`);
        for (const [k, v] of Object.entries(ix.params)) {
          lines.push(`   ${k}: ${v}`);
        }
      }
      ixBox.textContent = lines.join('\n');
      block.appendChild(ixBox);
    }

    // Simulation summary
    if (tx.simulation) {
      const simBox = document.createElement('div');
      simBox.className = 'code-box';
      const simLines = [
        `Simulation: ${tx.simulation.ok ? 'OK' : `Failed (${tx.simulation.error ?? 'error'})`}`,
      ];
      if (tx.simulation.unitsConsumed !== undefined) {
        simLines.push(`Compute units: ${tx.simulation.unitsConsumed.toLocaleString()}`);
      }
      if (tx.simulation.logsTail && tx.simulation.logsTail.length > 0) {
        simLines.push('Logs:', ...tx.simulation.logsTail);
      }
      simBox.textContent = simLines.join('\n');
      block.appendChild(simBox);
    }

    techBody.appendChild(block);
  }

  if (report.errors.length > 0) {
    const errHdr = document.createElement('div');
    errHdr.className = 'section-title';
    errHdr.style.color = '#fcd34d';
    errHdr.textContent = 'Errors';
    const errBox = document.createElement('div');
    errBox.className = 'code-box';
    errBox.textContent = report.errors.join('\n');
    techBody.append(errHdr, errBox);
  }
}

function startExpiryCountdown(expiresAt: number): void {
  const update = () => {
    const remainingSec = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    const mins = Math.floor(remainingSec / 60);
    const secs = String(remainingSec % 60).padStart(2, '0');
    expiryTimer.textContent = `${mins}:${secs}`;
    if (remainingSec <= 30) {
      expiryTimer.className = 'pill pill-danger mono';
    }
    if (remainingSec <= 0 && !decided) {
      void submitDecision(false);
    }
  };
  update();
  countdownHandle = setInterval(update, 1000);
}

function renderReview(data: ReviewFetchResponse): void {
  loadingBox.classList.add('hidden');
  if (!data.pending || !data.report) {
    verdictBanner.className = 'verdict-banner verdict-UNVERIFIED';
    verdictBanner.classList.remove('hidden');
    verdictLabel.textContent = 'EXPIRED';
    verdictSubtitle.textContent = data.error ?? 'This review request is no longer active.';
    btnApprove.disabled = true;
    return;
  }

  const { request, report, site, expiresAt } = data;
  const verdict = report.verdict;

  verdictBanner.className = `verdict-banner verdict-${verdict}`;
  verdictBanner.classList.remove('hidden');
  verdictLabel.textContent = verdict;
  verdictSubtitle.textContent = describeVerdict(verdict, report);

  if (report.kind === 'transaction') {
    rpcStatusPill.textContent = report.rpcUsed ? 'Simulated' : 'Static only';
    rpcStatusPill.className = `pill ${report.rpcUsed ? 'pill-safe' : 'pill-neutral'}`;
  } else {
    rpcStatusPill.textContent = report.kind === 'message' ? 'Message' : 'Connect';
    rpcStatusPill.className = 'pill pill-neutral';
  }

  contextCard.classList.remove('hidden');
  renderSiteBadge(site, request.origin);
  methodBadge.textContent = request.method;
  walletLabel.textContent = request.walletPubkey
    ? `${request.wallet} (${shortAddr(request.walletPubkey)})`
    : request.wallet;
  if (request.walletPubkey) walletLabel.title = request.walletPubkey;

  // Deep-Dive Cards: What You Are Approving / What You Are Connecting To
  const renderedApprovalCount = renderApprovalDeepDive(report);
  renderConnectDeepDive(report.connectDetails, verdict);

  // Warnings / Findings (hidden when clean so safe requests don't repeat themselves)
  const items = report.findings.filter(
    (f) => f.severity !== 'safe' && f.id !== 'sign-in-with-solana',
  );
  findingsList.textContent = '';
  if (items.length === 0) {
    findingsCard.classList.add('hidden');
  } else {
    findingsCard.classList.remove('hidden');
    for (const f of items) {
      const card = document.createElement('div');
      card.className = `finding-card sev-${f.severity}`;
      const titleRow = document.createElement('div');
      titleRow.className = 'finding-title';
      const titleSpan = document.createElement('span');
      titleSpan.textContent = f.title;
      const sevPill = document.createElement('span');
      const pillTone =
        f.severity === 'critical' || f.severity === 'high'
          ? 'pill-danger'
          : f.severity === 'medium' || f.severity === 'low'
            ? 'pill-caution'
            : 'pill-safe';
      sevPill.className = `pill ${pillTone}`;
      sevPill.textContent = f.severity.toUpperCase();
      titleRow.append(titleSpan, sevPill);

      const detail = document.createElement('div');
      detail.className = 'finding-detail';
      detail.textContent = f.detail;

      card.append(titleRow, detail);
      findingsList.appendChild(card);
    }
  }

  renderBalancesAndAuthorities(report, renderedApprovalCount);
  renderMessageSection(report);
  renderTechnicalDetails(report);

  // DANGER gate: require explicit risk checkbox before Continue enables
  if (verdict === 'DANGER') {
    dangerAckWrap.classList.remove('hidden');
    dangerAck.checked = false;
    btnApprove.disabled = true;
    dangerAck.addEventListener('change', (e) => {
      if (!e.isTrusted) return;
      btnApprove.disabled = !dangerAck.checked;
    });
  } else {
    dangerAckWrap.classList.add('hidden');
    btnApprove.disabled = false;
  }

  if (typeof expiresAt === 'number') {
    startExpiryCountdown(expiresAt);
  }

  // Default focus on Reject for safe keyboard ergonomics
  btnReject.focus();
}

btnReject.addEventListener('click', (e) => {
  if (!e.isTrusted) return;
  void submitDecision(false);
});

btnApprove.addEventListener('click', (e) => {
  if (!e.isTrusted || btnApprove.disabled) return;
  void submitDecision(true);
});

window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    e.preventDefault();
    void submitDecision(false);
  }
});

// Load review payload on startup
if (!reviewId) {
  loadingBox.textContent = 'Missing review session ID.';
  btnApprove.disabled = true;
} else {
  const req: ReviewFetchRequest = { type: 'review:get', reviewId };
  void sendMsg<ReviewFetchResponse>(req)
    .then(renderReview)
    .catch((err) => {
      loadingBox.textContent = `Could not load review session: ${err instanceof Error ? err.message : String(err)}`;
      btnApprove.disabled = true;
    });
}
