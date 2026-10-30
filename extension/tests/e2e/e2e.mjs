/**
 * e2e.mjs
 * ---------------------------------------------------------------------------
 * PURPOSE:  End-to-end Playwright verification of the production Aegis MV3
 *           extension in dist/extension/:
 *           1) Fixed extension ID === ihpojnfbapdmblojonlfopnpchokokbd
 *           2) Wallet Standard gate opens review.html popup; Reject returns
 *              4001 without invoking wallet; Continue (including DANGER risk
 *              checkbox flow) forwards to mock wallet with #private fields intact
 *           3) Paste Guard blocks Solana secret key pastes while allowing
 *              32-byte contract address pastes
 *           4) Address Swap detector raises clipboard-swap banner when address A
 *              is copied and address B is pasted
 *           5) Clipboard Guardian detects copied secret key, sets countdown
 *              badge, and overwrites clipboard with '[Aegis: cleared]'
 * ACCESS:   Local HTTP loopback server + isolated headless Chromium profile.
 * NEVER:    No external network traffic, all keys are random throwaway bytes.
 * ---------------------------------------------------------------------------
 */

import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';
import { Keypair, PublicKey, SystemProgram, Transaction } from '@solana/web3.js';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const EXPECTED_EXT_ID = 'ihpojnfbapdmblojonlfopnpchokokbd';
const here = dirname(fileURLToPath(import.meta.url));
const extPath = join(here, '..', '..', 'dist', 'extension');
const dappHtml = readFileSync(join(here, 'test-dapp.html'));

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
}

// Generate throwaway test keypair + public addresses
const seed = crypto.getRandomValues(new Uint8Array(32));
const pub = ed25519.getPublicKey(seed);
const testSecret = base58.encode(Uint8Array.from([...seed, ...pub]));
const testCA = base58.encode(crypto.getRandomValues(new Uint8Array(32)));
const copiedAddressA = base58.encode(crypto.getRandomValues(new Uint8Array(32)));
const pastedAddressB = base58.encode(crypto.getRandomValues(new Uint8Array(32)));

// Build two real serialized Solana legacy transactions (benign self-transfer + dangerous owner Assign)
const payer = Keypair.generate();
const dummyBlockhash = base58.encode(new Uint8Array(32).fill(7));

const benignTx = new Transaction({
  recentBlockhash: dummyBlockhash,
  feePayer: payer.publicKey,
}).add(
  SystemProgram.transfer({
    fromPubkey: payer.publicKey,
    toPubkey: payer.publicKey,
    lamports: 1_000,
  }),
);
const benignTxBytes = Array.from(benignTx.serialize({ requireAllSignatures: false, verifySignatures: false }));

const dangerAssignTx = new Transaction({
  recentBlockhash: dummyBlockhash,
  feePayer: payer.publicKey,
}).add(
  SystemProgram.assign({
    accountPubkey: payer.publicKey,
    programId: new PublicKey(crypto.getRandomValues(new Uint8Array(32))),
  }),
);
const dangerTxBytes = Array.from(dangerAssignTx.serialize({ requireAllSignatures: false, verifySignatures: false }));

const server = createServer((_req, res) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(dappHtml);
}).listen(0, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const dappUrl = `http://127.0.0.1:${server.address().port}/`;

const profileDir = mkdtempSync(join(tmpdir(), 'aegis-e2e-'));
const context = await chromium.launchPersistentContext(profileDir, {
  channel: 'chromium',
  headless: true,
  args: [`--disable-extensions-except=${extPath}`, `--load-extension=${extPath}`],
});

try {
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 15_000 });
  const extId = new URL(sw.url()).host;

  // ---- 0. Deterministic Extension ID & Zero Unsolicited Setup Tabs ----
  check('fixed extension ID is ihpojnfbapdmblojonlfopnpchokokbd', extId === EXPECTED_EXT_ID, extId);
  await new Promise((r) => setTimeout(r, 300));
  const unsolicitedExtTabs = context.pages().filter((p) => p.url().startsWith('chrome-extension://'));
  check('zero unsolicited onboarding/settings tabs opened on install', unsolicitedExtTabs.length === 0, `tabs=${unsolicitedExtTabs.length}`);

  // Configure 10s clipboard countdown and offline static mode so E2E completes briskly without external network traffic
  await sw.evaluate(async () => {
    const existing = await chrome.storage.local.get('settings');
    const prev = existing.settings || {};
    await chrome.storage.local.set({
      settings: {
        clipboardGuard: true,
        clipboardSeconds: 10,
        clipboardPlaceholder: '[Aegis: cleared]',
        pasteGuard: true,
        seedFormWarning: true,
        addressChecks: true,
        transactionGate: true,
        rpcFailure: 'warn',
        rpcUrl: '',
        trustedPasteOrigins: [],
        ...prev,
        rpcUrl: '',
        clipboardSeconds: 10,
        clipboardPlaceholder: '[Aegis: cleared]',
        onboardingDone: true,
      },
    });
  });

  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: dappUrl });

  const page = await context.newPage();
  await page.goto(dappUrl);
  await page.waitForTimeout(400);

  // ---- 1. Wallet Standard Gate: Reject Flow ----
  const reviewPopup1Promise = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const rejectCallPromise = page.evaluate(
    ([bytes, addr]) => window.requestSign(bytes, addr),
    [benignTxBytes, payer.publicKey.toBase58()],
  );

  const reviewPage1 = await reviewPopup1Promise;
  await reviewPage1.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 10_000 });
  check('review.html popup window opened for signTransaction', reviewPage1.url().startsWith(`chrome-extension://${EXPECTED_EXT_ID}/review.html`));

  await reviewPage1.click('#btnReject');
  const rejectOutcome = await rejectCallPromise;
  const walletCallsAfterReject = await page.evaluate(() => window.__walletCalls.slice());

  check('clicking Reject returns code 4001 to dApp', rejectOutcome === 'rejected:4001', rejectOutcome);
  check('mock wallet never ran when Aegis rejected', !walletCallsAfterReject.includes('signTransaction'));

  // ---- 2. Wallet Standard Gate: Approve Flow (with DANGER checkbox verification) ----
  const reviewPopup2Promise = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const approveCallPromise = page.evaluate(
    ([bytes, addr]) => window.requestSign(bytes, addr),
    [dangerTxBytes, payer.publicKey.toBase58()],
  );

  const reviewPage2 = await reviewPopup2Promise;
  await reviewPage2.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 10_000 });

  const verdictText = (await reviewPage2.textContent('#verdictLabel'))?.trim();
  const ackVisible = await reviewPage2.locator('#dangerAckWrap').isVisible();
  if (ackVisible) {
    const disabledBeforeCheck = await reviewPage2.locator('#btnApprove').isDisabled();
    check('DANGER verdict disables Continue until risk box is checked', disabledBeforeCheck === true, `verdict=${verdictText}`);
    await reviewPage2.check('#dangerAck');
  }

  await reviewPage2.click('#btnApprove');
  const approveOutcome = await approveCallPromise;
  const walletCallsAfterApprove = await page.evaluate(() => window.__walletCalls.slice());

  check(
    'clicking Continue forwards to mock wallet with #private fields intact',
    approveOutcome === 'signed:1' && walletCallsAfterApprove.includes('signTransaction'),
    approveOutcome,
  );

  // ---- 3. Paste Guard ----
  await page.bringToFront();
  const pasteOutcome = await page.evaluate(
    ([secret, ca]) => {
      const field = document.getElementById('importField');
      const dispatchPaste = (text) => {
        const dt = new DataTransfer();
        dt.setData('text/plain', text);
        field.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
      };
      dispatchPaste(secret);
      const afterSecret = window.__pasteSeen.length;
      dispatchPaste(ca);
      return { afterSecret, afterCA: window.__pasteSeen.length };
    },
    [testSecret, testCA],
  );

  await page.waitForSelector('[data-aegis-alert="paste-blocked"]', { state: 'attached', timeout: 5_000 });
  check('Paste Guard blocked Solana secret key before page saw it', pasteOutcome.afterSecret === 0);
  check('Paste Guard allowed 32-byte contract address paste through', pasteOutcome.afterCA === 1);

  // ---- 4. Address Swap Warning ----
  await page.evaluate((addrA) => {
    const field = document.getElementById('importField');
    const dt = new DataTransfer();
    dt.setData('text/plain', addrA);
    field.dispatchEvent(new ClipboardEvent('copy', { clipboardData: dt, bubbles: true, cancelable: true }));
  }, copiedAddressA);

  await page.waitForTimeout(300);

  await page.evaluate((addrB) => {
    const field = document.getElementById('importField');
    const dt = new DataTransfer();
    dt.setData('text/plain', addrB);
    field.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
  }, pastedAddressB);

  const swapBanner = await page.waitForSelector('[data-aegis-alert="clipboard-swap"]', {
    state: 'attached',
    timeout: 5_000,
  });
  check('Address Swap warning triggered when copying address A and pasting address B', Boolean(swapBanner));

  // ---- 5. Clipboard Guardian (offscreen poller + 10s countdown -> '[Aegis: cleared]') ----
  await page.bringToFront();
  await page.evaluate((s) => navigator.clipboard.writeText(s), testSecret);
  await page.waitForTimeout(2200);

  const badgeActive = await sw.evaluate(() => chrome.action.getBadgeText({}));
  check('Clipboard Guardian detected secret key and set countdown badge', /^\d+$/.test(badgeActive), `badge="${badgeActive}"`);

  console.log('...waiting for configured 10s clipboard countdown to clear');
  await page.waitForTimeout(10_500);
  await page.bringToFront();

  const clipboardAfter = await page.evaluate(() => navigator.clipboard.readText());
  const badgeAfter = await sw.evaluate(() => chrome.action.getBadgeText({}));
  check(
    'Clipboard overwritten with "[Aegis: cleared]" after countdown',
    clipboardAfter === '[Aegis: cleared]',
    `clipboard="${clipboardAfter}"`,
  );
  check('Badge cleared after countdown finished', badgeAfter === '', `badge="${badgeAfter}"`);

  // Ensure 32-byte contract address on clipboard triggers zero countdown alert
  await page.evaluate((ca) => navigator.clipboard.writeText(ca), testCA);
  await page.waitForTimeout(2000);
  const badgeForCA = await sw.evaluate(() => chrome.action.getBadgeText({}));
  check('32-byte contract address on clipboard causes no false alert', badgeForCA === '', `badge="${badgeForCA}"`);
} finally {
  await context.close();
  server.close();
  rmSync(profileDir, { recursive: true, force: true });
}

const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} E2E checks passed`);
process.exit(failed ? 1 : 0);
