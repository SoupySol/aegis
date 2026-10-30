/**
 * e2e-spike.mjs: automated Phase 0 verification of the spike extension.
 * Loads dist/spike into Playwright's Chromium (headless, isolated profile),
 * serves the local test dApp, and checks:
 *   1. Wallet Standard hook: sign requests are paused BEFORE the (mock) wallet runs.
 *   2. Paste guard: a test private key paste is blocked; a contract address paste is not.
 *   3. Clipboard guard: a test key on the clipboard is detected and cleared after the countdown.
 * All keys are generated here from random bytes (throwaway test values). No network beyond localhost.
 */
import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';

const here = dirname(fileURLToPath(import.meta.url));
const extPath = join(here, '..', '..', 'dist', 'spike');
const html = readFileSync(join(here, 'test-dapp.html'));

const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
};

// Throwaway test key
const seed = crypto.getRandomValues(new Uint8Array(32));
const pub = ed25519.getPublicKey(seed);
const testSecret = base58.encode(Uint8Array.from([...seed, ...pub]));
const testCA = base58.encode(crypto.getRandomValues(new Uint8Array(32)));

const server = createServer((_req, res) => {
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(html);
}).listen(0, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const url = `http://127.0.0.1:${server.address().port}/`;

const profile = mkdtempSync(join(tmpdir(), 'aegis-spike-'));
const context = await chromium.launchPersistentContext(profile, {
  channel: 'chromium',
  headless: true,
  args: [`--disable-extensions-except=${extPath}`, `--load-extension=${extPath}`],
});

try {
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent('serviceworker');
  const extId = new URL(sw.url()).host;
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: url });

  const page = await context.newPage();
  const logs = [];
  page.on('console', (m) => logs.push(m.text()));
  await page.goto(url);
  await page.waitForTimeout(500);

  // ---- 1. Wallet hook ----
  check('inpage hooks installed at document_start', logs.some((l) => l.includes('inpage hooks installed')));
  check('mock Wallet Standard wallet was wrapped', logs.some((l) => l.includes('Wallet Standard wallet wrapped')));

  page.once('dialog', (d) => d.dismiss());
  const rejected = await page.evaluate(() => window.requestSign());
  const callsAfterReject = await page.evaluate(() => window.__walletCalls.slice());
  check('rejecting in Aegis returns code 4001 to the dApp', rejected === 'rejected:4001', rejected);
  check('wallet NEVER ran when Aegis rejected', !callsAfterReject.includes('signTransaction'));

  page.once('dialog', (d) => d.accept());
  const approved = await page.evaluate(() => window.requestSign());
  const callsAfterApprove = await page.evaluate(() => window.__walletCalls.slice());
  check('approving forwards to the wallet (private #fields intact)', approved === 'signed:1' && callsAfterApprove.includes('signTransaction'), approved);
  check('intercept was logged before the wallet ran', logs.some((l) => l.includes('INTERCEPTED before wallet opened')));

  // ---- 2. Paste guard ----
  const pasteResult = await page.evaluate(([secret, ca]) => {
    const field = document.getElementById('importField');
    const fire = (text) => {
      const dt = new DataTransfer();
      dt.setData('text/plain', text);
      field.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
    };
    fire(secret);
    const afterSecret = window.__pasteSeen.length;
    fire(ca);
    return { afterSecret, afterCA: window.__pasteSeen.length };
  }, [testSecret, testCA]);
  check('test private key paste blocked before the page saw it', pasteResult.afterSecret === 0);
  check('contract address paste allowed through', pasteResult.afterCA === 1);

  // ---- 3. Clipboard guard (offscreen poller + countdown) ----
  await page.bringToFront();
  await page.evaluate((s) => navigator.clipboard.writeText(s), testSecret);
  await page.waitForTimeout(2500);
  const badge = await sw.evaluate(() => chrome.action.getBadgeText({}));
  check('clipboard secret detected (badge countdown running)', /^\d+$/.test(badge), `badge="${badge}"`);

  console.log('...waiting for the 30s countdown');
  await page.waitForTimeout(31000);
  const after = await page.evaluate(() => navigator.clipboard.readText());
  check('clipboard cleared after countdown', after === '', after === '' ? 'empty' : 'still has content');

  await page.evaluate((s) => navigator.clipboard.writeText(s), testCA);
  await page.waitForTimeout(2000);
  const badgeCA = await sw.evaluate(() => chrome.action.getBadgeText({}));
  check('contract address on clipboard: no alert', badgeCA === '', `badge="${badgeCA}"`);
  console.log(`extension id: ${extId}`);
} finally {
  await context.close();
  server.close();
  rmSync(profile, { recursive: true, force: true });
}

const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);

