/**
 * e2e-qa-deep.mjs
 * ---------------------------------------------------------------------------
 * PURPOSE:  Deep E2E & UI QA verification suite for the built Aegis Wallet
 *           Shield MV3 extension (`dist/extension`), covering:
 *           1) UI Pages Health & Console Audit (`onboarding`, `popup`,
 *              `options`, `blocked`, `review`) + zero `pageerror`/console errors
 *           2) Exposure Checkup End-to-End against local mock Solana JSON-RPC
 *           3) Legacy Injected Provider (`window.solana`) & Batch Transactions
 *              (`signTransaction`, `signAllTransactions` worst-verdict DANGER,
 *              `signMessage`, plus provider/cross-realm/signIn edge probes)
 *           4) `signMessage` Review Cases (UTF-8 SAFE, SIWS domain mismatch
 *              DANGER, disguised serialized Solana tx bytes DANGER)
 *           5) Untrusted Scripted Click Resistance (`event.isTrusted` + closed
 *              Shadow Root isolation + CDP internal button synthetic click test)
 *           6) Recovery-Phrase Form Warning (`<textarea>` & 12 `<input>`s) +
 *              Address Lookalike detection (plus in-browser copy-then-paste probe)
 *           7) Domain Blocklist (`declarativeNetRequest`) & Session Bypass
 *              (exact domain + subdomain + multi-query-param URL probes)
 * ACCESS:   Local HTTP loopback servers (`127.0.0.1`) + isolated Chromium profile.
 * NEVER:    Zero external network traffic; all keys are random throwaway bytes.
 * ---------------------------------------------------------------------------
 */

import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';
import { Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction } from '@solana/web3.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const EXPECTED_EXT_ID = 'ihpojnfbapdmblojonlfopnpchokokbd';
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const here = dirname(fileURLToPath(import.meta.url));
const extPath = join(here, '..', '..', 'dist', 'extension');

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
}

function generateValid32ByteAddress44() {
  while (true) {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    raw[0] = 40 + (raw[0] % 60);
    const encoded = base58.encode(raw);
    if (encoded.length === 44) return encoded;
  }
}

function makeLookalike32ByteAddress(addr) {
  const mid = Math.floor(addr.length / 2);
  for (const ch of B58_ALPHABET) {
    if (ch === addr[mid]) continue;
    const candidate = addr.slice(0, mid) + ch + addr.slice(mid + 1);
    try {
      const decoded = base58.decode(candidate);
      if (
        decoded.length === 32 &&
        base58.encode(decoded) === candidate &&
        candidate.slice(0, 4) === addr.slice(0, 4) &&
        candidate.slice(-4) === addr.slice(-4)
      ) {
        return candidate;
      }
    } catch {
      /* continue */
    }
  }
  throw new Error('Failed to generate valid 32-byte lookalike address');
}

// ---- Test Cryptographic Fixtures (100% random throwaway) -------------------
const seed = crypto.getRandomValues(new Uint8Array(32));
const pub = ed25519.getPublicKey(seed);
const testSecretKey = base58.encode(Uint8Array.from([...seed, ...pub]));

const payer = Keypair.generate();
const payerAddress = payer.publicKey.toBase58();
const exposureWallet = Keypair.generate().publicKey.toBase58();
const mockTokenAccountPubkey = Keypair.generate().publicKey.toBase58();
const mockDelegatePubkey = Keypair.generate().publicKey.toBase58();
const attackerProgramPubkey = Keypair.generate().publicKey;

const addressA = generateValid32ByteAddress44();
const addressALookalike = makeLookalike32ByteAddress(addressA);
const addressC = generateValid32ByteAddress44();
const addressCLookalike = makeLookalike32ByteAddress(addressC);

const dummyBlockhash = base58.encode(new Uint8Array(32).fill(9));

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
    programId: attackerProgramPubkey,
  }),
);
const dangerTxBytes = Array.from(dangerAssignTx.serialize({ requireAllSignatures: false, verifySignatures: false }));

// Additional fixtures for Section 10 (Swap Fast-Path vs Deep-Dive Approve & Connect)
const TOKEN_PROGRAM_PK = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const JUPITER_V6_PK = new PublicKey('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4');
const USDC_MINT_PK = new PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
const swapMemeMintPk = Keypair.generate().publicKey;
const userUsdcAtaPk = Keypair.generate().publicKey;
const userMemeAtaPk = Keypair.generate().publicKey;
const drainerSpenderPk = Keypair.generate().publicKey;

function buildApproveIx(source, delegate, owner, amountBigInt) {
  const data = Buffer.alloc(9);
  data[0] = 4; // SPL Token: Approve
  data.writeBigUInt64LE(amountBigInt, 1);
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_PK,
    keys: [
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: delegate, isSigner: false, isWritable: false },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
    data,
  });
}

function buildRpcTokenAccount({ mintPk, ownerPk, amount, delegatePk = null, delegatedAmount = 0n }) {
  const buf = Buffer.alloc(165);
  Buffer.from(mintPk.toBytes()).copy(buf, 0);
  Buffer.from(ownerPk.toBytes()).copy(buf, 32);
  buf.writeBigUInt64LE(amount, 64);
  if (delegatePk) {
    buf.writeUInt32LE(1, 72);
    Buffer.from(delegatePk.toBytes()).copy(buf, 76);
  }
  buf[108] = 1; // initialized
  buf.writeBigUInt64LE(delegatedAmount, 121);
  return {
    lamports: 2_039_280,
    owner: TOKEN_PROGRAM_PK.toBase58(),
    data: [buf.toString('base64'), 'base64'],
    executable: false,
    rentEpoch: 0,
  };
}

function buildRpcMintAccount(decimals) {
  const buf = Buffer.alloc(82);
  buf.writeBigUInt64LE(1_000_000_000_000n, 36);
  buf[44] = decimals;
  buf[45] = 1; // isInitialized
  return {
    lamports: 1_461_600,
    owner: TOKEN_PROGRAM_PK.toBase58(),
    data: [buf.toString('base64'), 'base64'],
    executable: false,
    rentEpoch: 0,
  };
}

const jupiterSwapIx = new TransactionInstruction({
  programId: JUPITER_V6_PK,
  keys: [
    { pubkey: payer.publicKey, isSigner: true, isWritable: true },
    { pubkey: userMemeAtaPk, isSigner: false, isWritable: true },
  ],
  data: Buffer.from([0xe4, 0x45, 0xa5, 0x2e, 0x01]),
});

const cleanSwapBuyTx = new Transaction({
  recentBlockhash: dummyBlockhash,
  feePayer: payer.publicKey,
}).add(jupiterSwapIx);
const cleanSwapBuyBytes = Array.from(cleanSwapBuyTx.serialize({ requireAllSignatures: false, verifySignatures: false }));

const U64_MAX = 18_446_744_073_709_551_615n;
const trojanSwapApproveTx = new Transaction({
  recentBlockhash: dummyBlockhash,
  feePayer: payer.publicKey,
}).add(jupiterSwapIx, buildApproveIx(userUsdcAtaPk, drainerSpenderPk, payer.publicKey, U64_MAX));
const trojanSwapApproveBytes = Array.from(
  trojanSwapApproveTx.serialize({ requireAllSignatures: false, verifySignatures: false }),
);

const pureApprove250UsdcTx = new Transaction({
  recentBlockhash: dummyBlockhash,
  feePayer: payer.publicKey,
}).add(buildApproveIx(userUsdcAtaPk, drainerSpenderPk, payer.publicKey, 250_000_000n));
const pureApprove250UsdcBytes = Array.from(
  pureApprove250UsdcTx.serialize({ requireAllSignatures: false, verifySignatures: false }),
);

let mockPostUsdcDelegateAmount = 0n;

// ---- Local Mock Solana JSON-RPC Server (127.0.0.1) -------------------------
const MOCK_SLOT = 312_345_678;
const rpcCallLog = [];

const rpcServer = createServer((req, res) => {
  if (req.method !== 'POST') {
    res.writeHead(405);
    res.end();
    return;
  }
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
  });
  req.on('end', () => {
    let parsed;
    try {
      parsed = JSON.parse(body);
    } catch {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
      return;
    }

    const { id, method, params } = parsed;
    rpcCallLog.push(method);

    const reply = (result) => {
      res.writeHead(200, {
        'content-type': 'application/json',
        'access-control-allow-origin': '*',
      });
      res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
    };

    if (method === 'getSlot') {
      reply(MOCK_SLOT);
      return;
    }

    if (method === 'getAccountInfo') {
      reply({
        context: { slot: MOCK_SLOT },
        value: {
          lamports: 2_500_000_000,
          owner: '11111111111111111111111111111111',
          data: ['', 'base64'],
          executable: false,
          rentEpoch: 0,
        },
      });
      return;
    }

    if (method === 'getTokenAccountsByOwner') {
      const ownerAddr = params?.[0];
      const programFilter = params?.[1]?.programId;
      if (programFilter === 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA') {
        reply({
          context: { slot: MOCK_SLOT },
          value: [
            {
              pubkey: mockTokenAccountPubkey,
              account: {
                lamports: 2_039_280,
                owner: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                executable: false,
                rentEpoch: 0,
                data: {
                  program: 'spl-token',
                  space: 165,
                  parsed: {
                    type: 'account',
                    info: {
                      isNative: false,
                      mint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
                      owner: ownerAddr,
                      state: 'initialized',
                      delegate: mockDelegatePubkey,
                      delegatedAmount: {
                        amount: '500000000',
                        decimals: 6,
                        uiAmount: 500,
                        uiAmountString: '500',
                      },
                      tokenAmount: {
                        amount: '1000000000',
                        decimals: 6,
                        uiAmount: 1000,
                        uiAmountString: '1000',
                      },
                    },
                  },
                },
              },
            },
          ],
        });
      } else {
        reply({ context: { slot: MOCK_SLOT }, value: [] });
      }
      return;
    }

    if (method === 'getMultipleAccounts') {
      const addrs = Array.isArray(params?.[0]) ? params[0] : [];
      reply({
        context: { slot: MOCK_SLOT },
        value: addrs.map((addr) => {
          if (addr === payerAddress) {
            return {
              lamports: 5_000_000_000,
              owner: '11111111111111111111111111111111',
              data: ['', 'base64'],
              executable: false,
              rentEpoch: 0,
            };
          }
          if (addr === userUsdcAtaPk.toBase58()) {
            return buildRpcTokenAccount({
              mintPk: USDC_MINT_PK,
              ownerPk: payer.publicKey,
              amount: 1_500_000_000n,
            });
          }
          if (addr === USDC_MINT_PK.toBase58() || addr === swapMemeMintPk.toBase58()) {
            return buildRpcMintAccount(6);
          }
          return null;
        }),
      });
      return;
    }

    if (method === 'simulateTransaction') {
      const simAddrs = params?.[1]?.accounts?.addresses ?? [];
      const touchesSwapAta = simAddrs.includes(userMemeAtaPk.toBase58());
      const touchesUsdcAta = simAddrs.includes(userUsdcAtaPk.toBase58());
      reply({
        context: { slot: MOCK_SLOT },
        value: {
          err: null,
          unitsConsumed: 450,
          logs: [
            'Program 11111111111111111111111111111111 invoke [1]',
            'Program 11111111111111111111111111111111 success',
          ],
          innerInstructions: [],
          accounts: simAddrs.map((addr) => {
            if (addr === payerAddress) {
              return {
                lamports: touchesSwapAta ? 4_000_000_000 : 4_999_995_000,
                owner: '11111111111111111111111111111111',
                data: ['', 'base64'],
                executable: false,
                rentEpoch: 0,
              };
            }
            if (addr === userMemeAtaPk.toBase58()) {
              return buildRpcTokenAccount({
                mintPk: swapMemeMintPk,
                ownerPk: payer.publicKey,
                amount: 50_000_000_000n,
              });
            }
            if (addr === userUsdcAtaPk.toBase58() && touchesUsdcAta) {
              return buildRpcTokenAccount({
                mintPk: USDC_MINT_PK,
                ownerPk: payer.publicKey,
                amount: 1_500_000_000n,
                delegatePk: mockPostUsdcDelegateAmount > 0n ? drainerSpenderPk : null,
                delegatedAmount: mockPostUsdcDelegateAmount,
              });
            }
            return null;
          }),
        },
      });
      return;
    }

    reply(null);
  });
}).listen(0, '127.0.0.1');

await new Promise((r) => rpcServer.once('listening', r));
const rpcPort = rpcServer.address().port;
const mockRpcUrl = `http://127.0.0.1:${rpcPort}/`;

// ---- Local Mock HTTP dApp Server (127.0.0.1) -------------------------------
function buildMainDappHtml(walletPubkey) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Aegis Deep QA Mock dApp</title>
    <script>
      window.__legacyCalls = [];
      window.__standardCalls = [];
      window.__phantomLateCalls = [];
      window.__pasteLog = [];

      // 1. Legacy window.solana provider (assigned after inpage.js hookGlobal)
      window.solana = {
        isPhantom: true,
        publicKey: { toBase58: () => ${JSON.stringify(walletPubkey)} },
        connect: async () => {
          window.__legacyCalls.push('connect');
          return { publicKey: { toBase58: () => ${JSON.stringify(walletPubkey)} } };
        },
        signTransaction: async (tx) => {
          window.__legacyCalls.push('signTransaction');
          return tx;
        },
        signAllTransactions: async (txs) => {
          window.__legacyCalls.push('signAllTransactions:' + txs.length);
          return txs;
        },
        signMessage: async (msg) => {
          window.__legacyCalls.push('signMessage:' + (msg ? msg.byteLength : 0));
          return { signature: new Uint8Array(64).fill(1), publicKey: ${JSON.stringify(walletPubkey)} };
        },
        signIn: async (input) => {
          window.__legacyCalls.push('signIn');
          return { account: { address: ${JSON.stringify(walletPubkey)} }, signedMessage: new Uint8Array(10), signature: new Uint8Array(64) };
        },
      };

      // 2. Multi-step window.phantom = {}; window.phantom.solana = ... (common multi-chain injection pattern)
      window.phantom = window.phantom || {};
      window.phantom.solana = {
        isPhantom: true,
        publicKey: { toBase58: () => ${JSON.stringify(walletPubkey)} },
        signTransaction: async (tx) => {
          window.__phantomLateCalls.push('signTransaction');
          return tx;
        },
      };

      // 3. Wallet Standard wallet including solana:signIn
      class DeepMockStandardWallet {
        #priv = 'ok';
        get name() { return 'DeepMockWallet'; }
        get version() { return '1.0.0'; }
        get chains() { return ['solana:mainnet']; }
        get accounts() { return []; }
        get features() {
          const self = this;
          return {
            'standard:connect': {
              version: '1.0.0',
              connect: async () => {
                if (self.#priv !== 'ok') throw new Error('broken #priv');
                window.__standardCalls.push('connect');
                return { accounts: [] };
              },
            },
            'solana:signTransaction': {
              version: '1.0.0',
              supportedTransactionVersions: ['legacy', 0],
              signTransaction: async (...inputs) => {
                if (self.#priv !== 'ok') throw new Error('broken #priv');
                window.__standardCalls.push('signTransaction:' + inputs.length);
                return inputs.map((i) => ({ signedTransaction: i.transaction }));
              },
            },
            'solana:signMessage': {
              version: '1.0.0',
              signMessage: async (...inputs) => {
                if (self.#priv !== 'ok') throw new Error('broken #priv');
                window.__standardCalls.push('signMessage');
                return inputs.map((i) => ({ signedMessage: i.message, signature: new Uint8Array(64) }));
              },
            },
            'solana:signIn': {
              version: '1.0.0',
              signIn: async (...inputs) => {
                if (self.#priv !== 'ok') throw new Error('broken #priv');
                window.__standardCalls.push('signIn');
                return inputs.map(() => ({
                  account: { address: ${JSON.stringify(walletPubkey)} },
                  signedMessage: new Uint8Array(16),
                  signature: new Uint8Array(64),
                }));
              },
            },
          };
        }
      }

      const stdWallet = new DeepMockStandardWallet();
      window.__wallets = [];
      const register = (...w) => { window.__wallets.push(...w); return () => {}; };
      window.addEventListener('wallet-standard:register-wallet', ({ detail: cb }) => cb({ register }));
      window.dispatchEvent(new CustomEvent('wallet-standard:app-ready', { detail: Object.freeze({ register }) }));
      window.dispatchEvent(new CustomEvent('wallet-standard:register-wallet', { detail: ({ register: r }) => r(stdWallet) }));
    </script>
  </head>
  <body>
    <h1 id="dappHeading">Aegis Deep QA Harness</h1>
    <div id="reqPath"></div>
    <input id="importField" type="text" placeholder="Paste target input" style="width:520px;" />
    <textarea id="seedArea" rows="4" cols="60" placeholder="Recovery phrase textarea"></textarea>
    <script>
      document.getElementById('reqPath').textContent = location.pathname + location.search + location.hash;
      const importField = document.getElementById('importField');
      importField.addEventListener('paste', (e) => {
        const txt = e.clipboardData ? e.clipboardData.getData('text/plain') : '';
        window.__pasteLog.push(txt);
      });

      window.makeSerializableTx = (bytesArr) => ({
        serialize: () => new Uint8Array(bytesArr),
      });

      window.callLegacySignTx = async (bytesArr) => {
        try {
          await window.solana.signTransaction(window.makeSerializableTx(bytesArr));
          return 'approved';
        } catch (e) {
          return 'rejected:' + (e && e.code);
        }
      };

      window.callLegacySignAllTxs = async (listOfBytesArr) => {
        try {
          const txs = listOfBytesArr.map((b) => window.makeSerializableTx(b));
          const signed = await window.solana.signAllTransactions(txs);
          return 'approved:' + signed.length;
        } catch (e) {
          return 'rejected:' + (e && e.code);
        }
      };

      window.callLegacySignMessageUtf8 = async (str) => {
        try {
          const bytes = new TextEncoder().encode(str);
          const res = await window.solana.signMessage(bytes, 'utf8');
          return 'approved:' + res.signature.byteLength;
        } catch (e) {
          return 'rejected:' + (e && e.code);
        }
      };

      window.callLegacySignMessageBytes = async (bytesArr) => {
        try {
          const bytes = new Uint8Array(bytesArr);
          const res = await window.solana.signMessage(bytes);
          return 'approved:' + res.signature.byteLength;
        } catch (e) {
          return 'rejected:' + (e && e.code);
        }
      };
    </script>
  </body>
</html>`;
}

function buildTwelveInputsHtml() {
  const inputs = Array.from({ length: 12 }, (_, i) => `<input id="w${i + 1}" type="text" placeholder="Word ${i + 1}" />`).join('\n');
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>12-Word Grid</title></head>
  <body>
    <h1>12 Input Seed Grid</h1>
    <form id="gridForm">${inputs}</form>
  </body>
</html>`;
}

function buildSolflareSuiteHtml(walletPubkey) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Solflare & Multi-Wallet Compatibility Suite</title>
    <script>
      // K1 check BEFORE any wallet injects into this page:
      window.__ghostGlobalsBeforeInject = {
        solflareInWindow: 'solflare' in window,
        okxInWindow: 'okxwallet' in window,
        magicEdenInWindow: 'magicEden' in window,
        coinbaseInWindow: 'coinbaseSolana' in window,
        solflareDocSnippetSafe: (() => {
          if ('solflare' in window) {
            return Boolean(window.solflare.isSolflare);
          }
          return true;
        })(),
      };

      // Simulate Solflare Wallet Standard registering in <head> BEFORE DOMContentLoaded
      // using { once: true } + @solana/wallet-standard frozen events + Object.freeze(wallet) + #private state!
      class FrozenRegisterWalletEvent extends Event {
        constructor(cb) {
          super('wallet-standard:register-wallet');
          this.detail = cb;
          Object.freeze(this);
        }
      }
      class FrozenAppReadyEvent extends Event {
        constructor(api) {
          super('wallet-standard:app-ready');
          this.detail = api;
          Object.freeze(this);
        }
      }
      window.__FrozenAppReadyEvent = FrozenAppReadyEvent;

      class SolflareStandardMock {
        #connected = false;
        #accounts = [];
        #connectFn = async () => {
          this.#connected = true;
          this.#accounts = [Object.freeze({
            address: ${JSON.stringify(walletPubkey)},
            chains: ['solana:mainnet'],
            features: ['solana:signTransaction', 'solana:signAndSendTransaction', 'solana:signMessage'],
          })];
          return { accounts: this.#accounts };
        };
        #signTxFn = async (...inputs) => {
          if (!this.#connected) throw new Error('Solflare not connected');
          return inputs.map((i) => ({ signedTransaction: i.transaction }));
        };
        #signAndSendFn = async (...inputs) => {
          if (!this.#connected) throw new Error('Solflare not connected');
          return inputs.map(() => ({ signature: new Uint8Array(64).fill(5) }));
        };
        get name() { return 'Solflare'; }
        get version() { return '1.0.0'; }
        get chains() { return ['solana:mainnet']; }
        get accounts() { return this.#accounts; }
        get features() {
          return Object.freeze({
            'standard:connect': Object.freeze({ version: '1.0.0', connect: this.#connectFn }),
            'solana:signTransaction': Object.freeze({
              version: '1.0.0',
              supportedTransactionVersions: ['legacy', 0],
              signTransaction: this.#signTxFn,
            }),
            'solana:signAndSendTransaction': Object.freeze({
              version: '1.0.0',
              supportedTransactionVersions: ['legacy', 0],
              signAndSendTransaction: this.#signAndSendFn,
            }),
          });
        }
      }

      const rawSolflareStd = Object.freeze(new SolflareStandardMock());
      const registerCb = ({ register }) => register(rawSolflareStd);
      window.dispatchEvent(new FrozenRegisterWalletEvent(registerCb));
      window.addEventListener('wallet-standard:app-ready', (ev) => registerCb(ev.detail), { once: true });
    </script>
  </head>
  <body>
    <h1 id="solflareReady">Solflare & Multi-Wallet Harness</h1>
    <iframe id="solflareEnclaveFrame" src="http://solflare.com:__PORT__/enclave" style="display:none"></iframe>
    <script>
      // dApp discovers Wallet Standard wallets AFTER body scripts load (just like React wallet-adapter)
      window.addEventListener('DOMContentLoaded', () => {
        const discovered = [];
        const dappApi = Object.freeze({
          register: (...ws) => {
            discovered.push(...ws);
            return () => {};
          },
        });
        window.addEventListener('wallet-standard:register-wallet', (ev) => ev.detail(dappApi));
        window.dispatchEvent(new window.__FrozenAppReadyEvent(dappApi));
        window.__solflareStdDiscovered = discovered;
      });
    </script>
  </body>
</html>`;
}

function buildEnclaveHtml() {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>Solflare Enclave</title></head>
  <body>
    <script>
      window.addEventListener('message', (ev) => {
        if (ev.data === 'ping-enclave') {
          ev.source.postMessage({ enclaveInpageActive: Boolean(window.__aegisInpageActive) }, '*');
        }
      });
    </script>
  </body>
</html>`;
}

const dappServer = createServer((req, res) => {
  const url = req.url || '/';
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  if (url.startsWith('/12-inputs')) {
    res.end(buildTwelveInputsHtml());
    return;
  }
  if (url.startsWith('/enclave')) {
    res.end(buildEnclaveHtml());
    return;
  }
  if (url.startsWith('/solflare-suite')) {
    res.end(buildSolflareSuiteHtml(payerAddress).replace('__PORT__', String(dappServer.address().port)));
    return;
  }
  res.end(buildMainDappHtml(payerAddress));
}).listen(0, '127.0.0.1');

await new Promise((r) => dappServer.once('listening', r));
const dappPort = dappServer.address().port;
const dappUrl = `http://127.0.0.1:${dappPort}/`;

// ---- Launch Persistent Chromium Context with Extension + Local Host Map ----
const profileDir = mkdtempSync(join(tmpdir(), 'aegis-qa-deep-'));
const pageErrorsByUrl = [];
const consoleErrorsByUrl = [];

function attachAuditListeners(page) {
  page.on('pageerror', (err) => {
    pageErrorsByUrl.push({ url: page.url(), message: err?.message || String(err) });
  });
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      consoleErrorsByUrl.push({ url: page.url(), text: msg.text() });
    }
  });
}

const context = await chromium.launchPersistentContext(profileDir, {
  channel: 'chromium',
  headless: true,
  args: [
    `--disable-extensions-except=${extPath}`,
    `--load-extension=${extPath}`,
    '--host-resolver-rules=MAP blocked-dapp.test 127.0.0.1,MAP app.subtest-phish.test 127.0.0.1,MAP qparam-phish.test 127.0.0.1,MAP purnp.fun 127.0.0.1,MAP solflare.com 127.0.0.1',
  ],
});

context.on('page', attachAuditListeners);
for (const existingPage of context.pages()) {
  attachAuditListeners(existingPage);
}

try {
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 15_000 });
  const extId = new URL(sw.url()).host;
  check('Extension loaded with deterministic ID ihpojnfbapdmblojonlfopnpchokokbd', extId === EXPECTED_EXT_ID, extId);

  const manifestObj = await sw.evaluate(() => chrome.runtime.getManifest());
  const manifestPermissions = manifestObj.permissions ?? [];
  check(
    'manifest.json: zero nativeMessaging, zero declarativeNetRequest, zero options_ui (lean zero-config extension)',
    !manifestPermissions.includes('nativeMessaging') &&
      !manifestPermissions.includes('declarativeNetRequest') &&
      !manifestObj.options_ui &&
      !manifestObj.optional_permissions,
    JSON.stringify(manifestPermissions),
  );

  await new Promise((r) => setTimeout(r, 400));
  const autoOpenedExtTabs = context.pages().filter((p) => p.url().startsWith('chrome-extension://'));
  check(
    'Zero-Config Install: zero unsolicited onboarding or settings tabs opened on install',
    autoOpenedExtTabs.length === 0,
    `extTabs=${autoOpenedExtTabs.length}`,
  );

  // =========================================================================
  // 1. ZERO-INPUT POPUP UI & ZERO-CONFIG DEFAULTS AUDIT
  // =========================================================================
  console.log('\n--- 1. Zero-Input Popup UI & Zero-Config Defaults Audit ---');

  const popupPage = await context.newPage();
  await popupPage.goto(`chrome-extension://${EXPECTED_EXT_ID}/popup.html`, { waitUntil: 'domcontentloaded' });
  await popupPage.waitForSelector('#shieldStatusPill', { timeout: 5_000 });
  await popupPage.waitForTimeout(350);

  const defaultDashboard = await popupPage.evaluate(
    () => new Promise((res) => chrome.runtime.sendMessage({ type: 'ui:get-dashboard' }, res)),
  );
  check(
    'Zero-Config Default Settings: live Solana Mainnet RPC enabled automatically out of the box',
    defaultDashboard?.settings?.rpcUrl === 'https://api.mainnet-beta.solana.com' &&
      defaultDashboard?.settings?.onboardingDone === true &&
      defaultDashboard?.settings?.transactionGate === true,
    `rpcUrl="${defaultDashboard?.settings?.rpcUrl}"`,
  );

  const manualInputCount = await popupPage.evaluate(
    () => document.querySelectorAll('input:not([type="checkbox"]), textarea, select').length,
  );
  const removedBtnCount = await popupPage.locator('#btnSettings, #btnExposureCheckup, #btnGhostScan').count();
  check(
    'popup.html: strictly zero manual text/number/slider inputs and zero settings-page bloat buttons',
    manualInputCount === 0 && removedBtnCount === 0,
    `manualInputs=${manualInputCount}, legacyButtons=${removedBtnCount}`,
  );

  const initialPill = (await popupPage.textContent('#shieldStatusPill'))?.trim();
  check('popup.html: renders Shield Active status cleanly', initialPill === 'Shield Active', initialPill);

  // Toggle Transaction Gate off then back on via popup switch
  await popupPage.locator('label.switch:has(#togTxGate)').click();
  await popupPage.waitForTimeout(250);
  const pillWhen3 = (await popupPage.textContent('#shieldStatusPill'))?.trim();
  const txGateOffInStorage = await sw.evaluate(async () => (await chrome.storage.local.get('settings')).settings?.transactionGate);
  check(
    'popup.html: toggling Transaction Gate updates status pill to "3/4 Active" & persists',
    pillWhen3 === '3/4 Active' && txGateOffInStorage === false,
    `pill="${pillWhen3}", stored=${txGateOffInStorage}`,
  );

  await popupPage.locator('label.switch:has(#togTxGate)').click();
  await popupPage.waitForTimeout(250);
  const pillRestored = (await popupPage.textContent('#shieldStatusPill'))?.trim();
  check('popup.html: re-enabling Transaction Gate restores "Shield Active"', pillRestored === 'Shield Active', pillRestored);

  // Toggle Paste & Seed-Form Guard off and verify both pasteGuard and seedFormWarning update together
  await popupPage.locator('label.switch:has(#togPasteGuard)').click();
  await popupPage.waitForTimeout(250);
  const pastePairOff = await sw.evaluate(async () => {
    const s = (await chrome.storage.local.get('settings')).settings;
    return { pasteGuard: s?.pasteGuard, seedFormWarning: s?.seedFormWarning };
  });
  await popupPage.locator('label.switch:has(#togPasteGuard)').click();
  await popupPage.waitForTimeout(250);
  const pastePairOn = await sw.evaluate(async () => {
    const s = (await chrome.storage.local.get('settings')).settings;
    return { pasteGuard: s?.pasteGuard, seedFormWarning: s?.seedFormWarning };
  });
  check(
    'popup.html: Paste & Seed-Form Guard switch updates both pasteGuard and seedFormWarning together',
    pastePairOff.pasteGuard === false &&
      pastePairOff.seedFormWarning === false &&
      pastePairOn.pasteGuard === true &&
      pastePairOn.seedFormWarning === true,
    JSON.stringify({ off: pastePairOff, on: pastePairOn }),
  );

  // Verify 1-click Trusted Paste Sites reset row (hidden when empty, visible when populated, resets cleanly)
  const trustedRowHiddenInitially = await popupPage.locator('#trustedResetRow').evaluate((el) => el.classList.contains('hidden'));
  await popupPage.evaluate(
    () =>
      new Promise((res) =>
        chrome.runtime.sendMessage(
          { type: 'ui:update-settings', patch: { trustedPasteOrigins: ['https://example.org'] } },
          res,
        ),
      ),
  );
  await popupPage.waitForFunction(
    () => !document.getElementById('trustedResetRow')?.classList.contains('hidden'),
    null,
    { timeout: 3_000 },
  );
  await popupPage.click('#btnResetTrusted');
  await popupPage.waitForFunction(
    () => document.getElementById('trustedResetRow')?.classList.contains('hidden'),
    null,
    { timeout: 3_000 },
  );
  const trustedAfterReset = await sw.evaluate(
    async () => (await chrome.storage.local.get('settings')).settings?.trustedPasteOrigins ?? [],
  );
  check(
    'popup.html: #trustedResetRow stays hidden until needed and 1-click Reset clears trustedPasteOrigins',
    trustedRowHiddenInitially === true && trustedAfterReset.length === 0,
    `afterReset=${trustedAfterReset.length}`,
  );

  // Point simulation RPC to our local mock JSON-RPC server so E2E generates zero external network traffic
  await popupPage.evaluate(
    (url) =>
      new Promise((res) =>
        chrome.runtime.sendMessage({ type: 'ui:update-settings', patch: { rpcUrl: url } }, res),
      ),
    mockRpcUrl,
  );

  const uiPagesErrors = [...pageErrorsByUrl, ...consoleErrorsByUrl];
  check(
    'UI Popup Audit: zero pageerror and zero console.error in popup.html',
    uiPagesErrors.length === 0,
    uiPagesErrors.length ? JSON.stringify(uiPagesErrors) : '0 errors',
  );

  // =========================================================================
  // 3. LEGACY INJECTED PROVIDER (window.solana) & BATCH TRANSACTIONS
  // =========================================================================
  console.log('\n--- 3. Legacy Injected Provider (window.solana) & Batch Transactions ---');

  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: dappUrl });
  const dappPage = await context.newPage();
  await dappPage.goto(dappUrl, { waitUntil: 'domcontentloaded' });
  await dappPage.waitForSelector('#dappHeading', { timeout: 5_000 });

  // 3a. window.solana.signTransaction (Reject -> 4001, then Approve with live Mock RPC Simulation)
  const revLegacy1P = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const legSignRejectP = dappPage.evaluate((b) => window.callLegacySignTx(b), benignTxBytes);
  const revLegacy1 = await revLegacy1P;
  await revLegacy1.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });

  const leg1Verdict = (await revLegacy1.textContent('#verdictLabel'))?.trim();
  const leg1RpcPill = (await revLegacy1.textContent('#rpcStatusPill'))?.trim();
  const leg1Method = (await revLegacy1.textContent('#methodBadge'))?.trim();
  check(
    'window.solana.signTransaction: opens review.html with Simulated SAFE preview via local mock RPC',
    leg1Verdict === 'SAFE' && leg1RpcPill === 'Simulated' && leg1Method === 'signTransaction',
    `verdict=${leg1Verdict}, rpc=${leg1RpcPill}, method=${leg1Method}`,
  );

  await revLegacy1.click('#btnReject');
  const legSignRejectRes = await legSignRejectP;
  const legacyCallsAfterReject = await dappPage.evaluate(() => window.__legacyCalls.slice());
  check(
    'window.solana.signTransaction: Reject returns 4001 without invoking underlying provider',
    legSignRejectRes === 'rejected:4001' && legacyCallsAfterReject.length === 0,
    legSignRejectRes,
  );

  const revLegacy2P = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const legSignApproveP = dappPage.evaluate((b) => window.callLegacySignTx(b), benignTxBytes);
  const revLegacy2 = await revLegacy2P;
  await revLegacy2.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  await revLegacy2.click('#btnApprove');
  const legSignApproveRes = await legSignApproveP;
  const legacyCallsAfterApprove = await dappPage.evaluate(() => window.__legacyCalls.slice());
  check(
    'window.solana.signTransaction: Continue forwards to legacy provider',
    legSignApproveRes === 'approved' && legacyCallsAfterApprove.includes('signTransaction'),
    legSignApproveRes,
  );

  // 3b. window.solana.signAllTransactions (Batch: [benignTx, dangerAssignTx] -> worst verdict DANGER wins!)
  const revBatchP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const batchCallP = dappPage.evaluate(
    ([tx1, tx2]) => window.callLegacySignAllTxs([tx1, tx2]),
    [benignTxBytes, dangerTxBytes],
  );
  const revBatch = await revBatchP;
  await revBatch.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });

  const batchVerdict = (await revBatch.textContent('#verdictLabel'))?.trim();
  const batchMethod = (await revBatch.textContent('#methodBadge'))?.trim();
  const batchFindings = (await revBatch.textContent('#findingsList'))?.trim() ?? '';
  const batchTech = (await revBatch.textContent('#techBody'))?.trim() ?? '';
  const batchApproveDisabledInitially = await revBatch.locator('#btnApprove').isDisabled();

  check(
    'window.solana.signAllTransactions: batch [SAFE, SystemProgram.assign] escalates overall verdict to DANGER',
    batchVerdict === 'DANGER' &&
      batchMethod === 'signAllTransactions' &&
      batchFindings.includes('Hands control of your wallet to another program') &&
      batchTech.includes('Transaction #1') &&
      batchTech.includes('Transaction #2') &&
      batchApproveDisabledInitially === true,
    `verdict=${batchVerdict}, method=${batchMethod}`,
  );

  await revBatch.check('#dangerAck');
  await revBatch.click('#btnApprove');
  const batchRes = await batchCallP;
  check(
    'window.solana.signAllTransactions: approving after risk-ack resolves both transactions',
    batchRes === 'approved:2',
    batchRes,
  );

  // 3c. Strict RPC Failure Policy ("block") rejects unsimulated transactions without opening review.html
  await sw.evaluate(async () => {
    const cur = (await chrome.storage.local.get('settings')).settings;
    await chrome.storage.local.set({ settings: { ...cur, rpcUrl: '', rpcFailure: 'block' } });
  });
  const blockPolicyRes = await dappPage.evaluate((b) => window.callLegacySignTx(b), benignTxBytes);
  check(
    'RPC Failure Policy ("block"): automatically rejects unsimulated transaction with 4001 when RPC is unconfigured',
    blockPolicyRes === 'rejected:4001',
    blockPolicyRes,
  );
  // Restore mockRpcUrl and rpcFailure: 'warn'
  await sw.evaluate(async (url) => {
    const cur = (await chrome.storage.local.get('settings')).settings;
    await chrome.storage.local.set({ settings: { ...cur, rpcUrl: url, rpcFailure: 'warn' } });
  }, mockRpcUrl);

  // 3d. Lookalike domain escalation in review.html (purnp.fun -> Pump.fun lookalike -> DANGER on connect)
  const phishPage = await context.newPage();
  await phishPage.goto(`http://purnp.fun:${dappPort}/`, { waitUntil: 'domcontentloaded' });
  const lookalikeRevP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const phishGateResP = phishPage.evaluate(() => {
    return new Promise((resolve) => {
      const reqId = 'phish-connect-1';
      window.addEventListener('message', function onMsg(ev) {
        if (ev.data && ev.data.__aegis === 'gate-res' && ev.data.id === reqId) {
          window.removeEventListener('message', onMsg);
          resolve(ev.data.allow);
        }
      });
      window.postMessage({ __aegis: 'gate-req', id: reqId, payload: { method: 'connect', wallet: 'Phantom' } }, '*');
    });
  });
  const lookalikeRev = await lookalikeRevP;
  await lookalikeRev.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  const phishVerdict = (await lookalikeRev.textContent('#verdictLabel'))?.trim();
  const phishSiteBadge = (await lookalikeRev.textContent('#siteBadge'))?.trim();
  check(
    'Lookalike Domain Escalation: connect request from purnp.fun escalates review.html to DANGER with "Lookalike warning!" badge',
    phishVerdict === 'DANGER' && phishSiteBadge === 'Lookalike warning!',
    `verdict=${phishVerdict}, badge="${phishSiteBadge}"`,
  );
  await lookalikeRev.click('#btnReject');
  await phishGateResP;
  await phishPage.close();

  // =========================================================================
  // 4. signMessage REVIEW CASES
  // =========================================================================
  console.log('\n--- 4. signMessage Review Cases ---');

  // 4a. Plain readable UTF-8 message -> SAFE, displays message text
  const plainMsg = 'Confirm Aegis QA session #42 — no on-chain authority granted.';
  const revMsgSafeP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const msgSafeCallP = dappPage.evaluate((m) => window.callLegacySignMessageUtf8(m), plainMsg);
  const revMsgSafe = await revMsgSafeP;
  await revMsgSafe.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });

  const msgSafeVerdict = (await revMsgSafe.textContent('#verdictLabel'))?.trim();
  const msgSafeBoxText = (await revMsgSafe.textContent('#messageTextBox'))?.trim();
  const msgSafeCardVisible = await revMsgSafe.locator('#messageCard').isVisible();
  check(
    'signMessage (UTF-8): plain readable message renders SAFE verdict and exact message text',
    msgSafeVerdict === 'SAFE' && msgSafeCardVisible && msgSafeBoxText === plainMsg,
    `verdict=${msgSafeVerdict}`,
  );
  await revMsgSafe.click('#btnApprove');
  const msgSafeOutcome = await msgSafeCallP;
  check('signMessage (UTF-8): approving resolves signature to dApp', msgSafeOutcome === 'approved:64', msgSafeOutcome);

  // 4b. Sign-In With Solana (SIWS) claiming phantom.app on 127.0.0.1 -> DANGER domain mismatch
  const siwsPhishText = [
    'phantom.app wants you to sign in with your Solana account:',
    payerAddress,
    '',
    'Sign in to Phantom Portal',
    'URI: https://phantom.app',
    'Version: 1',
    'Nonce: 98ab76cd',
  ].join('\n');

  const revSiwsP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const msgSiwsCallP = dappPage.evaluate((m) => window.callLegacySignMessageUtf8(m), siwsPhishText);
  const revSiws = await revSiwsP;
  await revSiws.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });

  const siwsVerdict = (await revSiws.textContent('#verdictLabel'))?.trim();
  const siwsFindings = (await revSiws.textContent('#findingsList'))?.trim() ?? '';
  const siwsNote = (await revSiws.textContent('#siwsDomainNote'))?.trim() ?? '';
  const siwsApproveDisabled = await revSiws.locator('#btnApprove').isDisabled();
  check(
    'signMessage (SIWS spoofing phantom.app on 127.0.0.1): triggers DANGER domain mismatch warning',
    siwsVerdict === 'DANGER' &&
      siwsFindings.includes('Sign-In domain does not match this website') &&
      siwsNote.includes('phantom.app') &&
      siwsApproveDisabled === true,
    `verdict=${siwsVerdict}`,
  );
  await revSiws.click('#btnReject');
  const siwsRejectOutcome = await msgSiwsCallP;
  check('signMessage (SIWS mismatch): Reject returns 4001', siwsRejectOutcome === 'rejected:4001', siwsRejectOutcome);

  // 4c. Serialized Solana transaction bytes passed to signMessage -> DANGER critical warning
  const revDisguisedTxP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const disguisedTxCallP = dappPage.evaluate((b) => window.callLegacySignMessageBytes(b), dangerTxBytes);
  const revDisguisedTx = await revDisguisedTxP;
  await revDisguisedTx.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });

  const disguisedVerdict = (await revDisguisedTx.textContent('#verdictLabel'))?.trim();
  const disguisedFindings = (await revDisguisedTx.textContent('#findingsList'))?.trim() ?? '';
  const disguisedMsgBox = (await revDisguisedTx.textContent('#messageTextBox'))?.trim() ?? '';
  const disguisedApproveDisabled = await revDisguisedTx.locator('#btnApprove').isDisabled();
  check(
    'signMessage (serialized Solana tx bytes): triggers CRITICAL DANGER disguised-transaction warning',
    disguisedVerdict === 'DANGER' &&
      disguisedFindings.includes('Message contains a disguised Solana transaction') &&
      disguisedFindings.includes('CRITICAL') &&
      disguisedMsgBox.includes('Binary message bytes resemble a serialized Solana transaction') &&
      disguisedApproveDisabled === true,
    `verdict=${disguisedVerdict}`,
  );
  await revDisguisedTx.click('#btnReject');
  await disguisedTxCallP;

  // =========================================================================
  // 5. UNTRUSTED SCRIPTED CLICK RESISTANCE (event.isTrusted & Closed Shadow)
  // =========================================================================
  console.log('\n--- 5. Untrusted Scripted Click Resistance (event.isTrusted) ---');

  await dappPage.bringToFront();
  await dappPage.evaluate((secret) => {
    const field = document.getElementById('importField');
    const dt = new DataTransfer();
    dt.setData('text/plain', secret);
    field.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
  }, testSecretKey);

  await dappPage.waitForSelector('[data-aegis-alert="paste-blocked"]', { state: 'attached', timeout: 5_000 });

  // 5a. Attempt page-script inspection & bypass from MAIN world
  const mainWorldProbe = await dappPage.evaluate(() => {
    const host = document.querySelector('[data-aegis-alert="paste-blocked"]');
    if (!host) return { found: false };
    const shadowRoot = host.shadowRoot;
    const innerButtons = host.querySelectorAll('button').length;
    host.click();
    host.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, composed: true }));
    return {
      found: true,
      shadowRootIsNull: shadowRoot === null,
      innerButtons,
      stillInDomAfterHostClick: document.contains(host),
    };
  });

  check(
    'Paste Guard overlay uses closed Shadow Root invisible to page scripts (host.shadowRoot === null)',
    mainWorldProbe.found === true && mainWorldProbe.shadowRootIsNull === true && mainWorldProbe.innerButtons === 0,
    JSON.stringify(mainWorldProbe),
  );

  // 5b. Pierce closed Shadow Root via Chromium CDP (in isolated world!) and dispatch synthetic untrusted clicks directly on internal buttons
  const cdp = await context.newCDPSession(dappPage);
  const isolatedContexts = [];
  cdp.on('Runtime.executionContextCreated', ({ context: ctx }) => {
    if (ctx?.auxData?.type === 'isolated') {
      isolatedContexts.push(ctx);
    }
  });
  await cdp.send('Runtime.enable');
  const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });

  function findShadowButtons(node, acc = []) {
    if (node.nodeName === 'BUTTON') acc.push(node);
    for (const child of node.children ?? []) findShadowButtons(child, acc);
    for (const sr of node.shadowRoots ?? []) findShadowButtons(sr, acc);
    return acc;
  }

  const shadowButtons = findShadowButtons(root);
  check(
    'Found internal "Allow on this site" & "Dismiss" buttons inside closed Shadow Root via CDP',
    shadowButtons.length >= 2,
    `buttons=${shadowButtons.length}, isolatedWorlds=${isolatedContexts.length}`,
  );

  // Dispatch untrusted programmatic .click() and new MouseEvent('click') directly on EVERY shadow button
  // inside the extension's isolated world execution context!
  const isolatedCtxId = isolatedContexts[0]?.id;
  for (const btnNode of shadowButtons) {
    const resolveParams = isolatedCtxId
      ? { nodeId: btnNode.nodeId, executionContextId: isolatedCtxId }
      : { nodeId: btnNode.nodeId };
    const { object } = await cdp.send('DOM.resolveNode', resolveParams);
    await cdp.send('Runtime.callFunctionOn', {
      objectId: object.objectId,
      functionDeclaration: `function() {
        this.click();
        this.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, composed: true }));
      }`,
    });
  }
  await dappPage.waitForTimeout(250);

  const bannerStillAttached = await dappPage.evaluate(
    () => document.querySelector('[data-aegis-alert="paste-blocked"]') !== null,
  );
  const trustedOriginsAfterSynthetic = await sw.evaluate(
    async () => (await chrome.storage.local.get('settings')).settings?.trustedPasteOrigins ?? [],
  );
  check(
    'Synthetic MouseEvent("click") (isTrusted: false) on internal shadow buttons is ignored (banner stays open & origin stays untrusted)',
    bannerStillAttached === true && trustedOriginsAfterSynthetic.length === 0,
    `attached=${bannerStillAttached}, trustedOrigins=${JSON.stringify(trustedOriginsAfterSynthetic)}`,
  );

  // Now perform a genuine trusted mouse click (`isTrusted: true`) on Dismiss button via coordinates
  const dismissNode = shadowButtons[shadowButtons.length - 1];
  const { model } = await cdp.send('DOM.getBoxModel', { nodeId: dismissNode.nodeId });
  const quad = model.border;
  const centerX = (quad[0] + quad[2] + quad[4] + quad[6]) / 4;
  const centerY = (quad[1] + quad[3] + quad[5] + quad[7]) / 4;
  await dappPage.mouse.click(centerX, centerY);
  await dappPage.waitForTimeout(200);
  const bannerClosedAfterTrustedClick = await dappPage.evaluate(
    () => document.querySelector('[data-aegis-alert="paste-blocked"]') === null,
  );
  check(
    'Real user mouse click (isTrusted: true) cleanly dismisses Paste Guard overlay',
    bannerClosedAfterTrustedClick === true,
  );

  // =========================================================================
  // 6. RECOVERY-PHRASE FORM WARNING & ADDRESS LOOKALIKE
  // =========================================================================
  console.log('\n--- 6. Recovery-Phrase Form Warning & Address Lookalike ---');

  // 6a. Recovery-phrase form warning on <textarea>
  await dappPage.fill('#seedArea', 'abandon ability able about above');
  const seedBannerOnTextarea = await dappPage.waitForSelector('[data-aegis-alert="seed-form"]', {
    state: 'attached',
    timeout: 4_000,
  });
  check(
    'Recovery-Phrase Form Warning triggers after typing 5 BIP-39 words into <textarea>',
    Boolean(seedBannerOnTextarea),
  );

  // Also verify 12-<input> seed grid page (no <textarea>)
  const gridPage = await context.newPage();
  await gridPage.goto(`http://127.0.0.1:${dappPort}/12-inputs`, { waitUntil: 'domcontentloaded' });
  const fiveWords = ['abandon', 'ability', 'able', 'about', 'above'];
  for (let i = 0; i < fiveWords.length; i++) {
    await gridPage.fill(`#w${i + 1}`, fiveWords[i]);
  }
  const seedBannerOn12Inputs = await gridPage.waitForSelector('[data-aegis-alert="seed-form"]', {
    state: 'attached',
    timeout: 4_000,
  });
  check(
    'Recovery-Phrase Form Warning triggers after typing 5 BIP-39 words across 12 <input> fields',
    Boolean(seedBannerOn12Inputs),
  );
  await gridPage.close();

  // 6b. Address Lookalike Warning (copy valid 32-byte address A, expire swap window, paste lookalike of A)
  await dappPage.bringToFront();
  await dappPage.evaluate((addr) => {
    const field = document.getElementById('importField');
    const dt = new DataTransfer();
    dt.setData('text/plain', addr);
    field.dispatchEvent(new ClipboardEvent('copy', { clipboardData: dt, bubbles: true, cancelable: true }));
  }, addressA);
  await dappPage.waitForTimeout(250);

  // Expire the 2-minute clipboard-swap window so lookalike check is evaluated
  await sw.evaluate(async () => {
    await chrome.storage.local.set({ lastCopiedAddress: null });
  });

  const pasteLogBeforeLookalike = await dappPage.evaluate(() => window.__pasteLog.length);
  await dappPage.evaluate((lookalike) => {
    const field = document.getElementById('importField');
    const dt = new DataTransfer();
    dt.setData('text/plain', lookalike);
    const notCancelled = field.dispatchEvent(
      new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }),
    );
    if (notCancelled) field.value = lookalike;
  }, addressALookalike);

  const lookalikeBanner = await dappPage.waitForSelector('[data-aegis-alert="lookalike"]', {
    state: 'attached',
    timeout: 4_000,
  });
  const pasteLogAfterLookalike = await dappPage.evaluate(() => window.__pasteLog.slice());
  check(
    'Address Lookalike warning triggers on matching first-4 + last-4 address WITHOUT blocking paste',
    Boolean(lookalikeBanner) &&
      pasteLogAfterLookalike.length === pasteLogBeforeLookalike + 1 &&
      pasteLogAfterLookalike[pasteLogAfterLookalike.length - 1] === addressALookalike,
    `${addressA.slice(0, 4)}...${addressA.slice(-4)} vs ${addressALookalike.slice(0, 4)}...${addressALookalike.slice(-4)}`,
  );

  // =========================================================================
  // 8. DEEP QA ADVERSARIAL & EDGE-CASE PROBES
  // =========================================================================
  console.log('\n--- 8. Deep QA Adversarial & Edge-Case Probes ---');

  // Probe A: Real-world address poisoning flow where user COPIES the poisoned lookalike address
  // inside a browser tab (e.g. from Solscan/Birdeye activity list) and then PASTES it.
  // First seed addressC into recentAddresses (simulating user's legitimate recipient from earlier).
  await sw.evaluate(async (knownAddr) => {
    await chrome.storage.local.set({
      recentAddresses: [knownAddr],
      lastCopiedAddress: null,
    });
  }, addressC);
  // Remove any earlier lookalike overlay from DOM so selector check is fresh
  await dappPage.evaluate(() => {
    document.querySelectorAll('[data-aegis-alert="lookalike"]').forEach((el) => el.remove());
  });
  // User copies poisoned lookalike addressCLookalike on a webpage, then pastes it:
  await dappPage.evaluate((poisonedAddr) => {
    const field = document.getElementById('importField');
    const dtCopy = new DataTransfer();
    dtCopy.setData('text/plain', poisonedAddr);
    field.dispatchEvent(new ClipboardEvent('copy', { clipboardData: dtCopy, bubbles: true, cancelable: true }));
  }, addressCLookalike);
  await dappPage.waitForTimeout(250);
  await dappPage.evaluate((poisonedAddr) => {
    const field = document.getElementById('importField');
    const dtPaste = new DataTransfer();
    dtPaste.setData('text/plain', poisonedAddr);
    field.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dtPaste, bubbles: true, cancelable: true }));
  }, addressCLookalike);
  await dappPage.waitForTimeout(500);
  const lookalikeShownAfterInBrowserCopy = await dappPage.evaluate(
    () => document.querySelector('[data-aegis-alert="lookalike"]') !== null,
  );
  check(
    'Adversarial Probe A (Address Poisoning): copying a lookalike address in-browser then pasting it still warns user',
    lookalikeShownAfterInBrowserCopy === true,
    lookalikeShownAfterInBrowserCopy
      ? 'warned'
      : 'BUG: recordAddressCopied() upserted poisoned lookalike into recentAddresses on copy, silencing checkAddressLookalike() on paste!',
  );

  // Probe D: Multi-step legacy window.phantom = {}; window.phantom.solana = provider hook coverage
  await dappPage.bringToFront();
  let phantomGateOpened = false;
  const phantomPopupWait = context
    .waitForEvent('page', { predicate: (p) => p.url().includes('/review.html'), timeout: 1_500 })
    .then(async (p) => {
      phantomGateOpened = true;
      await p.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 5_000 });
      await p.click('#btnReject');
    })
    .catch(() => {});

  await dappPage.evaluate(async (b) => {
    try {
      await window.phantom.solana.signTransaction(window.makeSerializableTx(b));
    } catch {
      /* rejected */
    }
  }, dangerTxBytes);
  await phantomPopupWait;
  const phantomLateCalls = await dappPage.evaluate(() => window.__phantomLateCalls.slice());
  check(
    'Adversarial Probe D (window.phantom.solana two-step injection): Aegis intercepts window.phantom.solana.signTransaction',
    phantomGateOpened === true && phantomLateCalls.length === 0,
    phantomGateOpened
      ? 'intercepted'
      : `BUG: bypassed Aegis gate (provider called=${phantomLateCalls.length}) when window.phantom={} assigned before .solana!`,
  );

  // Probe E: Wallet Standard solana:signIn domain spoofing (`domain: "phantom.app"` from `127.0.0.1`)
  const signInPopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const signInCallP = dappPage.evaluate(async () => {
    try {
      const w = window.__wallets[0];
      await w.features['solana:signIn'].signIn({ domain: 'phantom.app', statement: 'Sign in to Phantom' });
      return 'approved';
    } catch (e) {
      return 'rejected:' + (e && e.code);
    }
  });
  const signInPopup = await signInPopupP;
  await signInPopup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  const stdSignInVerdict = (await signInPopup.textContent('#verdictLabel'))?.trim();
  await signInPopup.click('#btnReject');
  await signInCallP;
  check(
    'Adversarial Probe E (solana:signIn domain mismatch): signIn({ domain: "phantom.app" }) on 127.0.0.1 warns DANGER instead of SAFE',
    stdSignInVerdict === 'DANGER',
    stdSignInVerdict === 'SAFE'
      ? 'BUG: review-manager.ts buildFallbackReport() hardcodes SAFE for method==="signIn" without checking domain !== origin!'
      : `verdict=${stdSignInVerdict}`,
  );

  // Probe F: Cross-realm iframe Uint8Array passed to signMessage with disguised transaction bytes
  const crossRealmPopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const crossRealmCallP = dappPage.evaluate(async (txBytes) => {
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    document.body.appendChild(iframe);
    const IframeUint8Array = iframe.contentWindow.Uint8Array;
    const crossBytes = new IframeUint8Array(txBytes);
    try {
      await window.solana.signMessage(crossBytes);
      return 'approved';
    } catch (e) {
      return 'rejected:' + (e && e.code);
    } finally {
      iframe.remove();
    }
  }, dangerTxBytes);
  const crossRealmPopup = await crossRealmPopupP;
  await crossRealmPopup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  const crossRealmVerdict = (await crossRealmPopup.textContent('#verdictLabel'))?.trim();
  const crossRealmFindings = (await crossRealmPopup.textContent('#findingsList'))?.trim() ?? '';
  await crossRealmPopup.click('#btnReject');
  await crossRealmCallP;
  check(
    'Adversarial Probe F (Cross-realm Uint8Array signMessage): disguised tx in iframe Uint8Array still detected as DANGER',
    crossRealmVerdict === 'DANGER',
    crossRealmVerdict !== 'DANGER'
      ? `BUG: rendered verdict="${crossRealmVerdict}" ("${crossRealmFindings.slice(0, 60)}...") because inpage.ts uses instanceof Uint8Array and review-manager.ts falls back to SAFE connect report!`
      : `verdict=${crossRealmVerdict}`,
  );

  // Probe G: Partial batch serialization failure in signAllTransactions([benignTx, statefulThrowingTx])
  const partialBatchPopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const partialBatchCallP = dappPage.evaluate(
    async ([safeBytes, evilBytes]) => {
      let serializeCount = 0;
      const safeTx = window.makeSerializableTx(safeBytes);
      const statefulEvilTx = {
        serialize() {
          serializeCount += 1;
          if (serializeCount === 1) {
            throw new Error('Hide from Aegis txToBytes()');
          }
          return new Uint8Array(evilBytes);
        },
      };
      try {
        await window.solana.signAllTransactions([safeTx, statefulEvilTx]);
        return 'approved';
      } catch (e) {
        return 'rejected:' + (e && e.code);
      }
    },
    [benignTxBytes, dangerTxBytes],
  );
  const partialBatchPopup = await partialBatchPopupP;
  await partialBatchPopup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  const partialBatchVerdict = (await partialBatchPopup.textContent('#verdictLabel'))?.trim();
  const partialBatchTech = (await partialBatchPopup.textContent('#techBody'))?.trim() ?? '';
  await partialBatchPopup.click('#btnReject');
  await partialBatchCallP;
  check(
    'Adversarial Probe G (Batch signAllTransactions null-filter bypass): unreadable tx in batch escalates to DANGER',
    partialBatchVerdict === 'DANGER' && partialBatchTech.includes('Transaction #2'),
    partialBatchVerdict === 'SAFE'
      ? 'BUG: inpage.ts .filter(b => b !== null) silently dropped tx #2 when serialize() threw once, rendering SAFE for a 2-tx batch!'
      : `verdict=${partialBatchVerdict}`,
  );

  // Probe G2: Wallet Standard input.transaction malicious getter TOCTOU swap defense
  const getterSwapPopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const getterSwapCallP = dappPage.evaluate(
    async ([safeBytes, evilBytes]) => {
      let reads = 0;
      const w = window.__wallets[0];
      const maliciousInput = {
        get transaction() {
          reads += 1;
          return new Uint8Array(reads === 1 ? safeBytes : evilBytes);
        },
      };
      const out = await w.features['solana:signTransaction'].signTransaction(maliciousInput);
      const forwarded = Array.from(out[0].signedTransaction);
      return { reads, matchedSafe: forwarded.length === safeBytes.length && forwarded.every((b, idx) => b === safeBytes[idx]) };
    },
    [benignTxBytes, dangerTxBytes],
  );
  const getterSwapPopup = await getterSwapPopupP;
  await getterSwapPopup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  await getterSwapPopup.click('#btnApprove');
  const getterSwapOutcome = await getterSwapCallP;
  check(
    'Adversarial Probe G2 (Wallet Standard getter TOCTOU defense): snapshots input.transaction once and forwards frozen bytes',
    getterSwapOutcome.reads === 1 && getterSwapOutcome.matchedSafe === true,
    JSON.stringify(getterSwapOutcome),
  );

  // Probe H: ui:update-settings enforces HTTPS (or localhost/127.0.0.1) for rpcUrl
  const insecureUpdateRes = await popupPage.evaluate(
    () =>
      new Promise((res) =>
        chrome.runtime.sendMessage(
          { type: 'ui:update-settings', patch: { rpcUrl: 'http://insecure-remote-rpc.example.com/' } },
          res,
        ),
      ),
  );
  const savedInsecureRpc = await sw.evaluate(async () => (await chrome.storage.local.get('settings')).settings?.rpcUrl);
  await popupPage.close();
  check(
    'Adversarial Probe H (RPC HTTPS enforcement): ui:update-settings rejects cleartext http:// non-localhost RPC URLs',
    Boolean(insecureUpdateRes?.error) && savedInsecureRpc !== 'http://insecure-remote-rpc.example.com/',
    `saved="${savedInsecureRpc}", err="${insecureUpdateRes?.error ?? ''}"`,
  );

  // Probe J: Real-World Phantom + pump.fun Sign-In Simulation
  // Tests:
  //   J1) @wallet-standard/app `AppReadyEvent extends Event` (NOT CustomEvent!)
  //   J2) `Object.defineProperty(window, 'phantom', { value: ..., configurable: false, writable: false })`
  //   J3) Wallet Standard `solana:signMessage` delegating internally to `window.phantom.solana.signMessage` -> exactly 1 popup
  //   J4) Passive `connect({ onlyIfTrusted: true })` passes silently on non-lookalike site while interactive `connect()` gates
  const pumpPage = await context.newPage();
  await pumpPage.goto(`${dappUrl}?pumpSim=1`, { waitUntil: 'domcontentloaded' });
  const jSilentRes = await pumpPage.evaluate(async (addr) => {
    const phantomSolana = {
      isPhantom: true,
      publicKey: { toBase58: () => addr },
      async connect(opts) {
        return { publicKey: { toBase58: () => addr }, silent: Boolean(opts && opts.onlyIfTrusted) };
      },
      async signMessage(msg) {
        return { signature: new Uint8Array(64).fill(9), echoedLen: msg.length };
      },
    };
    const holder = {};
    Object.defineProperty(holder, 'solana', {
      value: phantomSolana,
      configurable: false,
      writable: false,
      enumerable: true,
    });
    Object.defineProperty(window, 'phantom', {
      value: holder,
      configurable: false,
      writable: false,
      enumerable: true,
    });

    // Simulate Phantom registering listener BEFORE app-ready, and dApp firing `class AppReadyEvent extends Event`
    class RealPhantomWallet {
      get name() {
        return 'Phantom';
      }
      get accounts() {
        return [{ address: addr, chains: ['solana:mainnet'], features: ['solana:signMessage'] }];
      }
      get features() {
        return {
          'standard:connect': {
            version: '1.0.0',
            connect: async (input) => {
              await window.phantom.solana.connect({ onlyIfTrusted: Boolean(input && input.silent) });
              return { accounts: this.accounts };
            },
          },
          'solana:signMessage': {
            version: '1.1.0',
            signMessage: async (...inputs) => {
              const res = await window.phantom.solana.signMessage(inputs[0].message);
              return [{ signedMessage: inputs[0].message, signature: res.signature }];
            },
          },
        };
      }
    }

    const rawPhantomWallet = new RealPhantomWallet();
    window.addEventListener('wallet-standard:app-ready', (ev) => {
      ev.detail.register(rawPhantomWallet);
    });

    const registered = [];
    const appApi = Object.freeze({
      register: (...ws) => {
        registered.push(...ws);
        return () => {};
      },
    });
    class RealAppReadyEvent extends Event {
      #detail;
      get detail() {
        return this.#detail;
      }
      constructor(api) {
        super('wallet-standard:app-ready');
        this.#detail = api;
      }
    }
    window.dispatchEvent(new RealAppReadyEvent(appApi));
    window.__realStdWallet = registered[0];

    // Passive eager check must NOT open a popup on a non-lookalike site
    const silentOut = await window.__realStdWallet.features['standard:connect'].connect({ silent: true });
    return { registeredCount: registered.length, silentAccounts: silentOut.accounts.length };
  }, payerAddress);

  check(
    'Adversarial Probe J1 (Wallet Standard Event subclass + silent eager connect): registered wrapped Phantom & allowed silent connect',
    jSilentRes.registeredCount === 1 && jSilentRes.silentAccounts === 1,
    JSON.stringify(jSilentRes),
  );

  let jPopupCount = 0;
  const onPopupCount = (p) => {
    if (p.url().includes('/review.html')) jPopupCount += 1;
  };
  context.on('page', onPopupCount);

  const jSignPopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const jSignCallP = pumpPage.evaluate(async (addr) => {
    const msg = new TextEncoder().encode('Sign in to pump.fun: nonce-987654');
    const out = await window.__realStdWallet.features['solana:signMessage'].signMessage({
      account: { address: addr },
      message: msg,
    });
    return out[0].signature.length;
  }, payerAddress);

  const jSignPopup = await jSignPopupP;
  await jSignPopup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  const jSignVerdict = (await jSignPopup.textContent('#verdictLabel'))?.trim();
  await jSignPopup.click('#btnApprove');
  const jSigLen = await jSignCallP;
  await pumpPage.waitForTimeout(150);
  context.off('page', onPopupCount);

  check(
    'Adversarial Probe J2 (pump.fun Sign-In via Event-subclass Wallet Standard -> non-configurable window.phantom.solana): intercepted with exactly 1 popup',
    jSignVerdict === 'SAFE' && jSigLen === 64 && jPopupCount === 1,
    `verdict=${jSignVerdict}, sigLen=${jSigLen}, popups=${jPopupCount}`,
  );
  await pumpPage.close();

  // =========================================================================
  // 9. SOLFLARE & UNIVERSAL MULTI-WALLET COMPATIBILITY SUITE (Probes K1–K5)
  // =========================================================================
  console.log('\n--- 9. Solflare & Universal Multi-Wallet Compatibility Suite ---');

  const sfPage = await context.newPage();
  await sfPage.goto(`${dappUrl}solflare-suite`, { waitUntil: 'load' });

  // K1: Zero ghost globals before wallet injection
  const k1Ghost = await sfPage.evaluate(() => window.__ghostGlobalsBeforeInject);
  check(
    'Probe K1 (Zero Ghost Globals): window has no premature solflare/okxwallet/magicEden/coinbaseSolana keys before injection',
    k1Ghost.solflareInWindow === false &&
      k1Ghost.okxInWindow === false &&
      k1Ghost.magicEdenInWindow === false &&
      k1Ghost.coinbaseInWindow === false &&
      k1Ghost.solflareDocSnippetSafe === true,
    JSON.stringify(k1Ghost),
  );

  // K2: Real Solflare Wallet Standard ({ once: true } app-ready + frozen Event + Object.freeze(wallet) + Object.freeze(features))
  const k2ConnPopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const k2ConnectInfoP = sfPage.evaluate(async () => {
    const ws = window.__solflareStdDiscovered || [];
    const sf = ws.find((w) => w.name === 'Solflare');
    if (!sf) return { found: false };
    const fnRef1 = sf.features['solana:signTransaction'].signTransaction;
    const fnRef2 = sf.features['solana:signTransaction'].signTransaction;
    const connectRes = await sf.features['standard:connect'].connect();
    return {
      found: true,
      stableRef: fnRef1 === fnRef2,
      connectedAccounts: connectRes.accounts.length,
      liveAccountsProp: sf.accounts.length,
    };
  });
  const k2ConnPopup = await k2ConnPopupP;
  await k2ConnPopup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  const k2ConnCardVisible = await k2ConnPopup.locator('#connectCard').isVisible();
  await k2ConnPopup.click('#btnApprove');
  const k2ConnectInfo = await k2ConnectInfoP;
  check(
    'Probe K2a (Solflare Wallet Standard { once: true } + Object.freeze): discovered after DOMContentLoaded, shows Connect Deep-Dive & connects cleanly',
    k2ConnectInfo.found === true &&
      k2ConnCardVisible === true &&
      k2ConnectInfo.stableRef === true &&
      k2ConnectInfo.connectedAccounts === 1 &&
      k2ConnectInfo.liveAccountsProp === 1,
    JSON.stringify({ ...k2ConnectInfo, k2ConnCardVisible }),
  );

  const k2SignPopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const k2SignCallP = sfPage.evaluate(
    async ([bytes, addr]) => {
      const sf = window.__solflareStdDiscovered.find((w) => w.name === 'Solflare');
      const res = await sf.features['solana:signAndSendTransaction'].signAndSendTransaction({
        account: sf.accounts[0] || { address: addr },
        transaction: new Uint8Array(bytes),
        chain: 'solana:mainnet',
      });
      return res[0].signature.length;
    },
    [benignTxBytes, payerAddress],
  );
  const k2SignPopup = await k2SignPopupP;
  await k2SignPopup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  const k2Verdict = (await k2SignPopup.textContent('#verdictLabel'))?.trim();
  const k2Method = (await k2SignPopup.textContent('#methodBadge'))?.trim();
  await k2SignPopup.click('#btnApprove');
  const k2SigLen = await k2SignCallP;
  check(
    'Probe K2b (Solflare Wallet Standard signAndSendTransaction): opens review.html and forwards cleanly on Continue',
    k2Verdict === 'SAFE' && k2Method === 'signAndSendTransaction' && k2SigLen === 64,
    `verdict=${k2Verdict}, method=${k2Method}, sigLen=${k2SigLen}`,
  );

  // K3: Frozen Legacy window.solflare (Object.freeze + non-configurable + EventEmitter chaining + connect() => true + base58 provider.request)
  const dangerTxB58 = base58.encode(Uint8Array.from(dangerTxBytes));
  const k3ConnPopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const k3SetupP = sfPage.evaluate(async (addr) => {
    const eventsBound = [];
    class LegacySolflare {
      #ready = true;
      constructor() {
        this.isSolflare = true;
        this.publicKey = { toBase58: () => addr };
        this.connect = async () => {
          if (!this.#ready) throw new Error('broken #ready');
          return true;
        };
        this.signTransaction = async (tx) => tx;
        this.request = async (payload) => ({ signature: 'ok:' + payload.method });
        this.on = function (ev) {
          eventsBound.push(ev);
          return this;
        };
      }
    }
    const frozenSolflare = Object.freeze(new LegacySolflare());
    Object.defineProperty(window, 'solflare', {
      value: frozenSolflare,
      writable: false,
      configurable: false,
      enumerable: true,
    });

    const chained = window.solflare.on('connect', () => {}).on('disconnect', () => {});
    const connectBool = await window.solflare.connect();
    return {
      isSolflare: window.solflare.isSolflare,
      chainedMatchesWindow: chained === window.solflare,
      eventsCount: eventsBound.length,
      connectBool,
    };
  }, payerAddress);
  const k3ConnPopup = await k3ConnPopupP;
  await k3ConnPopup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  await k3ConnPopup.click('#btnApprove');
  const k3Setup = await k3SetupP;

  check(
    'Probe K3a (Frozen Legacy window.solflare): zero V8 Proxy invariant TypeError, .on() chaining intact, connect() resolves true after Connect review',
    k3Setup.isSolflare === true &&
      k3Setup.chainedMatchesWindow === true &&
      k3Setup.eventsCount === 2 &&
      k3Setup.connectBool === true,
    JSON.stringify(k3Setup),
  );

  const k3ReqPopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const k3ReqCallP = sfPage.evaluate(async (b58Tx) => {
    try {
      await window.solflare.request({ method: 'signTransaction', params: { message: b58Tx } });
      return 'approved';
    } catch (e) {
      return 'rejected:' + (e && e.code);
    }
  }, dangerTxB58);
  const k3ReqPopup = await k3ReqPopupP;
  await k3ReqPopup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  const k3ReqVerdict = (await k3ReqPopup.textContent('#verdictLabel'))?.trim();
  const k3ReqFindings = (await k3ReqPopup.textContent('#findingsList'))?.trim() ?? '';
  await k3ReqPopup.click('#btnReject');
  const k3ReqOut = await k3ReqCallP;
  check(
    'Probe K3b (window.solflare.request base58 signTransaction): decodes base58 wire tx and escalates SystemProgram.assign to DANGER',
    k3ReqVerdict === 'DANGER' &&
      k3ReqFindings.includes('Hands control of your wallet to another program') &&
      k3ReqOut === 'rejected:4001',
    `verdict=${k3ReqVerdict}, out=${k3ReqOut}`,
  );

  // K4: Multi-Wallet Ecosystem Coverage (Backpack direct + .solana, OKX, Magic Eden, Coinbase, Bitget, Nightly, Coin98)
  await sfPage.evaluate((addr) => {
    const makeProv = (tag) =>
      Object.freeze({
        publicKey: { toBase58: () => addr },
        signTransaction: async (tx) => ({ signedBy: tag, tx }),
      });

    const bp = {
      isBackpack: true,
      publicKey: { toBase58: () => addr },
      signTransaction: async (tx) => ({ signedBy: 'backpack-root', tx }),
      solana: makeProv('backpack-solana'),
    };
    Object.defineProperty(window, 'backpack', { value: Object.freeze(bp), configurable: false, writable: false });
    Object.defineProperty(window, 'okxwallet', { value: Object.freeze({ solana: makeProv('okx') }), configurable: true });
    Object.defineProperty(window, 'magicEden', { value: Object.freeze({ solana: makeProv('magicEden') }), configurable: true });
    Object.defineProperty(window, 'coinbaseSolana', { value: makeProv('coinbase'), configurable: true });
    Object.defineProperty(window, 'bitkeep', { value: Object.freeze({ solana: makeProv('bitget') }), configurable: true });
    Object.defineProperty(window, 'nightly', { value: Object.freeze({ solana: makeProv('nightly') }), configurable: true });
    Object.defineProperty(window, 'coin98', { value: Object.freeze({ sol: makeProv('coin98') }), configurable: true });
  }, payerAddress);

  const multiWalletTargets = [
    ['Backpack (root)', 'window.backpack'],
    ['Backpack (.solana)', 'window.backpack.solana'],
    ['OKX (.solana)', 'window.okxwallet.solana'],
    ['Magic Eden (.solana)', 'window.magicEden.solana'],
    ['Coinbase (coinbaseSolana)', 'window.coinbaseSolana'],
    ['Bitget (.solana)', 'window.bitkeep.solana'],
    ['Nightly (.solana)', 'window.nightly.solana'],
    ['Coin98 (.sol)', 'window.coin98.sol'],
  ];
  let multiIntercepted = 0;
  const multiFailures = [];
  for (const [label, expr] of multiWalletTargets) {
    const mwPopupP = context.waitForEvent('page', {
      predicate: (p) => p.url().includes('/review.html'),
      timeout: 5_000,
    });
    const mwCallP = sfPage.evaluate(
      async ([pathExpr, bytes]) => {
        const parts = pathExpr.replace(/^window\./, '').split('.');
        let target = window;
        for (const k of parts) target = target[k];
        try {
          await target.signTransaction(new Uint8Array(bytes));
          return 'approved';
        } catch (e) {
          return 'rejected:' + (e && e.code) + ':' + (e && e.message);
        }
      },
      [expr, benignTxBytes],
    );
    try {
      const mwPopup = await mwPopupP;
      await mwPopup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
      await mwPopup.click('#btnReject');
      const mwRes = await mwCallP;
      if (mwRes.startsWith('rejected:4001:')) multiIntercepted += 1;
      else multiFailures.push(`${label}:${mwRes}`);
    } catch (err) {
      const mwRes = await Promise.race([mwCallP, new Promise((r) => setTimeout(() => r('hung'), 300))]);
      multiFailures.push(`${label}:no-popup(${mwRes})`);
    }
  }
  check(
    'Probe K4 (Multi-Wallet Ecosystem Gate): Backpack, OKX, Magic Eden, Coinbase, Bitget, Nightly & Coin98 all intercepted cleanly (8/8)',
    multiIntercepted === multiWalletTargets.length,
    multiFailures.length ? multiFailures.join(', ') : `intercepted=${multiIntercepted}/${multiWalletTargets.length}`,
  );

  // K5: Cross-origin Solflare enclave iframe skipped while parent dApp stays active
  const k5Enclave = await sfPage.evaluate(async () => {
    const frame = document.getElementById('solflareEnclaveFrame');
    const enclaveActive = await new Promise((resolve) => {
      window.addEventListener('message', function onMsg(ev) {
        if (ev.data && typeof ev.data.enclaveInpageActive === 'boolean') {
          window.removeEventListener('message', onMsg);
          resolve(ev.data.enclaveInpageActive);
        }
      });
      frame.contentWindow.postMessage('ping-enclave', '*');
    });
    return {
      parentInpageActive: Boolean(window.__aegisInpageActive),
      enclaveInpageActive: enclaveActive,
    };
  });
  check(
    'Probe K5 (Solflare Enclave Subframe Safety): inpage.js skips cross-origin solflare.com iframe while protecting parent dApp',
    k5Enclave.parentInpageActive === true && k5Enclave.enclaveInpageActive === false,
    JSON.stringify(k5Enclave),
  );

  await sfPage.close();

  // =========================================================================
  // 10. BUY/SELL FAST-PATH + DEEP-DIVE APPROVE & WALLET CONNECT SUITE (L1–L4)
  // =========================================================================
  console.log('\n--- 10. Buy/Sell Fast-Path + Deep-Dive Approve & Wallet Connect Suite ---');
  await dappPage.bringToFront();

  // Probe L1: Clean DEX Buy Swap (Jupiter v6, 1 SOL -> 50,000 MEME, zero approvals) passes with ZERO popups!
  let l1Popups = 0;
  const countL1Popup = (p) => {
    if (p.url().includes('/review.html')) l1Popups += 1;
  };
  context.on('page', countL1Popup);
  const l1SwapOut = await dappPage.evaluate((b) => window.callLegacySignTx(b), cleanSwapBuyBytes);
  await dappPage.waitForTimeout(200);
  context.off('page', countL1Popup);
  check(
    'Probe L1 (Clean Buy/Sell Swap Fast-Path): verified Jupiter v6 buy swap passes straight to wallet with 0 popups',
    l1SwapOut === 'approved' && l1Popups === 0,
    `out=${l1SwapOut}, popups=${l1Popups}`,
  );

  // Probe L2: Trojan Swap + Hidden SPL Token: Approve(u64::MAX) opens review.html with DANGER & rich Approval Deep-Dive!
  mockPostUsdcDelegateAmount = U64_MAX;
  const l2PopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const l2CallP = dappPage.evaluate((b) => window.callLegacySignTx(b), trojanSwapApproveBytes);
  const l2Popup = await l2PopupP;
  await l2Popup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  const l2Verdict = (await l2Popup.textContent('#verdictLabel'))?.trim();
  const l2ApprovalVisible = await l2Popup.locator('#approvalCard').isVisible();
  const l2ApprovalText = (await l2Popup.textContent('#approvalCard')) ?? '';
  const l2ContinueDisabled = await l2Popup.locator('#btnApprove').isDisabled();
  await l2Popup.click('#btnReject');
  const l2Out = await l2CallP;
  check(
    'Probe L2 (Trojan Swap + Hidden Approve): blocks fast-path, opens DANGER review with UNLIMITED USDC + 1500 USDC at-risk breakdown',
    l2Verdict === 'DANGER' &&
      l2ApprovalVisible === true &&
      l2ApprovalText.includes('Approval Request') &&
      l2ApprovalText.includes('UNLIMITED USDC') &&
      l2ApprovalText.includes('1500 USDC') &&
      l2ApprovalText.includes(drainerSpenderPk.toBase58()) &&
      l2ContinueDisabled === true &&
      l2Out === 'rejected:4001',
    `verdict=${l2Verdict}, out=${l2Out}`,
  );

  // Probe L3: Pure SPL Token: Approve(250 USDC) shows exact 250 USDC allowance + zero-immediate-transfer warning
  mockPostUsdcDelegateAmount = 250_000_000n;
  const l3PopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const l3CallP = dappPage.evaluate((b) => window.callLegacySignTx(b), pureApprove250UsdcBytes);
  const l3Popup = await l3PopupP;
  await l3Popup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  const l3ApprovalText = (await l3Popup.textContent('#approvalCard')) ?? '';
  const l3ZeroDeltaVisible = await l3Popup.locator('#balanceZeroApprovalNote').isVisible();
  await l3Popup.click('#btnReject');
  const l3Out = await l3CallP;
  mockPostUsdcDelegateAmount = 0n;
  check(
    'Probe L3 (Pure SPL Token Approve 250 USDC): shows exact 250 USDC limit, 1500 USDC at risk, and zero-immediate-transfer notice',
    l3ApprovalText.includes('250 USDC') &&
      l3ApprovalText.includes('1500 USDC') &&
      l3ApprovalText.includes('Unrecognized address') &&
      l3ZeroDeltaVisible === true &&
      l3Out === 'rejected:4001',
    `out=${l3Out}`,
  );

  // Probe L4: Silent connect({ onlyIfTrusted: true }) skips popup, while interactive connect() opens Connect Deep-Dive!
  let l4SilentPopups = 0;
  const countL4Silent = (p) => {
    if (p.url().includes('/review.html')) l4SilentPopups += 1;
  };
  context.on('page', countL4Silent);
  const l4SilentRes = await dappPage.evaluate(async () => {
    const res = await window.solana.connect({ onlyIfTrusted: true });
    return Boolean(res && res.publicKey);
  });
  await dappPage.waitForTimeout(150);
  context.off('page', countL4Silent);

  const l4ConnPopupP = context.waitForEvent('page', (p) => p.url().includes('/review.html'));
  const l4ConnCallP = dappPage.evaluate(async () => {
    const res = await window.solana.connect();
    return Boolean(res && res.publicKey);
  });
  const l4ConnPopup = await l4ConnPopupP;
  await l4ConnPopup.waitForSelector('#verdictBanner:not(.hidden)', { timeout: 8_000 });
  const l4ConnectVisible = await l4ConnPopup.locator('#connectCard').isVisible();
  const l4ConnectText = (await l4ConnPopup.textContent('#connectCard')) ?? '';
  await l4ConnPopup.click('#btnApprove');
  const l4ConnApproved = await l4ConnCallP;
  check(
    'Probe L4 (Wallet Connect Deep-Dive vs Silent Reconnect): silent connect has 0 popups; interactive connect() shows Connection Details & permissions',
    l4SilentRes === true &&
      l4SilentPopups === 0 &&
      l4ConnectVisible === true &&
      l4ConnectText.includes('Connection Details') &&
      l4ConnectText.includes('Can') &&
      l4ConnectText.includes('Cannot') &&
      l4ConnApproved === true,
    `silentPopups=${l4SilentPopups}, connectVisible=${l4ConnectVisible}`,
  );

  // Verify Extension UI pages (including all review.html popups) + secure 127.0.0.1 dApp had ZERO errors
  const extAndLocalErrors = [...pageErrorsByUrl, ...consoleErrorsByUrl].filter(
    (e) => e.url.startsWith('chrome-extension://') || e.url.startsWith('http://127.0.0.1'),
  );
  check(
    'Extension UI & review.html Console/PageError Audit: zero errors across all extension pages & popups',
    extAndLocalErrors.length === 0,
    extAndLocalErrors.length ? JSON.stringify(extAndLocalErrors) : '0 errors across all extension UI pages & review popups',
  );

  // Probe I: inpage.js must not throw uncaught TypeError on non-secure http:// origins (where crypto.randomUUID is undefined)
  const nonSecureHttpErrors = pageErrorsByUrl.filter(
    (e) => !e.url.startsWith('chrome-extension://') && !e.url.startsWith('http://127.0.0.1'),
  );
  check(
    'Adversarial Probe I (Non-Secure HTTP Origin inpage.js): zero uncaught pageerrors on plain http:// domains',
    nonSecureHttpErrors.length === 0,
    nonSecureHttpErrors.length
      ? `BUG: inpage.js threw "${nonSecureHttpErrors[0].message}" on ${nonSecureHttpErrors[0].url} because crypto.randomUUID is [SecureContext]-only!`
      : '0 errors',
  );
} catch (err) {
  console.error('\n[DEEP QA FATAL ERROR]:', err);
  process.exitCode = 1;
} finally {
  await context.close().catch(() => {});
  dappServer.close();
  rpcServer.close();
  rmSync(profileDir, { recursive: true, force: true });
}

const passedCount = results.filter((r) => r.ok).length;
const failedCount = results.length - passedCount;
console.log(`\n=============================================================`);
console.log(`DEEP QA SUMMARY: ${passedCount}/${results.length} checks passed, ${failedCount} failed`);
console.log(`=============================================================`);
if (failedCount > 0) {
  console.log('\nFailed checks:');
  for (const r of results.filter((x) => !x.ok)) {
    console.log(`  - ${r.name}${r.detail ? ` -> ${r.detail}` : ''}`);
  }
}
process.exit(failedCount || process.exitCode ? 1 : 0);
