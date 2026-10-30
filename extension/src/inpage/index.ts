/**
 * inpage/index.ts (runs in the page's MAIN world at document_start)
 * ---------------------------------------------------------------------------
 * PURPOSE:  Intercepts wallet signing & connection requests BEFORE the wallet
 *           opens and asks Aegis for a decision. Compatible with Wallet
 *           Standard (`@wallet-standard/*`, `@solana/wallet-standard`) and
 *           legacy providers across Solflare, Phantom, Backpack, OKX, Magic
 *           Eden, Coinbase, Brave, Bitget, Trust, Bybit, Nightly, Glow,
 *           Coin98, Exodus, Privy, Dynamic, and Unified Wallet Kit.
 *
 * ACCESS:   Wraps wallet interfaces in-page; inspects unsigned tx/message
 *           bytes and public addresses only.
 *
 * NEVER:    Never touches private keys. Zero network calls. Never pre-consumes
 *           `{ once: true }` Wallet Standard listeners, never creates ghost
 *           `window.<wallet>` properties, and never violates ECMAScript Proxy
 *           invariants on `Object.freeze`d wallet objects.
 * ---------------------------------------------------------------------------
 */

function initAegisInpage(): void {
  // ARCHITECTURAL DESIGN NOTE: Embedded Wallet & Iframe Enclave Isolation
  // Sub-frames hosted on dedicated wallet auth domains (Privy, Turnkey, Dynamic,
  // Solflare popup frame, etc.) run their own cryptographic key-management sandboxes.
  // Intercepting internal postMessage flows inside these enclaves can break cross-origin
  // iframe handshakes or corrupt internal RPC channels. Aegis monitors the top-level
  // dApp window where transactions originate, letting embedded wallet enclaves initialize cleanly.
  try {
    if (window !== window.top) {
      const h = location.hostname.toLowerCase();
      const enclaves = [
        'solflare.com',
        'phantom.app',
        'backpack.app',
        'privy.io',
        'turnkey.com',
        'dynamicauth.com',
        'magic.link',
        'web3auth.io',
        'tor.us',
        'tiplink.io',
        'crossmint.com',
      ];
      if (enclaves.some((d) => h === d || h.endsWith(`.${d}`))) return;
    }
  } catch {
    /* ignore restricted frame check */
  }

  // ARCHITECTURAL DESIGN NOTE: Main-World Idempotency Guard
  // Inpage scripts are injected at document_start. If a single-page app dynamically
  // reloads or navigates without full page unload, or if multiple extensions inject
  // content scripts, this non-configurable property ensures our hooks are registered
  // exactly once per window lifetime, avoiding duplicate proxy wrappers or memory leaks.
  if ((window as any).__aegisInpageActive) return;
  try {
    Object.defineProperty(window, '__aegisInpageActive', {
      value: true,
      configurable: false,
      enumerable: false,
      writable: false,
    });
  } catch {
    (window as any).__aegisInpageActive = true;
  }

  const wasLoaded = document.readyState !== 'loading';
  const SIGN_FEATURES: Record<string, string> = {
    'solana:signTransaction': 'signTransaction',
    'solana:signAndSendTransaction': 'signAndSendTransaction',
    'solana:signMessage': 'signMessage',
    'solana:signIn': 'signIn',
    'standard:connect': 'connect',
  };
  const LEGACY_METHODS = new Set([
    'connect',
    'signTransaction',
    'signAllTransactions',
    'signAndSendTransaction',
    'signAndSendAllTransactions',
    'signMessage',
    'signIn',
    'request',
  ]);
  const SUB_NS = new Set(['solana', 'sol']);
  const HOOKED_GLOBALS = new Set([
    'solana',
    'solflare',
    'phantom',
    'backpack',
    'xnft',
    'okxwallet',
    'magicEden',
    'coinbaseSolana',
    'braveSolana',
    'bitkeep',
    'bitgetWallet',
    'trustwallet',
    'trustWallet',
    'bybitWallet',
    'nightly',
    'glowSolana',
    'glow',
    'coin98',
    'exodus',
    'clover_solana',
    'tokenpocket',
    'gatewallet',
  ]);

  // AEGIS-SECURITY: capture pristine built-ins at document_start.
  const postMsg = window.postMessage.bind(window);
  const addWinListener = window.addEventListener.bind(window);
  const randBytes = crypto.getRandomValues.bind(crypto);
  const randUUID = typeof crypto.randomUUID === 'function' ? crypto.randomUUID.bind(crypto) : null;
  const btoaRef = window.btoa.bind(window);
  const isView = ArrayBuffer.isView;
  const toStr = Object.prototype.toString;
  const defProp = Object.defineProperty;
  const reflectDefProp = Reflect.defineProperty;
  const getOwnDesc = Object.getOwnPropertyDescriptor;
  const getProto = Object.getPrototypeOf;
  const utf8Enc = new TextEncoder();
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  function nextId(): string {
    if (randUUID) return randUUID();
    const b = randBytes(new Uint8Array(16));
    b[6] = (b[6]! & 0x0f) | 0x40;
    b[8] = (b[8]! & 0x3f) | 0x80;
    let h = '';
    for (let i = 0; i < 16; i++) h += b[i]!.toString(16).padStart(2, '0');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  interface GatePayload {
    origin: string;
    method: string;
    wallet: string;
    walletPubkey?: string;
    transactions?: string[];
    message?: string;
    signInDomain?: string;
    signInFields?: Record<string, unknown>;
    silentConnect?: boolean;
    unreadableCount?: number;
    note?: string;
  }

  const pending = new Map<string, (allow: boolean) => void>();
  addWinListener('message', (ev: MessageEvent) => {
    if (ev.source !== window) return;
    const d = ev.data;
    if (!d || d.__aegis !== 'gate-res' || typeof d.id !== 'string') return;
    const res = pending.get(d.id);
    if (res) {
      pending.delete(d.id);
      res(d.allow === true);
    }
  });

  function askAegis(payload: GatePayload): Promise<boolean> {
    return new Promise((resolve) => {
      const id = nextId();
      pending.set(id, resolve);
      postMsg({ __aegis: 'gate-req', id, payload }, '*');
    });
  }

  function toB64(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return btoaRef(s);
  }

  function fromB58(s: unknown): Uint8Array | null {
    if (!s || typeof s !== 'string' || s.length > 4096) return null;
    const out: number[] = [];
    for (let i = 0; i < s.length; i++) {
      const v = B58.indexOf(s[i]!);
      if (v < 0) return null;
      let c = v;
      for (let j = 0; j < out.length; j++) {
        c += out[j]! * 58;
        out[j] = c & 0xff;
        c >>= 8;
      }
      while (c > 0) {
        out.push(c & 0xff);
        c >>= 8;
      }
    }
    for (let i = 0; i < s.length && s[i] === '1'; i++) out.push(0);
    return new Uint8Array(out.reverse());
  }

  function toBytes(v: any): Uint8Array | null {
    if (!v) return null;
    if (v instanceof Uint8Array) return v;
    if (isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    if (v instanceof ArrayBuffer || toStr.call(v) === '[object ArrayBuffer]') {
      return new Uint8Array(v as ArrayBuffer);
    }
    return null;
  }

  function txToBytes(tx: any): Uint8Array | null {
    try {
      const d = toBytes(tx);
      if (d) return d;
      if (tx && typeof tx.serialize === 'function') {
        const out = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
        return toBytes(out) ?? (Array.isArray(out) ? new Uint8Array(out) : null);
      }
    } catch {
      /* unreadable */
    }
    return null;
  }

  function attachTxList(base: GatePayload, snaps: Array<Uint8Array | null>): GatePayload {
    base.transactions = [];
    for (const s of snaps) {
      if (s) base.transactions.push(toB64(s));
      else {
        base.transactions.push('');
        base.unreadableCount = (base.unreadableCount ?? 0) + 1;
      }
    }
    return base;
  }

  function attachSi(base: GatePayload, inp: any): GatePayload {
    if (!inp || typeof inp !== 'object') return base;
    if (typeof inp.domain === 'string') base.signInDomain = inp.domain;
    const f: Record<string, unknown> = {};
    for (const k of ['domain', 'statement', 'uri', 'nonce', 'issuedAt', 'expirationTime', 'chainId']) {
      if (typeof inp[k] === 'string') f[k] = inp[k].slice(0, 512);
    }
    if (Array.isArray(inp.resources)) f.resources = inp.resources.filter((x: unknown) => typeof x === 'string').slice(0, 10);
    if (Object.keys(f).length > 0) base.signInFields = f;
    if (!base.walletPubkey && typeof inp.address === 'string') base.walletPubkey = inp.address;
    base.note = `Sign-in request for domain "${String(inp.domain ?? location.host)}"`;
    return base;
  }

  function pubkeyStr(v: any): string | undefined {
    try {
      if (!v) return undefined;
      if (typeof v === 'string') return v;
      if (typeof v.address === 'string') return v.address;
      if (typeof v.toBase58 === 'function') return v.toBase58();
      if (v.publicKey) return pubkeyStr(v.publicKey);
    } catch {
      /* ignore */
    }
    return undefined;
  }

  function rejectErr(): Error {
    const err = new Error('User rejected the request.') as Error & { code: number };
    err.code = 4001;
    err.name = 'WalletSignTransactionError';
    return err;
  }

  let syncDepth = 0;
  const passes = new Map<string, number>();

  function dedupKey(p: GatePayload): string {
    if (p.transactions?.length) return `tx:${p.transactions.join(',')}:${p.unreadableCount ?? 0}`;
    if (p.message) return `msg:${p.message}`;
    if (p.method === 'signIn') return `si:${p.signInDomain ?? ''}`;
    if (p.method === 'connect') return `cn:${p.silentConnect ? '1' : '0'}`;
    return `${p.method}:${p.note ?? ''}`;
  }

  async function gate(payload: GatePayload): Promise<string> {
    const k = dedupKey(payload);
    const exp = passes.get(k);
    if (exp !== undefined) {
      passes.delete(k);
      if (exp > Date.now()) return '';
    }
    if (syncDepth > 0) return '';
    if (!(await askAegis(payload))) throw rejectErr();
    const now = Date.now();
    for (const [pk, pe] of passes) if (pe <= now) passes.delete(pk);
    passes.set(k, now + 250);
    return k;
  }

  function runRaw(fn: Function, ctx: any, args: any[]): any {
    syncDepth++;
    try {
      return fn.apply(ctx, args);
    } finally {
      syncDepth--;
    }
  }

  function mark<T extends Function>(fn: T): T {
    try {
      defProp(fn, '__aegisWrapped', { value: true });
    } catch {
      (fn as any).__aegisWrapped = true;
    }
    return fn;
  }

  // ARCHITECTURAL DESIGN NOTE: V8 Proxy Invariant Preservation via Extensible Shadow Target
  // In ECMAScript (§10.5.8 [[Get]] and §10.5.14 [[GetOwnProperty]]), if a Proxy wraps a target
  // that contains non-configurable properties (or is frozen via Object.freeze()), the Proxy's
  // get/getOwnPropertyDescriptor traps MUST return the exact property values present on the target.
  // If a proxy returns a wrapped function or altered value on a frozen target, V8 throws a fatal:
  // "TypeError: 'get' on proxy: property 'x' is a read-only and non-configurable data property on the
  // proxy target but the proxy did not return its actual value".
  //
  // Because Solflare, Backpack, and @wallet-standard/base freeze their exported interfaces and features,
  // creating `new Proxy(real, ...)` crashes when intercepting signing methods.
  // Aegis solves this by constructing `new Proxy({} as T, ...)`. The shadow target `{}` is extensible
  // and has zero non-configurable own properties, satisfying all ECMAScript invariants while allowing
  // our get/has/ownKeys traps to transparently delegate calls to `real` via Reflect.
  const proxies = new WeakSet<object>();
  const proxyRaw = new WeakMap<object, object>();
  const boundCache = new WeakMap<object, WeakMap<Function, Function>>();

  // ARCHITECTURAL DESIGN NOTE: Function Binding & Fluent Interface Chaining
  // When methods on a wallet (e.g. wallet.on, wallet.connect) are accessed through the proxy,
  // they must execute with `this` set to the real underlying wallet instance to access private
  // internal state. However, if the method returns `this` for chaining (e.g. `wallet.on(...).on(...)`),
  // leaking the raw unwrapped `target` would bypass all subsequent proxy traps.
  // `bindFn` intercepts the return value: if `r === target`, it returns `proxyRef` instead.
  function bindFn(target: object, fn: Function, proxyRef: object): Function {
    if ((fn as any).__aegisWrapped) return fn;
    let m = boundCache.get(target);
    if (!m) {
      m = new WeakMap();
      boundCache.set(target, m);
    }
    let b = m.get(fn);
    if (!b) {
      b = (...args: any[]) => {
        const r = fn.apply(target, args);
        return r === target ? proxyRef : r;
      };
      m.set(fn, b);
    }
    return b;
  }

  function safeProxy<T extends object>(
    real: T,
    resolveProp?: (t: T, p: string | symbol, prx: T) => { hit: boolean; val?: any },
    onSet?: (t: T, p: string | symbol, v: any) => void,
  ): T {
    let prx!: T;
    const read = (p: string | symbol): any => {
      if (resolveProp) {
        const r = resolveProp(real, p, prx);
        if (r.hit) return r.val;
      }
      const v = Reflect.get(real, p, real);
      return typeof v === 'function' ? bindFn(real, v, prx) : v;
    };
    prx = new Proxy({} as T, {
      get: (_s, p) => read(p),
      set(_s, p, v) {
        if (onSet) onSet(real, p, v);
        return Reflect.set(real, p, v, real);
      },
      has: (_s, p) => Reflect.has(real, p),
      ownKeys: () => Reflect.ownKeys(real),
      // All descriptor queries report configurable: true so V8 never enforces strict identity
      // checks between the shadow target and the intercepted property values.
      getOwnPropertyDescriptor(_s, p) {
        const d = getOwnDesc(real, p);
        if (!d) return undefined;
        return 'value' in d ? { ...d, configurable: true, value: read(p) } : { ...d, configurable: true };
      },
      getPrototypeOf: () => getProto(real),
    });
    proxies.add(prx);
    proxyRaw.set(prx, real);
    return prx;
  }

  // ---- Wallet Standard ------------------------------------------------------
  const wrappedObjs = new WeakMap<object, object>();
  const featCache = new WeakMap<object, Record<string, any>>();
  const walletSlotCache = new WeakMap<object, Map<string, { o: Function; w: Function }>>();
  const patchedStd = new WeakSet<object>();
  const appApis = new WeakMap<object, AppApi>();
  const isWrappedApi = new WeakSet<object>();
  const ourEvents = new WeakSet<Event>();

  // ARCHITECTURAL DESIGN NOTE: TOCTOU Defense via Immutable Transaction Snapshotting
  // A hostile dApp could pass a mutable Uint8Array buffer or object to wallet.signTransaction,
  // display a harmless transaction during Aegis inspection, and then modify the buffer
  // in-place asynchronously while the user is looking at the review window.
  // To eliminate Time-of-Check to Time-of-Use (TOCTOU) exploits, `snapStdInput` makes an
  // immediate byte-for-byte immutable clone (`b.slice()`) before sending bytes to review.
  // The clone is what both Aegis inspects and what the underlying wallet receives.
  function snapStdInput(inp: any): { snap: Uint8Array | null; clone: any } {
    if (!inp || typeof inp !== 'object') return { snap: null, clone: inp };
    const b = txToBytes(inp.transaction);
    if (!b) return { snap: null, clone: inp };
    const snap = b.slice();
    const c: Record<string, any> = {};
    for (const k of Reflect.ownKeys(inp)) {
      if (k !== 'transaction' && getOwnDesc(inp, k)?.enumerable) c[k as string] = inp[k];
    }
    if (!('account' in c) && inp.account !== undefined) c.account = inp.account;
    if (!('chain' in c) && inp.chain !== undefined) c.chain = inp.chain;
    if (!('options' in c) && inp.options !== undefined) c.options = inp.options;
    c.transaction = snap;
    return { snap, clone: c };
  }

  function stdPayload(method: string, wallet: string, inputs: any[], snaps?: Array<Uint8Array | null>): GatePayload {
    const first = inputs[0];
    const base: GatePayload = {
      origin: location.origin,
      method,
      wallet,
      walletPubkey: pubkeyStr(first?.account),
    };
    if (method === 'connect') {
      if (first && (first.silent === true || first.onlyIfTrusted === true)) base.silentConnect = true;
    } else if (method === 'signTransaction' || method === 'signAndSendTransaction') {
      attachTxList(base, snaps ?? inputs.map((i) => txToBytes(i?.transaction)));
    } else if (method === 'signMessage') {
      const m = toBytes(first?.message);
      if (m) base.message = toB64(m);
    } else if (method === 'signIn') {
      attachSi(base, first);
    }
    return base;
  }

  function wrapStdFn(orig: Function, featObj: any, method: string, walletName: string): (...a: any[]) => Promise<any> {
    if ((orig as any).__aegisWrapped) return orig as any;
    return mark(async (...inputs: any[]) => {
      if (method === 'signTransaction' || method === 'signAndSendTransaction') {
        const cap = inputs.map(snapStdInput);
        const clones = cap.map((x) => x.clone);
        const pk = await gate(stdPayload(method, walletName, clones, cap.map((x) => x.snap)));
        try {
          return await runRaw(orig, featObj, clones);
        } finally {
          if (pk) passes.delete(pk);
        }
      }
      const pk = await gate(stdPayload(method, walletName, inputs));
      try {
        return await runRaw(orig, featObj, inputs);
      } finally {
        if (pk) passes.delete(pk);
      }
    });
  }

  function wrapFeatures(features: Record<string, any>, walletName: string, owner?: object): Record<string, any> {
    const hit = featCache.get(features);
    if (hit) return hit;
    let slots = owner ? walletSlotCache.get(owner) : undefined;
    if (owner && !slots) {
      slots = new Map();
      walletSlotCache.set(owner, slots);
    }
    const out: Record<string, any> = { ...features };
    for (const [feat, method] of Object.entries(SIGN_FEATURES)) {
      const f = features[feat];
      const orig = f?.[method];
      if (!f || typeof orig !== 'function' || orig.__aegisWrapped) continue;
      const prev = slots?.get(feat);
      const w = prev && prev.o === orig ? prev.w : wrapStdFn(orig, f, method, walletName);
      slots?.set(feat, { o: orig, w });
      out[feat] = { ...f, [method]: w };
    }
    featCache.set(features, out);
    return out;
  }

  function patchStdInPlace(wallet: any): void {
    if (!wallet || typeof wallet !== 'object' || proxies.has(wallet) || patchedStd.has(wallet)) return;
    patchedStd.add(wallet);
    const wName = String(wallet.name ?? 'Wallet');
    let cur: any = wallet;
    while (cur && cur !== Object.prototype) {
      const d = getOwnDesc(cur, 'features');
      if (d) {
        if (typeof d.get === 'function' && !(d.get as any).__aegisWrapped && d.configurable) {
          const og = d.get;
          try {
            defProp(cur, 'features', {
              ...d,
              get: mark(function (this: any) {
                const rawSelf = (this && proxyRaw.get(this)) || this;
                const raw = og.call(rawSelf);
                return raw && typeof raw === 'object'
                  ? wrapFeatures(raw, String(rawSelf?.name ?? wName), rawSelf)
                  : raw;
              }),
            });
          } catch {
            /* covered by proxy */
          }
        } else if ('value' in d && d.value && typeof d.value === 'object') {
          for (const [feat, m] of Object.entries(SIGN_FEATURES)) {
            const f = d.value[feat];
            if (!f || typeof f[m] !== 'function' || f[m].__aegisWrapped) continue;
            const wf = wrapStdFn(f[m], f, m, wName);
            try {
              f[m] = wf;
            } catch {
              try {
                d.value[feat] = { ...f, [m]: wf };
              } catch {
                /* frozen */
              }
            }
          }
        }
        break;
      }
      cur = getProto(cur);
    }
  }

  function wrapWallet<T extends object>(wallet: T): T {
    if (!wallet || typeof wallet !== 'object' || proxies.has(wallet)) return wallet;
    const hit = wrappedObjs.get(wallet);
    if (hit) return hit as T;
    const prx = safeProxy(wallet, (t, p) => {
      if (p === 'features') {
        const v = Reflect.get(t, 'features', t);
        if (v && typeof v === 'object') {
          return { hit: true, val: wrapFeatures(v, String((t as any).name ?? 'Wallet'), t) };
        }
      }
      return { hit: false };
    });
    wrappedObjs.set(wallet, prx);
    return prx;
  }

  type AppApi = { register: (...wallets: object[]) => unknown };
  function wrapAppApi(api: AppApi): AppApi {
    if (!api || typeof api.register !== 'function' || isWrappedApi.has(api)) return api;
    const hit = appApis.get(api);
    if (hit) return hit;
    const w = Object.freeze({ register: (...ws: object[]) => api.register(...ws.map(wrapWallet)) });
    isWrappedApi.add(w);
    appApis.set(api, w);
    return w;
  }

  function makeStdEvent<T>(type: string, detail: T): Event {
    const ev = new Event(type, { bubbles: false, cancelable: false, composed: false });
    defProp(ev, 'detail', { get: () => detail, enumerable: true, configurable: true });
    ourEvents.add(ev);
    return ev;
  }

  function isWin(t: unknown): boolean {
    return t === window || t === globalThis;
  }

  const origDispatch = EventTarget.prototype.dispatchEvent;
  EventTarget.prototype.dispatchEvent = function (this: EventTarget, ev: Event): boolean {
    if (isWin(this) && ev && typeof ev === 'object' && !ourEvents.has(ev)) {
      if (ev.type === 'wallet-standard:app-ready') {
        const d = (ev as any).detail;
        if (d && typeof d.register === 'function') {
          return origDispatch.call(this, makeStdEvent('wallet-standard:app-ready', wrapAppApi(d)));
        }
      } else if (ev.type === 'wallet-standard:register-wallet') {
        const cb = (ev as any).detail;
        if (typeof cb === 'function') {
          return origDispatch.call(
            this,
            makeStdEvent('wallet-standard:register-wallet', (api: AppApi) => cb(wrapAppApi(api))),
          );
        }
      }
    }
    return origDispatch.call(this, ev);
  };

  const listenerMap = new WeakMap<object, EventListener>();
  const origAdd = EventTarget.prototype.addEventListener;
  const origRem = EventTarget.prototype.removeEventListener;

  function callListener(fn: any, target: EventTarget, ev: Event): unknown {
    if (typeof fn === 'function') return fn.call(target, ev);
    return typeof fn?.handleEvent === 'function' ? fn.handleEvent(ev) : undefined;
  }

  EventTarget.prototype.addEventListener = function (this: EventTarget, type: string, fn: any, opts?: any) {
    if (
      isWin(this) &&
      (type === 'wallet-standard:register-wallet' || type === 'wallet-standard:app-ready') &&
      (typeof fn === 'function' || typeof fn?.handleEvent === 'function')
    ) {
      let w = listenerMap.get(fn);
      if (!w) {
        w = (ev: Event) => {
          const d = (ev as any)?.detail;
          if (type === 'wallet-standard:register-wallet' && typeof d === 'function') {
            return callListener(
              fn,
              this,
              safeProxy(ev, (_t, p) =>
                p === 'detail' ? { hit: true, val: (api: AppApi) => d(wrapAppApi(api)) } : { hit: false },
              ),
            );
          }
          if (type === 'wallet-standard:app-ready' && d && typeof d.register === 'function') {
            return callListener(
              fn,
              this,
              safeProxy(ev, (_t, p) => (p === 'detail' ? { hit: true, val: wrapAppApi(d) } : { hit: false })),
            );
          }
          return callListener(fn, this, ev);
        };
        listenerMap.set(fn, w);
      }
      return origAdd.call(this, type, w, opts);
    }
    return origAdd.call(this, type, fn, opts);
  };

  EventTarget.prototype.removeEventListener = function (this: EventTarget, type: string, fn: any, opts?: any) {
    const mapped = fn && (typeof fn === 'function' || typeof fn === 'object') ? listenerMap.get(fn) : undefined;
    return origRem.call(this, type, mapped ?? fn, opts);
  };

  function hookNavWallets(): void {
    try {
      const q = (window.navigator as any)?.wallets;
      if (Array.isArray(q) && !(q as any).__aegisHooked) {
        const wrapCb = (cb: any) =>
          typeof cb === 'function' && !cb.__aegisWrapped ? mark((api: AppApi) => cb(wrapAppApi(api))) : cb;
        for (let i = 0; i < q.length; i++) q[i] = wrapCb(q[i]);
        const origPush = q.push.bind(q);
        defProp(q, 'push', {
          configurable: true,
          writable: true,
          value: (...cbs: any[]) => origPush(...cbs.map(wrapCb)),
        });
        defProp(q, '__aegisHooked', { value: true });
      }
    } catch {
      /* ignore */
    }
  }

  // Only probe when dynamically injected into an already-open tab, and re-broadcast
  // captured wallets so `{ once: true }` Wallet Standard listeners are never lost.
  function recoverOpenTabWallets(): void {
    hookNavWallets();
    if (!wasLoaded) return;
    try {
      const captured: object[] = [];
      const probe: AppApi = Object.freeze({
        register: (...ws: object[]) => {
          for (const w of ws) {
            patchStdInPlace(w);
            captured.push(wrapWallet(w));
          }
          return () => {};
        },
      });
      origDispatch.call(window, makeStdEvent('wallet-standard:app-ready', probe));
      if (captured.length > 0) {
        for (const w of captured) {
          origDispatch.call(window, makeStdEvent('wallet-standard:register-wallet', (api: AppApi) => api.register(w)));
        }
        origAdd.call(window, 'wallet-standard:app-ready', (ev: Event) => {
          const api = (ev as any)?.detail;
          if (api && typeof api.register === 'function') api.register(...captured);
        });
      }
    } catch {
      /* ignore */
    }
  }

  // ---- Legacy & Multi-Chain Namespace Providers -----------------------------
  const patchedLegacy = new WeakSet<object>();
  const legSlotCache = new WeakMap<object, Map<string, { o: Function; w: Function }>>();

  function legacyPayload(method: string, label: string, prov: any, args: any[]): GatePayload | null {
    const base: GatePayload = {
      origin: location.origin,
      method,
      wallet: label,
      walletPubkey: pubkeyStr(prov?.publicKey ?? prov?.selectedAddress),
    };
    const first = args[0];

    if (method === 'connect') {
      if (first && (first.onlyIfTrusted === true || first.silent === true)) base.silentConnect = true;
      return base;
    }
    if (method === 'signTransaction' || method === 'signAndSendTransaction') {
      return attachTxList(base, [txToBytes(first)]);
    }
    if (method === 'signAllTransactions' || method === 'signAndSendAllTransactions') {
      const list = Array.isArray(first) ? first : [first];
      return attachTxList(base, list.map(txToBytes));
    }
    if (method === 'signMessage') {
      const m = toBytes(first) ?? (typeof first === 'string' ? utf8Enc.encode(first) : null);
      if (m) base.message = toB64(m);
      return base;
    }
    if (method === 'signIn') {
      return attachSi(base, first);
    }
    if (method === 'request') {
      const im = String(first?.method ?? 'unknown');
      const p = first?.params;
      if (im === 'disconnect') return null;
      if (im === 'connect') {
        base.method = 'connect';
        if (p && (p.onlyIfTrusted === true || p.silent === true)) base.silentConnect = true;
        return base;
      }
      if (im === 'signTransaction' || im === 'signAndSendTransaction') {
        base.method = im;
        const raw = p?.transaction ?? p?.message;
        return attachTxList(base, [txToBytes(raw) ?? fromB58(raw)]);
      }
      if (im === 'signAllTransactions' || im === 'signAndSendAllTransactions') {
        base.method = im;
        const raw = p?.transactions ?? p?.message;
        const list = Array.isArray(raw) ? raw : [raw];
        return attachTxList(base, list.map((x) => txToBytes(x) ?? fromB58(x)));
      }
      if (im === 'signMessage') {
        base.method = 'signMessage';
        const rm = p?.message;
        const mb =
          toBytes(rm) ??
          (p?.display === 'utf8' && typeof rm === 'string'
            ? utf8Enc.encode(rm)
            : fromB58(rm) ?? (typeof rm === 'string' ? utf8Enc.encode(rm) : null));
        if (mb) base.message = toB64(mb);
        return base;
      }
      if (im === 'signIn') {
        base.method = 'signIn';
        return attachSi(base, p);
      }
      base.method = `request:${im}`;
      base.note = 'Legacy wallet request. Aegis cannot fully decode this call.';
      return base;
    }
    return base;
  }

  function wrapLegFn(orig: Function, label: string, prov: any, method: string): (...a: any[]) => Promise<any> {
    if ((orig as any).__aegisWrapped) return orig as any;
    let slots = legSlotCache.get(prov);
    if (!slots) {
      slots = new Map();
      legSlotCache.set(prov, slots);
    }
    const hit = slots.get(method);
    if (hit && hit.o === orig) return hit.w as any;

    const w = mark(async function (this: any, ...args: any[]) {
      const recv = this && !proxies.has(this) ? this : (this && proxyRaw.get(this)) || prov;
      const payload = legacyPayload(method, label, recv, args);
      const pk = payload ? await gate(payload) : '';
      try {
        return await runRaw(orig, recv, args);
      } finally {
        if (pk) passes.delete(pk);
      }
    });
    slots.set(method, { o: orig, w });
    return w;
  }

  function patchLegacyInPlace(prov: any, label: string): void {
    if (!prov || typeof prov !== 'object' || proxies.has(prov) || patchedLegacy.has(prov)) return;
    patchedLegacy.add(prov);

    for (const sub of SUB_NS) {
      try {
        if (prov[sub] && typeof prov[sub] === 'object') patchLegacyInPlace(prov[sub], label);
      } catch {
        /* ignore */
      }
    }

    for (const m of LEGACY_METHODS) {
      let fn: any;
      try {
        fn = prov[m];
      } catch {
        continue;
      }
      if (typeof fn !== 'function' || fn.__aegisWrapped) continue;
      const wf = wrapLegFn(fn, label, prov, m);
      const od = getOwnDesc(prov, m);
      if (!od || od.configurable || od.writable) {
        try {
          defProp(prov, m, { value: wf, configurable: true, writable: true, enumerable: od ? od.enumerable : false });
          continue;
        } catch {
          /* try prototype */
        }
      }
      let proto = getProto(prov);
      while (proto && proto !== Object.prototype) {
        const pd = getOwnDesc(proto, m);
        if (pd) {
          if (typeof pd.value === 'function' && !pd.value.__aegisWrapped && (pd.configurable || pd.writable)) {
            try {
              defProp(proto, m, { ...pd, value: wrapLegFn(pd.value, label, prov, m) });
            } catch {
              /* ignore */
            }
          }
          break;
        }
        proto = getProto(proto);
      }
    }
  }

  function wrapProviderTree(obj: any, label: string): any {
    if (!obj || typeof obj !== 'object' || proxies.has(obj)) return obj;
    patchLegacyInPlace(obj, label);
    const hit = wrappedObjs.get(obj);
    if (hit) return hit;

    const prx: object = safeProxy(
      obj,
      (t, p, selfPrx) => {
        if (typeof p === 'string') {
          if (SUB_NS.has(p)) {
            const sub = Reflect.get(t, p, t);
            if (sub && typeof sub === 'object') return { hit: true, val: wrapProviderTree(sub, label) };
          }
          if (LEGACY_METHODS.has(p)) {
            const v = Reflect.get(t, p, t);
            if (typeof v === 'function') {
              return { hit: true, val: v.__aegisWrapped ? bindFn(t, v, selfPrx) : wrapLegFn(v, label, t, p) };
            }
          }
        }
        return { hit: false };
      },
      (_t, p, v) => {
        if (typeof p === 'string' && SUB_NS.has(p) && v && typeof v === 'object') patchLegacyInPlace(v, label);
      },
    );
    wrappedObjs.set(obj, prx);
    return prx;
  }

  function transformDesc(name: string, attr: PropertyDescriptor): PropertyDescriptor {
    const out: PropertyDescriptor = { ...attr };
    if ('value' in out && out.value && typeof out.value === 'object') {
      out.value = wrapProviderTree(out.value, name);
    } else if (typeof out.get === 'function' && !(out.get as any).__aegisWrapped) {
      const og = out.get;
      out.get = mark(function (this: any) {
        const r = og.call(this);
        return r && typeof r === 'object' ? wrapProviderTree(r, name) : r;
      });
    }
    return out;
  }

  let defDepth = 0;
  Object.defineProperty = function <T>(t: T, p: PropertyKey, attr: PropertyDescriptor): T {
    if (!defDepth && isWin(t) && typeof p === 'string' && HOOKED_GLOBALS.has(p) && attr && typeof attr === 'object') {
      return defProp(t, p, transformDesc(p, attr));
    }
    return defProp(t, p, attr);
  };
  Reflect.defineProperty = function (t: object, p: PropertyKey, attr: PropertyDescriptor): boolean {
    if (!defDepth && isWin(t) && typeof p === 'string' && HOOKED_GLOBALS.has(p) && attr && typeof attr === 'object') {
      return reflectDefProp(t, p, transformDesc(p, attr));
    }
    return reflectDefProp(t, p, attr);
  };

  const hookedAccessors = new Set<string>();
  function syncPresentGlobals(): void {
    hookNavWallets();
    for (const name of HOOKED_GLOBALS) {
      const d = getOwnDesc(window, name);
      if (!d) continue;
      if (!d.configurable) {
        try {
          const ex = (window as any)[name];
          if (ex && typeof ex === 'object') patchLegacyInPlace(ex, name);
        } catch {
          /* ignore */
        }
        continue;
      }
      if (hookedAccessors.has(name) && typeof d.get === 'function' && (d.get as any).__aegisWrapped) continue;
      if (typeof d.get === 'function') {
        defDepth++;
        try {
          defProp(window, name, transformDesc(name, d));
          hookedAccessors.add(name);
        } catch {
          /* ignore */
        } finally {
          defDepth--;
        }
        continue;
      }
      if (d.value === undefined) continue;
      let cur = d.value && typeof d.value === 'object' ? wrapProviderTree(d.value, name) : d.value;
      const getter = mark(() => cur);
      defDepth++;
      try {
        defProp(window, name, {
          configurable: true,
          enumerable: d.enumerable !== false,
          get: getter,
          set: (v) => {
            cur = v && typeof v === 'object' ? wrapProviderTree(v, name) : v;
          },
        });
        hookedAccessors.add(name);
      } catch {
        /* ignore */
      } finally {
        defDepth--;
      }
    }
  }

  syncPresentGlobals();
  recoverOpenTabWallets();

  try {
    const mo = new MutationObserver(syncPresentGlobals);
    mo.observe(document, { childList: true, subtree: true });
    addWinListener(
      'load',
      () => {
        syncPresentGlobals();
        mo.disconnect();
      },
      { once: true },
    );
  } catch {
    /* ignore */
  }

  for (const ev of [
    'solana#initialized',
    'solflare#initialized',
    'phantom#initialized',
    'backpack#initialized',
    'okxwallet#initialized',
  ]) {
    addWinListener(ev, syncPresentGlobals);
  }
  addWinListener('readystatechange', syncPresentGlobals);
  addWinListener('DOMContentLoaded', syncPresentGlobals, { once: true });
  addWinListener('load', syncPresentGlobals, true);
  addWinListener('pointerdown', syncPresentGlobals, true);
  addWinListener('keydown', syncPresentGlobals, true);
}

initAegisInpage();
