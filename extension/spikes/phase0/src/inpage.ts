/**
 * Spike: inpage wallet hooks (MAIN world, document_start).
 * PURPOSE:  Prove Aegis can pause every wallet signing request BEFORE the
 *           wallet popup opens: Wallet Standard wallets (Phantom, Solflare,
 *           Backpack...) and legacy window.solana-style providers.
 * ACCESS:   Wraps wallet objects in this page. Sees transaction BYTES only.
 * NEVER:    Never touches keys (wallets never expose them to pages). No network.
 *
 * Spike behaviour: logs each intercepted call to the console and asks with
 * window.confirm(). The real build replaces confirm() with decode + simulate
 * + an extension-owned review window.
 */

const TAG = '[Aegis spike]';
const SIGN_FEATURES: Record<string, string> = {
  'solana:signTransaction': 'signTransaction',
  'solana:signAndSendTransaction': 'signAndSendTransaction',
  'solana:signMessage': 'signMessage',
  'solana:signIn': 'signIn',
  'standard:connect': 'connect',
};
const LEGACY_METHODS = [
  'connect',
  'signTransaction',
  'signAllTransactions',
  'signAndSendTransaction',
  'signAndSendAllTransactions',
  'signMessage',
  'signIn',
  'request',
];

const wrappedWallets = new WeakMap<object, object>();
const proxies = new WeakSet<object>();
const wrappedFeatures = new WeakMap<object, object>();

function describeInputs(inputs: unknown[]): string {
  return inputs
    .map((i: any) => {
      if (i?.transaction instanceof Uint8Array) return `tx(${i.transaction.length} bytes)`;
      if (i?.message instanceof Uint8Array) return `message(${i.message.length} bytes)`;
      if (i && typeof i.serialize === 'function') return `${i.constructor?.name ?? 'Transaction'} object`;
      if (Array.isArray(i)) return `array(${i.length})`;
      if (i && typeof i === 'object' && 'method' in i) return `request(${String(i.method)})`;
      return typeof i;
    })
    .join(', ');
}

async function gate(source: string, method: string, inputs: unknown[]): Promise<void> {
  const summary = `${source} → ${method}(${describeInputs(inputs)}) from ${location.hostname}`;
  console.info(TAG, 'INTERCEPTED before wallet opened:', summary);
  if (method === 'connect') return; // spike: don't block connects
  const ok = window.confirm(`${TAG}\nIntercepted BEFORE your wallet opened:\n\n${summary}\n\nContinue to wallet?`);
  if (!ok) {
    const err = new Error('User rejected the request.') as Error & { code: number };
    err.code = 4001;
    throw err;
  }
}

function wrapFeatures(features: Record<string, any>, walletName: string): Record<string, any> {
  const cached = wrappedFeatures.get(features);
  if (cached) return cached as Record<string, any>;
  const out: Record<string, any> = { ...features };
  for (const [feature, method] of Object.entries(SIGN_FEATURES)) {
    const f = features[feature];
    if (!f || typeof f[method] !== 'function') continue;
    const original = f[method];
    out[feature] = {
      ...f,
      [method]: async (...inputs: unknown[]) => {
        await gate(`WalletStandard:${walletName}`, method, inputs);
        return original.apply(f, inputs);
      },
    };
  }
  wrappedFeatures.set(features, out);
  return out;
}

function wrapWallet<T extends object>(wallet: T): T {
  if (!wallet || typeof wallet !== 'object' || proxies.has(wallet)) return wallet;
  const existing = wrappedWallets.get(wallet);
  if (existing) return existing as T;
  const proxy = new Proxy(wallet, {
    get(target, prop) {
      // AEGIS-SECURITY: read with the ORIGINAL target as receiver so wallets using
      // private #fields keep working.
      const value = Reflect.get(target, prop, target);
      if (prop === 'features' && value && typeof value === 'object') {
        return wrapFeatures(value, String((target as any).name ?? 'wallet'));
      }
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  proxies.add(proxy);
  wrappedWallets.set(wallet, proxy);
  console.info(TAG, 'Wallet Standard wallet wrapped:', (wallet as any).name);
  return proxy;
}

// ---- Wallet Standard: intercept both registration directions --------------
const originalDispatch = EventTarget.prototype.dispatchEvent;
EventTarget.prototype.dispatchEvent = function (this: EventTarget, event: Event): boolean {
  if (this === window && event instanceof CustomEvent) {
    if (event.type === 'wallet-standard:app-ready' && event.detail?.register) {
      const appApi = event.detail;
      const replacement = new CustomEvent(event.type, {
        detail: Object.freeze({ register: (...wallets: object[]) => appApi.register(...wallets.map(wrapWallet)) }),
      });
      return originalDispatch.call(this, replacement);
    }
    if (event.type === 'wallet-standard:register-wallet' && typeof event.detail === 'function') {
      const walletCallback = event.detail;
      const replacement = new CustomEvent(event.type, {
        detail: (appApi: { register: (...w: object[]) => unknown }) =>
          walletCallback({ register: (...wallets: object[]) => appApi.register(...wallets.map(wrapWallet)) }),
      });
      return originalDispatch.call(this, replacement);
    }
  }
  return originalDispatch.call(this, event);
};

// Belt and braces: wrap app listeners for register-wallet events dispatched
// through a dispatchEvent reference captured before our patch.
const listenerMap = new WeakMap<Function, EventListener>();
const originalAdd = EventTarget.prototype.addEventListener;
const originalRemove = EventTarget.prototype.removeEventListener;
EventTarget.prototype.addEventListener = function (this: EventTarget, type: string, listener: any, options?: any) {
  if (this === window && type === 'wallet-standard:register-wallet' && typeof listener === 'function') {
    const wrapped: EventListener = (event: Event) => {
      const cb = (event as CustomEvent).detail;
      if (typeof cb !== 'function') return listener.call(this, event);
      const fake = new Proxy(event, {
        get(t, p) {
          if (p === 'detail') {
            return (appApi: { register: (...w: object[]) => unknown }) =>
              cb({ register: (...wallets: object[]) => appApi.register(...wallets.map(wrapWallet)) });
          }
          const v = Reflect.get(t, p, t);
          return typeof v === 'function' ? v.bind(t) : v;
        },
      });
      return listener.call(this, fake);
    };
    listenerMap.set(listener, wrapped);
    return originalAdd.call(this, type, wrapped, options);
  }
  return originalAdd.call(this, type, listener, options);
};
EventTarget.prototype.removeEventListener = function (this: EventTarget, type: string, listener: any, options?: any) {
  const mapped = listener && listenerMap.get(listener);
  return originalRemove.call(this, type, mapped ?? listener, options);
};

// ---- Legacy injected providers --------------------------------------------
function wrapLegacyProvider(provider: any, label: string): any {
  if (!provider || typeof provider !== 'object' || proxies.has(provider)) return provider;
  const proxy = new Proxy(provider, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target);
      if (typeof prop === 'string' && LEGACY_METHODS.includes(prop) && typeof value === 'function') {
        return async (...args: unknown[]) => {
          const method = prop === 'request' ? `request:${String((args[0] as any)?.method)}` : prop;
          await gate(`Legacy:${label}`, method, args);
          return value.apply(target, args);
        };
      }
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  proxies.add(proxy);
  return proxy;
}

function hookGlobal(name: string, getProvider: (v: any) => any, setProvider: (holder: any, p: any) => any): void {
  const desc = Object.getOwnPropertyDescriptor(window, name);
  if (desc && !desc.configurable) {
    console.warn(TAG, `window.${name} is non-configurable; relying on Wallet Standard path.`);
    return;
  }
  let current: any = desc && 'value' in desc ? desc.value : undefined;
  if (current) current = setProvider(current, wrapLegacyProvider(getProvider(current), name));
  try {
    Object.defineProperty(window, name, {
      configurable: true,
      enumerable: true,
      get: () => current,
      set: (v) => {
        current = v ? setProvider(v, wrapLegacyProvider(getProvider(v), name)) : v;
        console.info(TAG, `window.${name} provider wrapped`);
      },
    });
  } catch (e) {
    console.warn(TAG, `could not hook window.${name}`, e);
  }
}

const direct = (v: any) => v;
const replaceDirect = (_holder: any, p: any) => p;
hookGlobal('solana', direct, replaceDirect);
hookGlobal('solflare', direct, replaceDirect);
hookGlobal('backpack', direct, replaceDirect);
// window.phantom is a namespace object: { solana, ethereum, ... }
hookGlobal(
  'phantom',
  (v) => v?.solana,
  (holder, p) => {
    if (!holder?.solana) return holder;
    return new Proxy(holder, { get: (t, prop) => (prop === 'solana' ? p : Reflect.get(t, prop, t)) });
  },
);

console.info(TAG, 'inpage hooks installed at document_start on', location.hostname);

