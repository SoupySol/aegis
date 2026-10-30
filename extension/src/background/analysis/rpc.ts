/**
 * rpc.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Tiny JSON-RPC 2.0 client used by the preview engine to read
 *           public chain data (accounts, lookup tables, simulation) from the
 *           Solana RPC endpoint the user configured.
 *
 * ACCESS:   Network: HTTPS POST to the single configured RPC URL. This is the
 *           ONLY network call in the analysis engine.
 *
 * NEVER:    - Never sends secrets, cookies or credentials (credentials: 'omit').
 *           - Only sends public data: the unsigned transaction being previewed
 *             and public account addresses.
 *           - No storage. No logging of request or response bodies.
 * ---------------------------------------------------------------------------
 */

import type { RpcClient } from '../../shared/analysis-types';
import { isAllowedRpcUrl } from '../../shared/settings';

export const RPC_TIMEOUT_MS = 8_000;

export class RpcError extends Error {
  constructor(
    message: string,
    readonly code?: number,
  ) {
    super(message);
    this.name = 'RpcError';
  }
}

interface JsonRpcResponse<T> {
  jsonrpc?: string;
  id?: number | string;
  result?: T;
  error?: { code?: number; message?: string };
}

/**
 * Creates a JSON-RPC 2.0 client for `url` with an ~8s timeout per call.
 * `fetchImpl` lets tests inject a fake fetch.
 */
export function createRpcClient(url: string, fetchImpl?: typeof fetch, timeoutMs = RPC_TIMEOUT_MS): RpcClient {
  const cleanUrl = typeof url === 'string' ? url.trim() : '';
  if (!cleanUrl || !isAllowedRpcUrl(cleanUrl)) {
    throw new RpcError('RPC URL must use https:// (or http://localhost / http://127.0.0.1 for local testing)');
  }
  const doFetch: typeof fetch = fetchImpl ?? ((input, init) => fetch(input, init));
  let nextId = 1;

  return {
    async call<T = unknown>(method: string, params: unknown[]): Promise<T> {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        // AEGIS-NETWORK: JSON-RPC POST to the user-configured Solana RPC endpoint.
        // Payload is public data only (unsigned tx bytes, public addresses).
        const res = await doFetch(cleanUrl, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
          signal: controller.signal,
          credentials: 'omit',
          cache: 'no-store',
        });
        if (!res.ok) throw new RpcError(`RPC HTTP ${res.status}`);
        const json = (await res.json()) as JsonRpcResponse<T>;
        if (json.error) {
          throw new RpcError(`RPC error${json.error.code !== undefined ? ` ${json.error.code}` : ''}: ${json.error.message ?? 'unknown'}`, json.error.code);
        }
        if (!('result' in json)) throw new RpcError('RPC response missing result');
        return json.result as T;
      } catch (e) {
        if (e instanceof RpcError) throw e;
        if (controller.signal.aborted) throw new RpcError(`RPC timeout after ${timeoutMs}ms (${method})`);
        throw new RpcError(`RPC request failed (${method}): ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
