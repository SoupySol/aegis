/**
 * messages.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Typed messages exchanged between extension contexts
 *           (content script, offscreen document, service worker, UI pages).
 * ACCESS:   Types only.
 * NEVER:    No message type carries secret material. Detection results carry
 *           only kind/format/word count/short PUBLIC key.
 * ---------------------------------------------------------------------------
 */
import type { SecretFinding } from './detectors/secret-detector';
import type { AnalysisReport } from './analysis-types';

/** Content script → service worker: ask for a full secret check of candidate text. */
export interface DetectRequest {
  type: 'detect';
  text: string;
}
export interface DetectResponse {
  confirmed: boolean;
  findings: SecretFinding[];
  /** True when the sender's origin is on the user's trusted paste list. */
  trusted?: boolean;
}

export interface SignInFields {
  domain?: string;
  statement?: string;
  uri?: string;
  nonce?: string;
  issuedAt?: string;
  expirationTime?: string;
  chainId?: string;
  resources?: string[];
}

/** Content script → service worker: wallet request needs a decision. */
export interface GateRequest {
  type: 'gate';
  origin: string;
  /** e.g. "signTransaction", "signAndSendTransaction", "signMessage", "connect" */
  method: string;
  /** Wallet name as reported by the page hook ("Phantom", "Solflare"...). */
  wallet: string;
  walletPubkey?: string;
  /** base64 serialized transactions (for tx methods). */
  transactions?: string[];
  /** base64 message bytes (for signMessage / signIn). */
  message?: string;
  /** Claimed domain passed to solana:signIn / window.solana.signIn, if present. */
  signInDomain?: string;
  /** Structured Sign-In With Solana fields when passed to signIn(). */
  signInFields?: SignInFields;
  /** True when a dApp checks prior session state silently (e.g. onlyIfTrusted / silent). */
  silentConnect?: boolean;
  /** Count of batch transaction inputs that could not be serialized in-page. */
  unreadableCount?: number;
  /** Free-form summary for methods we can't decode (e.g. legacy request()). */
  note?: string;
}
export interface GateResponse {
  allow: boolean;
  reason?: string;
}

/** Content script → service worker: an address was copied in a page (public data). */
export interface AddressCopiedMessage {
  type: 'address-copied';
  address: string;
}
/** Content script → service worker: an address was pasted; check swap / lookalike. */
export interface AddressPastedRequest {
  type: 'address-pasted';
  address: string;
}
export interface AddressPastedResponse {
  warning?: 'clipboard-swap' | 'lookalike';
  expected?: string;
}

/** Content script → service worker: count BIP-39 words typed into a form (seed-form warning). */
export interface SeedFormCheckRequest {
  type: 'seed-form-check';
  words: string[];
}
export interface SeedFormCheckResponse {
  bip39Count: number;
}

/** Content script → service worker: is this origin trusted for pasting secrets? */
export interface PasteTrustRequest {
  type: 'paste-trust';
  origin: string;
  grant?: boolean;
}

/** Offscreen → service worker. */
export type OffscreenEvent =
  | { type: 'clip:ready' }
  | { type: 'clip:secret-detected'; findings: SecretFinding[]; confirmed: boolean; seconds: number }
  | { type: 'clip:tick'; secondsLeft: number }
  | { type: 'clip:finished'; cleared: boolean; displaced: boolean };

/** Service worker → offscreen. */
export type OffscreenCommand =
  | { target: 'offscreen'; type: 'clip:clear-now' }
  | { target: 'offscreen'; type: 'clip:extend'; seconds: number }
  | { target: 'offscreen'; type: 'clip:configure'; seconds: number; placeholder: string; enabled: boolean };

export interface SiteInfo {
  status: 'official' | 'unknown' | 'lookalike';
  hostname: string;
  brand?: string;
  officialDomain?: string;
  reason?: string;
}

/** Review window ↔ service worker. */
export interface ReviewFetchRequest {
  type: 'review:get';
  reviewId: string;
}
export interface ReviewFetchResponse {
  request: GateRequest;
  report: AnalysisReport | null;
  pending: boolean;
  error?: string;
  /** Site reputation for request.origin (official / unknown / lookalike). */
  site?: SiteInfo;
  /** Epoch ms after which the request is auto-rejected. */
  expiresAt?: number;
}
export interface ReviewDecision {
  type: 'review:decide';
  reviewId: string;
  allow: boolean;
}

