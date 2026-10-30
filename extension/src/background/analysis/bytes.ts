/**
 * bytes.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Small, bounds-checked binary helpers for the transaction preview
 *           engine: a cursor-style reader (u8/u16/u32/u64, compact-u16,
 *           pubkeys, length-prefixed strings), base58/base64 helpers and
 *           amount formatting.
 *
 * ACCESS:   Pure functions over in-memory byte arrays.
 *
 * NEVER:    - No network. No storage. No logging.
 *           - Never reads past the end of a buffer: every read is checked and
 *             throws a DecodeError instead of returning garbage.
 * ---------------------------------------------------------------------------
 */

import { base58, base64 } from '@scure/base';

export class DecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DecodeError';
  }
}

export class ByteReader {
  offset = 0;
  private readonly view: DataView;

  constructor(readonly bytes: Uint8Array, offset = 0) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.offset = offset;
  }

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  private need(n: number): void {
    if (n < 0 || this.offset + n > this.bytes.length) {
      throw new DecodeError(`unexpected end of data (need ${n} at ${this.offset}, have ${this.remaining})`);
    }
  }

  u8(): number {
    this.need(1);
    return this.view.getUint8(this.offset++);
  }

  u16(): number {
    this.need(2);
    const v = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return v;
  }

  u32(): number {
    this.need(4);
    const v = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return v;
  }

  u64(): bigint {
    this.need(8);
    const v = this.view.getBigUint64(this.offset, true);
    this.offset += 8;
    return v;
  }

  i64(): bigint {
    this.need(8);
    const v = this.view.getBigInt64(this.offset, true);
    this.offset += 8;
    return v;
  }

  take(n: number): Uint8Array {
    this.need(n);
    const out = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  pubkey(): string {
    return base58.encode(this.take(32));
  }

  /** Solana "shortvec" length: 1-3 bytes, 7 bits per byte, max 0xffff. */
  compactU16(): number {
    let value = 0;
    for (let i = 0; i < 3; i++) {
      const b = this.u8();
      value |= (b & 0x7f) << (7 * i);
      if ((b & 0x80) === 0) {
        if (i > 0 && b === 0) throw new DecodeError('non-canonical compact-u16');
        if (value > 0xffff) throw new DecodeError('compact-u16 overflow');
        return value;
      }
    }
    throw new DecodeError('compact-u16 too long');
  }

  /** Bincode string: u64 length prefix + UTF-8 bytes. */
  bincodeString(): string {
    const len = this.u64();
    if (len > BigInt(this.remaining)) throw new DecodeError('string length out of range');
    return new TextDecoder().decode(this.take(Number(len)));
  }

  /** Borsh string: u32 length prefix + UTF-8 bytes. */
  borshString(): string {
    const len = this.u32();
    return new TextDecoder().decode(this.take(len));
  }
}

export function readU64LE(bytes: Uint8Array, offset: number): bigint {
  if (offset + 8 > bytes.length) throw new DecodeError('u64 out of range');
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(offset, true);
}

export function readU32LE(bytes: Uint8Array, offset: number): number {
  if (offset + 4 > bytes.length) throw new DecodeError('u32 out of range');
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
}

export function readU16LE(bytes: Uint8Array, offset: number): number {
  if (offset + 2 > bytes.length) throw new DecodeError('u16 out of range');
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset, true);
}

export function readPubkey(bytes: Uint8Array, offset: number): string {
  if (offset + 32 > bytes.length) throw new DecodeError('pubkey out of range');
  return base58.encode(bytes.subarray(offset, offset + 32));
}

export function isAllZero(bytes: Uint8Array): boolean {
  for (const b of bytes) if (b !== 0) return false;
  return true;
}

export function encodeBase58(bytes: Uint8Array): string {
  return base58.encode(bytes);
}

export function decodeBase58(s: string): Uint8Array {
  return base58.decode(s);
}

export function encodeBase64(bytes: Uint8Array): string {
  return base64.encode(bytes);
}

export function decodeBase64(s: string): Uint8Array {
  return base64.decode(s);
}

/** True when `s` decodes as a 32-byte base58 value (i.e. looks like an address). */
export function looksLikePubkey(s: string): boolean {
  if (s.length < 32 || s.length > 44) return false;
  try {
    return base58.decode(s).length === 32;
  } catch {
    return false;
  }
}

/** Shorten an address for display: first 4 + "…" + last 4. */
export function shortAddr(addr: string): string {
  return addr.length > 12 ? `${addr.slice(0, 4)}…${addr.slice(-4)}` : addr;
}

/** Format a signed base-unit amount with `decimals` places, trimming trailing zeros. */
export function formatUnits(raw: bigint, decimals: number): string {
  const neg = raw < 0n;
  const abs = neg ? -raw : raw;
  if (decimals <= 0) return `${neg ? '-' : ''}${abs.toString()}`;
  const base = 10n ** BigInt(decimals);
  const whole = abs / base;
  const frac = (abs % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${neg ? '-' : ''}${whole.toString()}${frac ? `.${frac}` : ''}`;
}

export const LAMPORTS_PER_SOL = 1_000_000_000n;

export function formatSol(lamports: bigint): string {
  return formatUnits(lamports, 9);
}
