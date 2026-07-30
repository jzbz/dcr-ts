/**
 * Base58 and Decred's base58check.
 *
 * The alphabet is the standard Bitcoin one, but the check variant differs in a
 * consensus-critical way: the 4-byte checksum is the first four bytes of the
 * **double BLAKE-256** of the payload, not double SHA-256. Everything encoded
 * for humans on Decred — addresses, WIF private keys and `dprv`/`dpub` extended
 * keys — rides on {@link checkEncode}.
 */
import { hash256 } from "./hash.js";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE = 58n;

// Reverse lookup: char code -> value, or 255 for invalid.
const INDEX = new Uint8Array(128).fill(255);
for (let i = 0; i < ALPHABET.length; i++) {
  INDEX[ALPHABET.charCodeAt(i)] = i;
}

/** Encode raw bytes as base58 (no checksum). */
export function base58Encode(bytes: Uint8Array): string {
  // Preserve leading zero bytes as leading '1's.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);

  let out = "";
  while (num > 0n) {
    const rem = num % BASE;
    num = num / BASE;
    out = ALPHABET[Number(rem)] + out;
  }
  return "1".repeat(zeros) + out;
}

/**
 * Longest base58 string that can decode to `decodedLen` bytes.
 *
 * base58 expands by at most log_58(256) ≈ 1.37 bytes of output per input byte,
 * which is how dcrd derives its own bounds (`stdaddr.DecodeAddressV0`'s
 * `maxV0AddrLen`, `hdkeychain.NewKeyFromString`'s `maxKeyLen`). Callers must cap
 * untrusted input *before* decoding: {@link base58Decode} accumulates one BigInt
 * digit at a time and is therefore quadratic, so an unbounded string is a cheap
 * way to stall the event loop.
 */
export function maxBase58Length(decodedLen: number): number {
  return Math.floor((decodedLen * 137) / 100) + 1;
}

/**
 * Decode a base58 string to raw bytes. Throws on invalid characters.
 *
 * Cost is **quadratic** in the length of `str`. There is deliberately no length
 * cap here, because the function is general-purpose; every decoder in this
 * library bounds its input first via {@link maxBase58Length}, and anything
 * calling this directly on untrusted input must do the same.
 */
export function base58Decode(str: string): Uint8Array {
  let zeros = 0;
  while (zeros < str.length && str[zeros] === "1") zeros++;

  let num = 0n;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    const val = code < 128 ? INDEX[code]! : 255;
    if (val === 255) throw new Error(`invalid base58 character '${str[i]}'`);
    num = num * BASE + BigInt(val);
  }

  // Convert the big integer back to bytes (big-endian).
  const tail: number[] = [];
  while (num > 0n) {
    tail.push(Number(num % 256n));
    num = num / 256n;
  }
  tail.reverse();

  const out = new Uint8Array(zeros + tail.length);
  out.set(tail, zeros);
  return out;
}

/** base58check-encode: append the 4-byte double-BLAKE-256 checksum. */
export function checkEncode(data: Uint8Array): string {
  const checksum = hash256(data).subarray(0, 4);
  const full = new Uint8Array(data.length + 4);
  full.set(data);
  full.set(checksum, data.length);
  return base58Encode(full);
}

/**
 * base58check-decode and verify the checksum, returning the payload without the
 * trailing 4 checksum bytes. Throws if the checksum does not match.
 */
export function checkDecode(str: string): Uint8Array {
  const full = base58Decode(str);
  if (full.length < 4) throw new Error("base58check: too short");
  const data = full.subarray(0, full.length - 4);
  const checksum = full.subarray(full.length - 4);
  const expected = hash256(data).subarray(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expected[i]) throw new Error("base58check: bad checksum");
  }
  return data.slice();
}
