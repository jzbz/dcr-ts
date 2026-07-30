/**
 * secp256k1 helpers.
 *
 * Elliptic-curve math is delegated to the audited `@noble/curves` package; this
 * module only adapts it to the shapes the rest of the library needs (compressed
 * keys, scalar/point arithmetic for BIP32 derivation).
 */
import { secp256k1 } from "@noble/curves/secp256k1";

/** The secp256k1 group order. */
export const CURVE_ORDER: bigint = secp256k1.CURVE.n;

/** True when `key` is a valid secp256k1 private scalar (0 < key < n). */
export function isValidPrivateKey(key: Uint8Array): boolean {
  if (key.length !== 32) return false;
  const n = bytesToBigInt(key);
  return n > 0n && n < CURVE_ORDER;
}

/** Compressed (33-byte) public key for a private key. */
export function publicKeyFromPrivate(privateKey: Uint8Array, compressed = true): Uint8Array {
  return secp256k1.getPublicKey(privateKey, compressed);
}

/** True when `key` is a valid serialized secp256k1 point (compressed or not). */
export function isValidPublicKey(key: Uint8Array): boolean {
  try {
    secp256k1.ProjectivePoint.fromHex(key);
    return true;
  } catch {
    return false;
  }
}

/**
 * Throw unless `key` is a 33-byte compressed secp256k1 point.
 *
 * Anything that turns a public key into an address or an output script must go
 * through this. Length alone is not enough, and length is not even checked in the
 * common mistake: passing a 32-byte private key where the public key was meant
 * type-checks fine, since both are `Uint8Array`. The resulting address or script
 * is well-formed and permanently unspendable, because no key hashes to it.
 */
export function assertCompressedPubKey(key: Uint8Array, who: string): void {
  if (key.length !== 33) {
    throw new Error(`${who}: public key must be 33 compressed bytes, got ${key.length}`);
  }
  if (key[0] !== 0x02 && key[0] !== 0x03) {
    throw new Error(
      `${who}: public key must start with 0x02 or 0x03, got 0x${key[0]!.toString(16).padStart(2, "0")}`,
    );
  }
  if (!isValidPublicKey(key)) {
    throw new Error(`${who}: public key is not a point on the secp256k1 curve`);
  }
}

/** Big-endian 32-byte encoding of a scalar already reduced mod n. */
export function scalarToBytes(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

/**
 * BIP32 private child tweak: `(IL + kPar) mod n`, returned as 32 bytes.
 * Returns `null` when the result is invalid (IL >= n, or the sum is zero),
 * which signals the caller to skip to the next index.
 */
export function privateKeyTweakAdd(kPar: Uint8Array, il: Uint8Array): Uint8Array | null {
  const ilInt = bytesToBigInt(il);
  if (ilInt >= CURVE_ORDER) return null;
  const child = (ilInt + bytesToBigInt(kPar)) % CURVE_ORDER;
  if (child === 0n) return null;
  return scalarToBytes(child);
}

/**
 * A parsed secp256k1 point, for reuse across derivations.
 *
 * Deliberately *not* re-exported from the package root: it is `@noble`'s type, and
 * pinning the public API to a dependency's internals is not worth the 1.4x.
 */
export type PublicKeyPoint = InstanceType<typeof secp256k1.ProjectivePoint>;

/**
 * Decompress a serialized public key once, so a caller deriving a chain of
 * children can reuse it.
 *
 * Decompressing costs a modular square root — measured ~65 us, about 29% of a
 * public (watch-only) derivation step, and it is the same parent key every time
 * when scanning addresses under one account.
 */
export function parsePublicKeyPoint(key: Uint8Array): PublicKeyPoint | null {
  try {
    return secp256k1.ProjectivePoint.fromHex(key);
  } catch {
    return null;
  }
}

/** {@link publicKeyTweakAdd} with the parent already decompressed. */
export function publicKeyTweakAddPoint(
  parent: PublicKeyPoint,
  il: Uint8Array,
): Uint8Array | null {
  const ilInt = bytesToBigInt(il);
  if (ilInt >= CURVE_ORDER || ilInt === 0n) return null;
  const P = secp256k1.ProjectivePoint;
  try {
    const child = P.BASE.multiply(ilInt).add(parent);
    if (child.equals(P.ZERO)) return null;
    return child.toRawBytes(true);
  } catch {
    return null;
  }
}

/**
 * BIP32 public child tweak: `point(IL) + KPar`, returned as a compressed key.
 * Returns `null` when invalid (IL >= n, or the result is the point at infinity).
 */
export function publicKeyTweakAdd(kPar: Uint8Array, il: Uint8Array): Uint8Array | null {
  const parent = parsePublicKeyPoint(kPar);
  if (parent === null) return null;
  return publicKeyTweakAddPoint(parent, il);
}
