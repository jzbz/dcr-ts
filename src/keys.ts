/**
 * secp256k1 helpers.
 *
 * Elliptic-curve math is delegated to the audited `@noble/curves` package; this
 * module only adapts it to the shapes the rest of the library needs (compressed
 * keys, scalar/point arithmetic for BIP32 derivation).
 */
import { err } from "./errors.js";
import { isBytes } from "./bytes.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { ed25519 } from "@noble/curves/ed25519";

/** Name a rejected argument in an error message, without interpolating its value. */
function typeName(v: unknown): string {
  return Object.prototype.toString.call(v).slice(8, -1).toLowerCase();
}

/** The secp256k1 group order. */
export const CURVE_ORDER: bigint = secp256k1.CURVE.n;

/** The Ed25519 group order. Bounds WIF scalars for that signature suite. */
export const ED25519_CURVE_ORDER: bigint = ed25519.CURVE.n;

/** True when `key` is a valid secp256k1 private scalar (0 < key < n). */
export function isValidPrivateKey(key: Uint8Array): boolean {
  // The type check is load-bearing, not defensive: without it a 32-character
  // string, a 32-element `Array<number>` or an `Int8Array` all satisfy the length
  // test, and `bytesToBigInt` reads them into some unrelated number — so this
  // predicate answered `true` for values that are not keys at all.
  if (!isBytes(key) || key.length !== 32) return false;
  const n = bytesToBigInt(key);
  return n > 0n && n < CURVE_ORDER;
}

/**
 * Throw unless `key` is a usable secp256k1 private scalar.
 *
 * Everything that signs, or turns a private key into a public one, goes through
 * this. `@noble` checks the same two conditions itself but throws its own plain
 * `Error`, which escapes the typed-error contract — a caller branching on
 * `hasErrorCode` cannot classify a zeroed or wrong-length key buffer, which is
 * exactly the mistake worth classifying.
 *
 * Deliberately stricter than dcrd, which cannot express this failure at all:
 * `secp256k1.PrivKeyFromBytes` reduces mod n and left-pads a short slice, so a
 * zero key there signs under an all-zero-X public key and a 31-byte key is
 * silently padded. Rejecting is the safer contract for a signing API.
 */
export function assertPrivateKey(key: Uint8Array, who: string): void {
  if (!isBytes(key)) {
    throw err("invalid-argument", who, `private key must be a Uint8Array, got ${typeName(key)}`);
  }
  if (key.length !== 32) {
    throw err("bad-length", who, `private key must be 32 bytes, got ${key.length}`);
  }
  if (!isValidPrivateKey(key)) {
    throw err("invalid-private-key", who, "private key is zero, or at or above the group order");
  }
}

/** Compressed (33-byte) public key for a private key. */
export function publicKeyFromPrivate(privateKey: Uint8Array, compressed = true): Uint8Array {
  assertPrivateKey(privateKey, "publicKeyFromPrivate");
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
 * True when `key` is a valid 32-byte Ed25519 public key.
 *
 * Decred's alternative signature suites are recognised on decode even though this
 * library cannot sign for them, and an address whose key is not on the curve is
 * unspendable — so it should not decode as valid. Ed25519 comes from the same
 * `@noble/curves` package already in use, so this adds no dependency.
 */
export function isValidEd25519PublicKey(key: Uint8Array): boolean {
  if (key.length !== 32) return false;
  try {
    // ZIP-215 decoding, because that is what dcrd does. Its `ParsePubKey` goes
    // through AGL's `edwards25519`, whose `FeFromBytes` masks off only the sign
    // bit and never rejects a Y at or above the field prime; the reduction to
    // 0..p-1 happens on the way back out, so the `Y < P` check in `ParsePubKey`
    // can never fire. `@noble` defaults to the stricter RFC 8032 range, which
    // rejects 23 encodings dcrd accepts.
    const point = ed25519.ExtendedPoint.fromHex(key, true);
    // The one thing dcrd does reject: X = 0 with the sign bit set. Its sign
    // fix-up is `x.Sub(curve.P, x)`, which for X = 0 yields exactly P and then
    // trips the `X < P` check. `@noble` applies the same rule, but only when
    // ZIP-215 decoding is off, so it has to be restated here.
    return !(point.toAffine().x === 0n && (key[31]! & 0x80) !== 0);
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
    throw err("invalid-public-key", who, `public key must be 33 compressed bytes, got ${key.length}`);
  }
  if (key[0] !== 0x02 && key[0] !== 0x03) {
    throw err(
      "invalid-public-key",
      who,
      `public key must start with 0x02 or 0x03, got 0x${key[0]!.toString(16).padStart(2, "0")}`,
    );
  }
  if (!isValidPublicKey(key)) {
    throw err("invalid-public-key", who, "public key is not a point on the secp256k1 curve");
  }
}

/**
 * Throw unless `key` is a serialized secp256k1 point — 33-byte compressed or
 * 65-byte uncompressed.
 *
 * For hashing a key into a P2PKH address, where both serializations are
 * legitimate and produce *different* addresses (dcrd hashes whichever form the
 * caller holds; see `dcrutil/util.go`). Use {@link assertCompressedPubKey}
 * wherever the format itself requires 33 bytes, such as the pay-to-pubkey address
 * payload or a bare-P2PK script.
 */
export function assertPubKey(key: Uint8Array, who: string): void {
  if (key.length !== 33 && key.length !== 65) {
    throw err(
      "invalid-public-key",
      who,
      `public key must be 33 (compressed) or 65 (uncompressed) bytes, got ${key.length}`,
    );
  }
  const prefix = key[0]!;
  const ok = key.length === 33 ? prefix === 0x02 || prefix === 0x03 : prefix === 0x04;
  if (!ok) {
    throw err(
      "invalid-public-key",
      who,
      `public key has prefix 0x${prefix.toString(16).padStart(2, "0")}, which is not valid ` +
        `for a ${key.length}-byte key`,
    );
  }
  if (!isValidPublicKey(key)) {
    throw err("invalid-public-key", who, "public key is not a point on the secp256k1 curve");
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
 * Returns `null` when the result is invalid (IL zero or >= n, or the sum is
 * zero), which signals the caller to skip to the next index.
 *
 * BIP32 invalidates only `IL >= n` and `ki == 0`. Rejecting `IL == 0` as well is
 * dcrd's rule — `overflow || ilModN.IsZero()` in `hdkeychain`'s `child`, checked
 * before the private/public split, so it applies to both paths — and it is what
 * {@link publicKeyTweakAddPoint} already does. Without it a zero IL would make
 * the child byte-identical to its parent.
 */
export function privateKeyTweakAdd(kPar: Uint8Array, il: Uint8Array): Uint8Array | null {
  const ilInt = bytesToBigInt(il);
  if (ilInt === 0n || ilInt >= CURVE_ORDER) return null;
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

