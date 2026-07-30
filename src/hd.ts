/**
 * BIP32 hierarchical-deterministic keys, Decred serialization.
 *
 * The serialized form uses Decred's four-byte version identifiers
 * (`dprv`/`dpub` on mainnet, `tprv`/`tpub` on testnet, …) and the
 * double-BLAKE-256 base58check checksum. Both private (signer) and public
 * (watch-only) derivation are supported.
 *
 * The seed → master-key HMAC still keys on the literal string "Bitcoin seed",
 * which Decred kept for compatibility.
 *
 * # Hardened derivation is not plain BIP32
 *
 * Decred also differs in the hardened child function, and the difference is
 * load-bearing. dcrd's `hdkeychain` strips leading zero bytes from a derived
 * private key and carries the shortened string into the next hardened HMAC
 * (`hdkeychain/extendedkey.go`):
 *
 * > Note that per [BIP32] this should be the fully zero-padded 32-bytes,
 * > however, the Decred variation strips leading zeros for legacy reasons and
 * > changing it now would break derivation for a lot of Decred wallets that
 * > rely on this behavior.
 *
 * So for a parent scalar with a leading zero byte the hardened HMAC input is
 * `0x00 ‖ key31 ‖ 0x00 ‖ ser32(i)` rather than BIP32's
 * `0x00 ‖ 0x00 ‖ key31 ‖ ser32(i)` — the same length, different bytes, and
 * every descendant diverges. About 1 seed in 112 is affected on a BIP44 path.
 *
 * dcrd exposes both (`Child` legacy, `ChildBIP32Std` strict) and dcrwallet uses
 * the legacy one for the entire wallet path, so {@link ExtendedKey.derive} and
 * {@link ExtendedKey.derivePath} are the Decred variant. Strict BIP32 is
 * available as {@link ExtendedKey.deriveBip32Std} /
 * {@link ExtendedKey.derivePathBip32Std}.
 *
 * Getting this wrong is silent: a signer that derived strictly would show a user
 * restoring their Decrediton seed a different, empty wallet, with coins sent to
 * its addresses invisible to every other Decred wallet holding the same phrase.
 *
 * Two consequences worth knowing:
 *
 * - **Public (non-hardened) derivation is unaffected** — there is no private key
 *   to strip, and a stripped scalar has the same value and therefore the same
 *   public key. An account `dpub` and every address below it agree between the
 *   two variants.
 * - **The stripped state does not survive serialization.** dcrd pads the scalar
 *   back to 32 bytes in the extended-key string, so a key round-tripped through
 *   `dprv` derives strictly from then on — in dcrd too, which this mirrors.
 *   Only hardened steps are affected, and in BIP44 the deepest hardened level is
 *   the account key, so this rarely shows up in practice.
 */
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import { base58Decode, checkDecode, checkEncode, maxBase58Length } from "./base58.js";
import { copyOf } from "./bytes.js";
import { hash160 } from "./hash.js";
import {
  isValidPrivateKey,
  isValidPublicKey,
  privateKeyTweakAdd,
  publicKeyFromPrivate,
  publicKeyTweakAdd,
} from "./keys.js";
import type { Network } from "./networks.js";
import { networks } from "./networks.js";
import { pubKeyHashAddress } from "./address.js";

/** Index of the first hardened child (2^31). */
export const HARDENED_OFFSET = 0x80000000;

const MASTER_HMAC_KEY = new TextEncoder().encode("Bitcoin seed");
const SERIALIZED_LENGTH = 78;

/**
 * Longest a `dprv`/`dpub` string can be: the 78-byte serialization plus a 4-byte
 * checksum. Matches dcrd's `maxKeyLen` in `NewKeyFromString`.
 */
export const MAX_EXTENDED_KEY_LENGTH = maxBase58Length(SERIALIZED_LENGTH + 4);

/**
 * Mark a BIP44 child index as hardened.
 *
 * Rejects anything outside `0..2^31-1`: adding the offset to an already-hardened
 * or out-of-range index wraps, and the result would be a *non*-hardened index
 * silently derived from the wrong branch.
 */
export function hardened(index: number): number {
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
    throw new Error(`hd: hardened index must be an integer in 0..2^31-1, got ${index}`);
  }
  return (index + HARDENED_OFFSET) >>> 0;
}

function ser32(value: number): Uint8Array {
  return Uint8Array.of(
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  );
}

/** Number of leading 0x00 bytes, i.e. how many dcrd's `child` would strip. */
function leadingZeros(key: Uint8Array): number {
  let n = 0;
  while (n < key.length && key[n] === 0) n++;
  return n;
}

/** A BIP32 extended key with Decred version bytes. */
export class ExtendedKey {
  private constructor(
    readonly network: Network,
    readonly isPrivate: boolean,
    /** 32-byte private scalar, or `null` for a public (neutered) key. */
    private readonly privateKey: Uint8Array | null,
    /** 33-byte compressed public key. */
    private readonly compressedPublicKey: Uint8Array,
    readonly chainCode: Uint8Array,
    readonly depth: number,
    readonly parentFingerprint: Uint8Array,
    readonly childNumber: number,
    /**
     * Whether dcrd would be holding this scalar with its leading zero bytes
     * stripped, which changes the hardened HMAC input of its children (see the
     * module docs). True only for keys produced by {@link derive} — dcrd strips
     * in `child` alone, so a master key from `fromSeed` and a key parsed by
     * `fromSerialized` are both held at full width, exactly as `NewMaster` and
     * `NewKeyFromString` do. The scalar itself is always stored padded to 32
     * bytes here; only the HMAC input is narrowed.
     */
    private readonly scalarStripped: boolean = false,
  ) {}

  /** Derive a master key from a BIP32 seed (16–64 bytes). */
  static fromSeed(seed: Uint8Array, network: Network): ExtendedKey {
    if (seed.length < 16 || seed.length > 64) {
      throw new Error("hd: seed must be 16..64 bytes");
    }
    const I = hmac(sha512, MASTER_HMAC_KEY, seed);
    const il = I.subarray(0, 32);
    const ir = I.subarray(32, 64);
    if (!isValidPrivateKey(il)) throw new Error("hd: invalid master key (retry with new seed)");
    return new ExtendedKey(
      network,
      true,
      il.slice(),
      publicKeyFromPrivate(il),
      ir.slice(),
      0,
      new Uint8Array(4),
      0,
    );
  }

  /** The compressed public key (33 bytes). */
  publicKey(): Uint8Array {
    return this.compressedPublicKey.slice();
  }

  /** The 32-byte private scalar. Throws for a public key. */
  privateKeyBytes(): Uint8Array {
    if (!this.privateKey) throw new Error("hd: not a private key");
    return this.privateKey.slice();
  }

  /** Identifier = hash160(compressed pubkey); the fingerprint is its first 4 bytes. */
  identifier(): Uint8Array {
    return hash160(this.compressedPublicKey);
  }

  fingerprint(): Uint8Array {
    return this.identifier().subarray(0, 4);
  }

  /**
   * Derive a child key by index, the **Decred way** — the equivalent of dcrd
   * `hdkeychain.Child`, and what dcrwallet and Decrediton derive with for the
   * whole wallet path. Use {@link hardened} for hardened indices.
   *
   * This is the default because it is what the Decred ecosystem derives; see
   * {@link deriveBip32Std} for the strict form and the module docs for why they
   * differ.
   */
  derive(index: number): ExtendedKey {
    return this.deriveInner(index, false);
  }

  /**
   * Derive a child key by **strict BIP32** — the equivalent of dcrd
   * `hdkeychain.ChildBIP32Std`, retaining the leading zero bytes of the parent
   * private key that {@link derive} strips.
   *
   * Produces different hardened children from {@link derive} for any parent
   * scalar with a leading zero byte, which is about 1 key in 256 at each
   * hardened step. Use it only when strict BIP32 is what you want; anything that
   * has to agree with a dcrwallet or Decrediton seed must not.
   */
  deriveBip32Std(index: number): ExtendedKey {
    return this.deriveInner(index, true);
  }

  private deriveInner(index: number, strictBip32: boolean): ExtendedKey {
    // The serialized depth is a single byte, so refuse to go past what can be
    // round-tripped. (dcrd keeps depth as a uint16 and serializes depth%256, so
    // it will happily derive further and wrap; this is the stricter choice.)
    if (this.depth >= 255) throw new Error("hd: cannot derive beyond depth 255");
    if (!Number.isInteger(index)) throw new Error(`hd: index must be an integer, got ${index}`);
    if (index < 0 || index > 0xffffffff) throw new Error(`hd: index ${index} out of range`);
    const idx = index >>> 0;
    const isHardened = idx >= HARDENED_OFFSET;

    const data = new Uint8Array(37);
    if (isHardened) {
      if (!this.privateKey) {
        throw new Error("hd: cannot derive a hardened child from a public key");
      }
      // dcrd zeroes a 37-byte buffer, copies the parent scalar in at offset 1
      // and writes ser32(index) at offset 33. In the Decred variant the stored
      // scalar has had its leading zero bytes stripped, so it lands
      // LEFT-aligned at offset 1 and the gap before ser32(index) stays zero:
      //
      //   strict:  0x00 ‖ 0x00 ‖ key31 ‖ ser32(i)
      //   Decred:  0x00 ‖ key31 ‖ 0x00 ‖ ser32(i)
      //
      // Same length, different bytes — hence a different child.
      const skip = strictBip32 || !this.scalarStripped ? 0 : leadingZeros(this.privateKey);
      data.set(this.privateKey.subarray(skip), 1);
    } else {
      // Non-hardened derivation commits to the public key, which is unchanged by
      // stripping (a stripped scalar has the same value), so both variants agree.
      data.set(this.compressedPublicKey, 0);
    }
    data.set(ser32(idx), 33);

    const I = hmac(sha512, this.chainCode, data);
    const il = I.subarray(0, 32);
    const childChainCode = I.subarray(32, 64).slice();
    const parentFp = this.fingerprint();
    const childDepth = this.depth + 1;

    if (this.privateKey) {
      const childPriv = privateKeyTweakAdd(this.privateKey, il);
      if (!childPriv) throw new Error("hd: invalid child key (retry with next index)");
      return new ExtendedKey(
        this.network,
        true,
        childPriv,
        publicKeyFromPrivate(childPriv),
        childChainCode,
        childDepth,
        parentFp,
        idx,
        // dcrd's `child` strips the derived scalar unless strict BIP32 was asked
        // for, and that state is what the next hardened step reads.
        !strictBip32,
      );
    }

    const childPub = publicKeyTweakAdd(this.compressedPublicKey, il);
    if (!childPub) throw new Error("hd: invalid child key (retry with next index)");
    return new ExtendedKey(
      this.network,
      false,
      null,
      childPub,
      childChainCode,
      childDepth,
      parentFp,
      idx,
    );
  }

  /**
   * Derive along a path like `m/44'/42'/0'/0/0`, the **Decred way** (see
   * {@link derive}). An apostrophe or `h` marks a hardened index.
   */
  derivePath(path: string): ExtendedKey {
    return this.derivePathInner(path, false);
  }

  /**
   * Derive along a path using **strict BIP32** (see {@link deriveBip32Std}).
   * Diverges from {@link derivePath} below any hardened step whose parent scalar
   * has a leading zero byte, so do not use it to reproduce a wallet seed.
   */
  derivePathBip32Std(path: string): ExtendedKey {
    return this.derivePathInner(path, true);
  }

  private derivePathInner(path: string, strictBip32: boolean): ExtendedKey {
    const parts = path.trim().split("/");
    if (parts[0] === "m") parts.shift();
    let key: ExtendedKey = this;
    for (const raw of parts) {
      const isH = raw.endsWith("'") || raw.endsWith("h") || raw.endsWith("H");
      const numStr = isH ? raw.slice(0, -1) : raw;
      // Strict decimal only — `Number()` would accept "0x10", "1e2", "", etc.
      if (!/^\d+$/.test(numStr)) {
        throw new Error(`hd: invalid path element '${raw}'`);
      }
      const n = Number(numStr);
      if (n >= HARDENED_OFFSET) {
        throw new Error(`hd: path index ${n} out of range`);
      }
      const idx = isH ? hardened(n) : n;
      key = strictBip32 ? key.deriveBip32Std(idx) : key.derive(idx);
    }
    return key;
  }

  /** Return the public (watch-only) version of this key. */
  neuter(): ExtendedKey {
    if (!this.isPrivate) return this;
    return new ExtendedKey(
      this.network,
      false,
      null,
      this.compressedPublicKey,
      this.chainCode,
      this.depth,
      this.parentFingerprint,
      this.childNumber,
    );
  }

  /** The standard P2PKH address for this key on its network. */
  address(network: Network = this.network): string {
    return pubKeyHashAddress(hash160(this.compressedPublicKey), network);
  }

  /** Serialize to the 78-byte BIP32 form (without the base58check checksum). */
  serialize(): Uint8Array {
    const version = this.isPrivate ? this.network.hdPrivateKeyId : this.network.hdPublicKeyId;
    const out = new Uint8Array(SERIALIZED_LENGTH);
    out[0] = version[0];
    out[1] = version[1];
    out[2] = version[2];
    out[3] = version[3];
    out[4] = this.depth & 0xff;
    out.set(this.parentFingerprint, 5);
    out.set(ser32(this.childNumber), 9);
    out.set(this.chainCode, 13);
    if (this.isPrivate) {
      out[45] = 0x00;
      out.set(this.privateKey!, 46);
    } else {
      out.set(this.compressedPublicKey, 45);
    }
    return out;
  }

  /** Encode as a `dprv`/`dpub` (or per-network) base58check string. */
  toString(): string {
    return checkEncode(this.serialize());
  }

  /** Parse an extended key string, validating the checksum and version. */
  static fromString(str: string): ExtendedKey {
    // Bound before decoding; base58 decoding is quadratic, so an unbounded string
    // burns CPU proportional to its length squared. dcrd caps identically
    // (hdkeychain.NewKeyFromString's maxKeyLen).
    if (str.length > MAX_EXTENDED_KEY_LENGTH) {
      throw new Error(
        `hd: ${str.length} characters exceeds the ${MAX_EXTENDED_KEY_LENGTH}-character maximum`,
      );
    }
    const data = checkDecode(str);
    return ExtendedKey.fromSerialized(data);
  }

  /**
   * Parse a raw 78-byte serialization (checksum already verified/absent).
   *
   * Every field is copied out of `data`, so the returned key does not alias the
   * caller's buffer — which matters most here, because a caller doing the right
   * thing and wiping the serialization after parsing would otherwise destroy the
   * key it just parsed. See {@link copyOf}.
   */
  static fromSerialized(data: Uint8Array): ExtendedKey {
    if (data.length !== SERIALIZED_LENGTH) throw new Error("hd: bad serialized length");
    const version: [number, number, number, number] = [data[0]!, data[1]!, data[2]!, data[3]!];
    const depth = data[4]!;
    const parentFingerprint = copyOf(data, 5, 4);
    const childNumber =
      ((data[9]! << 24) | (data[10]! << 16) | (data[11]! << 8) | data[12]!) >>> 0;
    const chainCode = copyOf(data, 13, 32);
    const keyData = copyOf(data, 45, 33);

    const found = matchVersion(version);
    if (!found) throw new Error("hd: unknown extended-key version");
    const { network, isPrivate } = found;

    if (isPrivate) {
      if (keyData[0] !== 0x00) throw new Error("hd: bad private key prefix");
      const priv = copyOf(keyData, 1, 32);
      if (!isValidPrivateKey(priv)) throw new Error("hd: invalid private key");
      return new ExtendedKey(
        network,
        true,
        priv,
        publicKeyFromPrivate(priv),
        chainCode,
        depth,
        parentFingerprint,
        childNumber,
      );
    }
    if (keyData[0] !== 0x02 && keyData[0] !== 0x03) {
      throw new Error("hd: bad public key prefix");
    }
    if (!isValidPublicKey(keyData)) {
      throw new Error("hd: public key is not a valid curve point");
    }
    return new ExtendedKey(
      network,
      false,
      null,
      keyData,
      chainCode,
      depth,
      parentFingerprint,
      childNumber,
    );
  }
}

interface VersionMatch {
  network: Network;
  isPrivate: boolean;
}

function matchVersion(v: readonly number[]): VersionMatch | null {
  for (const network of Object.values(networks)) {
    if (eq4(v, network.hdPrivateKeyId)) return { network, isPrivate: true };
    if (eq4(v, network.hdPublicKeyId)) return { network, isPrivate: false };
  }
  return null;
}

function eq4(a: readonly number[], b: readonly number[]): boolean {
  return a[0] === b[0] && a[1] === b[1] && a[2] === b[2] && a[3] === b[3];
}

/** Low-level: base58-decode an extended key string without checksum validation. */
export function rawDecodeExtendedKey(str: string): Uint8Array {
  return base58Decode(str);
}
