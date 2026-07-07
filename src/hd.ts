/**
 * BIP32 hierarchical-deterministic keys, Decred serialization.
 *
 * The derivation math is standard BIP32 (HMAC-SHA512, secp256k1), but the
 * serialized form uses Decred's four-byte version identifiers (`dprv`/`dpub`
 * on mainnet, `tprv`/`tpub` on testnet, …) and the double-BLAKE-256 base58check
 * checksum. Both private (signer) and public (watch-only) derivation are
 * supported.
 *
 * The seed → master-key HMAC still keys on the literal string "Bitcoin seed",
 * which Decred kept for compatibility.
 */
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import { base58Decode, checkDecode, checkEncode } from "./base58.js";
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

/** Mark a BIP44 child index as hardened. */
export function hardened(index: number): number {
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

  /** Derive a child key by index. Use {@link hardened} for hardened indices. */
  derive(index: number): ExtendedKey {
    // The serialized depth is a single byte; dcrd errors past 255 as well.
    if (this.depth >= 255) throw new Error("hd: cannot derive beyond depth 255");
    const idx = index >>> 0;
    const isHardened = idx >= HARDENED_OFFSET;

    const data = new Uint8Array(37);
    if (isHardened) {
      if (!this.privateKey) {
        throw new Error("hd: cannot derive a hardened child from a public key");
      }
      data[0] = 0x00;
      data.set(this.privateKey, 1);
    } else {
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
   * Derive along a path like `m/44'/42'/0'/0/0`. An apostrophe or `h` marks a
   * hardened index.
   */
  derivePath(path: string): ExtendedKey {
    const parts = path.trim().split("/");
    if (parts[0] === "m" || parts[0] === "M") parts.shift();
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
      key = key.derive(isH ? hardened(n) : n);
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
    const data = checkDecode(str);
    return ExtendedKey.fromSerialized(data);
  }

  /** Parse a raw 78-byte serialization (checksum already verified/absent). */
  static fromSerialized(data: Uint8Array): ExtendedKey {
    if (data.length !== SERIALIZED_LENGTH) throw new Error("hd: bad serialized length");
    const version: [number, number, number, number] = [data[0]!, data[1]!, data[2]!, data[3]!];
    const depth = data[4]!;
    const parentFingerprint = data.slice(5, 9);
    const childNumber =
      ((data[9]! << 24) | (data[10]! << 16) | (data[11]! << 8) | data[12]!) >>> 0;
    const chainCode = data.slice(13, 45);
    const keyData = data.slice(45, 78);

    const found = matchVersion(version);
    if (!found) throw new Error("hd: unknown extended-key version");
    const { network, isPrivate } = found;

    if (isPrivate) {
      if (keyData[0] !== 0x00) throw new Error("hd: bad private key prefix");
      const priv = keyData.slice(1);
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
