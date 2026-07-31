/**
 * Decred addresses.
 *
 * A Decred address is `base58check(versionPrefix || payload)` where the version
 * prefix is **two** bytes (unlike Bitcoin's one) and the checksum is the
 * double-BLAKE-256 one from {@link checkEncode}. The two-byte prefix encodes
 * both the network and the address kind, which is how an address advertises the
 * signature suite it commits to.
 *
 * Supported kinds:
 * - pay-to-pubkey-hash (secp256k1 ECDSA) — the everyday `Ds…` address
 * - pay-to-script-hash
 * - pay-to-pubkey-hash (Ed25519 and secp256k1 Schnorr) — recognised on decode
 * - pay-to-pubkey (secp256k1 ECDSA) — the `Dk…` full-pubkey address
 */
import { base58Decode, checkDecode, checkEncode, maxBase58Length } from "./base58.js";
import { hash160 } from "./hash.js";
import type { Network } from "./networks.js";
import { networks } from "./networks.js";
import {
  payToPubKeyAltScript,
  payToPubKeyHashAltScript,
  payToPubKeyHashScript,
  payToPubKeyScript,
  payToScriptHashScript,
} from "./script.js";
import { copyOf } from "./bytes.js";
import {
  assertCompressedPubKey,
  assertPubKey,
  isValidEd25519PublicKey,
  isValidPublicKey,
} from "./keys.js";

export type AddressKind =
  | "pubkeyhash-ecdsa"
  | "pubkeyhash-ed25519"
  | "pubkeyhash-schnorr"
  | "scripthash"
  | "pubkey-ecdsa"
  | "pubkey-ed25519"
  | "pubkey-schnorr";

/** The hash-based address kinds, which carry a 20-byte `hash`. */
export type HashAddressKind =
  | "pubkeyhash-ecdsa"
  | "pubkeyhash-ed25519"
  | "pubkeyhash-schnorr"
  | "scripthash";

/** The pay-to-pubkey kinds, which carry a serialized `pubKey`. */
export type PubKeyAddressKind = "pubkey-ecdsa" | "pubkey-ed25519" | "pubkey-schnorr";

/**
 * A decoded address.
 *
 * A discriminated union on `kind`, so `hash` and `pubKey` are present exactly
 * where they exist — narrowing on `kind` (or on `"hash" in decoded`) replaces
 * what would otherwise be a non-null assertion at every use.
 */
export type DecodedAddress =
  | {
      readonly network: Network;
      readonly kind: HashAddressKind;
      /** 20-byte hash. */
      readonly hash: Uint8Array;
      /** The original address string. */
      readonly address: string;
    }
  | {
      readonly network: Network;
      readonly kind: PubKeyAddressKind;
      /**
       * The serialized public key: 33-byte compressed secp256k1 for
       * `pubkey-ecdsa` and `pubkey-schnorr`, 32-byte Ed25519 for
       * `pubkey-ed25519`.
       */
      readonly pubKey: Uint8Array;
      readonly address: string;
    };

interface PrefixEntry {
  network: Network;
  kind: AddressKind;
  prefix: readonly [number, number];
}

/**
 * Longest a version-0 address can be: a 33-byte payload (the pay-to-pubkey kind)
 * plus a 2-byte version prefix and a 4-byte checksum. Matches dcrd's
 * `maxV0AddrLen`.
 */
export const MAX_ADDRESS_LENGTH = maxBase58Length(33 + 2 + 4);

// Every (network, kind) → 2-byte prefix, used to classify on decode.
const PREFIXES: PrefixEntry[] = [];
for (const network of Object.values(networks)) {
  PREFIXES.push(
    { network, kind: "pubkeyhash-ecdsa", prefix: network.pubKeyHashAddrId },
    { network, kind: "pubkeyhash-ed25519", prefix: network.pubKeyHashEdwardsAddrId },
    { network, kind: "pubkeyhash-schnorr", prefix: network.pubKeyHashSchnorrAddrId },
    { network, kind: "scripthash", prefix: network.scriptHashAddrId },
    { network, kind: "pubkey-ecdsa", prefix: network.pubKeyAddrId },
  );
}

function encode(prefix: readonly [number, number], payload: Uint8Array): string {
  const data = new Uint8Array(2 + payload.length);
  data[0] = prefix[0];
  data[1] = prefix[1];
  data.set(payload, 2);
  return checkEncode(data);
}

/** Encode a 20-byte pubkey hash as a P2PKH (secp256k1 ECDSA) address. */
export function pubKeyHashAddress(hash: Uint8Array, network: Network): string {
  if (hash.length !== 20) throw new Error("pubKeyHashAddress: hash must be 20 bytes");
  return encode(network.pubKeyHashAddrId, hash);
}

/** Encode a 20-byte script hash as a P2SH address. */
export function scriptHashAddress(hash: Uint8Array, network: Network): string {
  if (hash.length !== 20) throw new Error("scriptHashAddress: hash must be 20 bytes");
  return encode(network.scriptHashAddrId, hash);
}

/** Encode a 20-byte pubkey hash as a P2PKH (Ed25519) address. */
export function pubKeyHashEd25519Address(hash: Uint8Array, network: Network): string {
  if (hash.length !== 20) throw new Error("pubKeyHashEd25519Address: hash must be 20 bytes");
  return encode(network.pubKeyHashEdwardsAddrId, hash);
}

/** Encode a 20-byte pubkey hash as a P2PKH (secp256k1 Schnorr) address. */
export function pubKeyHashSchnorrAddress(hash: Uint8Array, network: Network): string {
  if (hash.length !== 20) throw new Error("pubKeyHashSchnorrAddress: hash must be 20 bytes");
  return encode(network.pubKeyHashSchnorrAddrId, hash);
}

// A secp256k1 pay-to-pubkey address does not store the raw compressed key.
// Instead the 33-byte data is `identifier || X`, where the identifier is the
// signature type (0 for ECDSA) with the high bit set when the key's Y is odd.
const SIG_TYPE_ODD_FLAG = 0x80;

function encodePubKeyData(compressedPubKey: Uint8Array): Uint8Array {
  assertCompressedPubKey(compressedPubKey, "pubKeyAddress");
  const prefix = compressedPubKey[0]!;
  const data = new Uint8Array(33);
  data[0] = SignatureTypeEcdsa | (prefix === 0x03 ? SIG_TYPE_ODD_FLAG : 0);
  data.set(compressedPubKey.subarray(1), 1);
  return data;
}

/**
 * Decode a pay-to-pubkey payload for any of the three signature suites.
 *
 * All three share the layout `identifier || 32 bytes`, where the identifier is
 * the suite with the high bit set when a secp256k1 key's Y is odd. dcrd's
 * `DecodeAddressV0` accepts all three under one address ID, so handling only
 * ECDSA reported a legitimate mainnet address as invalid.
 */
function decodePubKeyData(data: Uint8Array): { kind: PubKeyAddressKind; pubKey: Uint8Array } {
  const sigType = data[0]! & ~SIG_TYPE_ODD_FLAG;
  const odd = (data[0]! & SIG_TYPE_ODD_FLAG) !== 0;

  if (sigType === SignatureTypeEd25519) {
    // The payload *is* the Ed25519 key; there is no oddness bit to apply.
    const pubKey = copyOf(data, 1, 32);
    if (!isValidEd25519PublicKey(pubKey)) {
      throw new Error("decodeAddress: pubkey is not a valid Ed25519 curve point");
    }
    return { kind: "pubkey-ed25519", pubKey };
  }

  if (sigType !== SignatureTypeEcdsa && sigType !== SignatureTypeSchnorr) {
    throw new Error(`decodeAddress: unsupported pubkey signature type ${sigType}`);
  }
  // secp256k1: rebuild the compressed serialization from X plus the oddness bit.
  const pubKey = new Uint8Array(33);
  pubKey[0] = odd ? 0x03 : 0x02;
  pubKey.set(data.subarray(1), 1);
  if (!isValidPublicKey(pubKey)) {
    throw new Error("decodeAddress: pubkey is not a valid curve point");
  }
  return { kind: sigType === SignatureTypeEcdsa ? "pubkey-ecdsa" : "pubkey-schnorr", pubKey };
}

// dcrec.SignatureType values.
const SignatureTypeEcdsa = 0;
const SignatureTypeEd25519 = 1;
const SignatureTypeSchnorr = 2;

/** Encode a compressed public key as a pay-to-pubkey (secp256k1 ECDSA) address. */
export function pubKeyAddress(compressedPubKey: Uint8Array, network: Network): string {
  return encode(network.pubKeyAddrId, encodePubKeyData(compressedPubKey));
}

/** Encode a 32-byte Ed25519 public key as a pay-to-pubkey address. */
export function pubKeyEd25519Address(pubKey: Uint8Array, network: Network): string {
  if (pubKey.length !== 32) {
    throw new Error(`pubKeyEd25519Address: an Ed25519 public key must be 32 bytes, got ${pubKey.length}`);
  }
  if (!isValidEd25519PublicKey(pubKey)) {
    throw new Error("pubKeyEd25519Address: public key is not a valid Ed25519 curve point");
  }
  const data = new Uint8Array(33);
  data[0] = SignatureTypeEd25519;
  data.set(pubKey, 1);
  return encode(network.pubKeyAddrId, data);
}

/** Encode a compressed public key as a pay-to-pubkey (secp256k1 Schnorr) address. */
export function pubKeySchnorrAddress(compressedPubKey: Uint8Array, network: Network): string {
  assertCompressedPubKey(compressedPubKey, "pubKeySchnorrAddress");
  const data = new Uint8Array(33);
  data[0] = SignatureTypeSchnorr | (compressedPubKey[0] === 0x03 ? SIG_TYPE_ODD_FLAG : 0);
  data.set(compressedPubKey.subarray(1), 1);
  return encode(network.pubKeyAddrId, data);
}

/**
 * Derive the standard P2PKH address for a public key (`hash160` of the key).
 *
 * Accepts **either** serialization: 33-byte compressed or 65-byte uncompressed.
 * They hash to different addresses, and both are legitimate — dcrd hashes
 * whichever form the caller holds — so refusing the uncompressed form would break
 * the only address a signature script built with
 * `signatureScript(..., compressed = false)` can ever satisfy.
 *
 * The key is validated as a real curve point. Without that, any byte string
 * hashes to something and produces a well-formed, valid-checksum address that no
 * key can ever spend from — and the way to hit it is mundane: passing
 * `privateKeyBytes()` where `publicKey()` was meant type-checks silently, because
 * both are `Uint8Array`, and 32 vs 33 bytes is invisible at the call site.
 */
export function addressFromPubKey(pubKey: Uint8Array, network: Network): string {
  assertPubKey(pubKey, "addressFromPubKey");
  return pubKeyHashAddress(hash160(pubKey), network);
}

/** Derive the P2SH address that pays to `redeemScript`. */
export function addressFromScript(redeemScript: Uint8Array, network: Network): string {
  return scriptHashAddress(hash160(redeemScript), network);
}

/**
 * Decode and validate an address. When `network` is given the address must
 * belong to it; otherwise the network is inferred from the version prefix.
 */
export function decodeAddress(address: string, network?: Network): DecodedAddress {
  // Bound the input before decoding. base58 decoding is quadratic, so without
  // this a long string is a cheap way to stall the event loop — and every length
  // check below happens after the decode. dcrd caps identically
  // (stdaddr.DecodeAddressV0's maxV0AddrLen): the largest version-0 address holds
  // a 33-byte payload plus a 2-byte prefix and a 4-byte checksum.
  if (address.length > MAX_ADDRESS_LENGTH) {
    throw new Error(
      `decodeAddress: ${address.length} characters exceeds the ${MAX_ADDRESS_LENGTH}-character maximum`,
    );
  }
  const data = checkDecode(address); // throws on bad checksum
  if (data.length < 3) throw new Error("decodeAddress: too short");
  const prefix: [number, number] = [data[0]!, data[1]!];
  const payload = data.subarray(2);

  const match = PREFIXES.find(
    (e) =>
      e.prefix[0] === prefix[0] &&
      e.prefix[1] === prefix[1] &&
      (!network || e.network === network),
  );
  if (!match) {
    throw new Error(
      `decodeAddress: unknown address prefix 0x${prefix[0]!.toString(16)}${prefix[1]!
        .toString(16)
        .padStart(2, "0")}`,
    );
  }

  if (match.kind === "pubkey-ecdsa") {
    // One address ID covers all three signature suites; the payload's first byte
    // says which, so the concrete kind comes from decoding rather than the prefix.
    if (payload.length !== 33) throw new Error("decodeAddress: bad pubkey length");
    const { kind, pubKey } = decodePubKeyData(payload);
    return { network: match.network, kind, pubKey, address };
  }
  if (payload.length !== 20) throw new Error("decodeAddress: bad hash length");
  return {
    network: match.network,
    kind: match.kind as HashAddressKind,
    hash: copyOf(payload, 0, 20),
    address,
  };
}

/** True when `address` is a well-formed address (optionally for `network`). */
export function isValidAddress(address: string, network?: Network): boolean {
  try {
    decodeAddress(address, network);
    return true;
  } catch {
    return false;
  }
}

/**
 * Build the pkScript that pays to `address`.
 *
 * `network` is **required**, and deliberately so. A payment script commits only
 * to the 20-byte hash, not to the network, so `addressToScript` on a testnet
 * address produces bytes byte-identical to the mainnet address for the same hash
 * — a pasted testnet address would quietly pay whoever controls that hash on
 * mainnet. Naming the expected network here is the only thing that catches it.
 *
 * Use {@link decodeAddress} without a network when you genuinely want to inspect
 * an address of unknown origin; it returns the network it found.
 */
export function addressToScript(address: string, network: Network): Uint8Array {
  // Checked at runtime, not just by the type system: a JavaScript caller (or a
  // stale `.d.ts`) can still pass nothing, and silently falling back to
  // network-agnostic decoding is the exact failure this parameter exists to stop.
  if (!network || typeof network.name !== "string") {
    throw new Error("addressToScript: a network is required (pass mainnet, testnet3, simnet or regnet)");
  }
  const d = decodeAddress(address, network);
  switch (d.kind) {
    case "pubkeyhash-ecdsa":
      return payToPubKeyHashScript(d.hash);
    // The alternative signature suites use OP_CHECKSIGALT with the signature
    // type pushed as a small integer (Ed25519 = 1, Schnorr = 2).
    case "pubkeyhash-ed25519":
      return payToPubKeyHashAltScript(d.hash, 1);
    case "pubkeyhash-schnorr":
      return payToPubKeyHashAltScript(d.hash, 2);
    case "scripthash":
      return payToScriptHashScript(d.hash);
    case "pubkey-ecdsa":
      return payToPubKeyScript(d.pubKey);
    case "pubkey-ed25519":
      return payToPubKeyAltScript(d.pubKey, 1);
    case "pubkey-schnorr":
      return payToPubKeyAltScript(d.pubKey, 2);
  }
}

/** Low-level: base58-decode an address without checksum validation. */
export function rawDecode(address: string): Uint8Array {
  return base58Decode(address);
}
