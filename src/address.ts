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
import { base58Decode, checkDecode, checkEncode } from "./base58.js";
import { hash160 } from "./hash.js";
import type { Network } from "./networks.js";
import { networks } from "./networks.js";
import {
  payToPubKeyHashAltScript,
  payToPubKeyHashScript,
  payToPubKeyScript,
  payToScriptHashScript,
} from "./script.js";
import { isValidPublicKey } from "./keys.js";

export type AddressKind =
  | "pubkeyhash-ecdsa"
  | "pubkeyhash-ed25519"
  | "pubkeyhash-schnorr"
  | "scripthash"
  | "pubkey-ecdsa";

export interface DecodedAddress {
  readonly network: Network;
  readonly kind: AddressKind;
  /** 20-byte hash for the hash-based kinds. */
  readonly hash?: Uint8Array;
  /** Serialized public key for the pay-to-pubkey kind. */
  readonly pubKey?: Uint8Array;
  /** The original address string. */
  readonly address: string;
}

interface PrefixEntry {
  network: Network;
  kind: AddressKind;
  prefix: readonly [number, number];
}

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
  const prefix = compressedPubKey[0]!;
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error("pubKeyAddress: expected a 33-byte compressed public key");
  }
  const data = new Uint8Array(33);
  data[0] = SignatureTypeEcdsa | (prefix === 0x03 ? SIG_TYPE_ODD_FLAG : 0);
  data.set(compressedPubKey.subarray(1), 1);
  return data;
}

function decodePubKeyData(data: Uint8Array): Uint8Array {
  const sigType = data[0]! & ~SIG_TYPE_ODD_FLAG;
  if (sigType !== SignatureTypeEcdsa) {
    throw new Error("decodeAddress: unsupported pubkey signature type");
  }
  const odd = (data[0]! & SIG_TYPE_ODD_FLAG) !== 0;
  const out = new Uint8Array(33);
  out[0] = odd ? 0x03 : 0x02;
  out.set(data.subarray(1), 1);
  if (!isValidPublicKey(out)) {
    throw new Error("decodeAddress: pubkey is not a valid curve point");
  }
  return out;
}

// dcrec.STEcdsaSecp256k1
const SignatureTypeEcdsa = 0;

/** Encode a compressed public key as a pay-to-pubkey (secp256k1 ECDSA) address. */
export function pubKeyAddress(compressedPubKey: Uint8Array, network: Network): string {
  if (compressedPubKey.length !== 33) throw new Error("pubKeyAddress: pubkey must be 33 bytes");
  return encode(network.pubKeyAddrId, encodePubKeyData(compressedPubKey));
}

/** Derive the standard P2PKH address for a public key (`hash160` of the key). */
export function addressFromPubKey(compressedPubKey: Uint8Array, network: Network): string {
  return pubKeyHashAddress(hash160(compressedPubKey), network);
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
    if (payload.length !== 33) throw new Error("decodeAddress: bad pubkey length");
    return {
      network: match.network,
      kind: match.kind,
      pubKey: decodePubKeyData(payload),
      address,
    };
  }
  if (payload.length !== 20) throw new Error("decodeAddress: bad hash length");
  return { network: match.network, kind: match.kind, hash: payload.slice(), address };
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

/** Build the pkScript that pays to `address`. */
export function addressToScript(address: string, network?: Network): Uint8Array {
  const d = decodeAddress(address, network);
  switch (d.kind) {
    case "pubkeyhash-ecdsa":
      return payToPubKeyHashScript(d.hash!);
    // The alternative signature suites use OP_CHECKSIGALT with the signature
    // type pushed as a small integer (Ed25519 = 1, Schnorr = 2).
    case "pubkeyhash-ed25519":
      return payToPubKeyHashAltScript(d.hash!, 1);
    case "pubkeyhash-schnorr":
      return payToPubKeyHashAltScript(d.hash!, 2);
    case "scripthash":
      return payToScriptHashScript(d.hash!);
    case "pubkey-ecdsa":
      return payToPubKeyScript(d.pubKey!);
  }
}

/** Low-level: base58-decode an address without checksum validation. */
export function rawDecode(address: string): Uint8Array {
  return base58Decode(address);
}
