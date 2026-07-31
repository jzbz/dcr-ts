/**
 * WIF (Wallet Import Format) private keys, Decred style.
 *
 * Decred's WIF differs from Bitcoin's in two ways: the network prefix is two
 * bytes, and instead of Bitcoin's trailing "compressed" flag it carries a
 * leading signature-type byte selecting the key's signature suite. The layout
 * is `base58check(privateKeyId[2] || sigType[1] || privKey[32])`.
 */
import { err } from "./errors.js";
import { base58Decode, base58Encode, maxBase58Length } from "./base58.js";
import { blake256 } from "./hash.js";
import type { Network } from "./networks.js";
import { networks } from "./networks.js";

/** Decred signature suites, matching dcrd's `dcrec.SignatureType`. */
export enum SignatureType {
  Ecdsa = 0,
  Ed25519 = 1,
  SchnorrSecp256k1 = 2,
}

export interface DecodedWif {
  readonly privateKey: Uint8Array;
  readonly network: Network;
  readonly signatureType: SignatureType;
}

// Unlike addresses, WIF uses a *single* BLAKE-256 checksum (dcrd's
// `chainhash.HashB`), not the double-BLAKE-256 of base58check.
function wifChecksum(data: Uint8Array): Uint8Array {
  return blake256(data).subarray(0, 4);
}

/** Encode a 32-byte private key as WIF. */
export function encodeWif(
  privateKey: Uint8Array,
  network: Network,
  signatureType: SignatureType = SignatureType.Ecdsa,
): string {
  if (privateKey.length !== 32) throw err("bad-length", "encodeWif", `private key must be 32 bytes, got ${privateKey.length}`);
  const payload = new Uint8Array(3 + 32);
  payload[0] = network.privateKeyId[0];
  payload[1] = network.privateKeyId[1];
  payload[2] = signatureType;
  payload.set(privateKey, 3);
  const full = new Uint8Array(payload.length + 4);
  full.set(payload);
  full.set(wifChecksum(payload), payload.length);
  return base58Encode(full);
}

/**
 * Longest a WIF string can be: 2 prefix + 1 suite + 32 key + 4 checksum bytes.
 */
export const MAX_WIF_LENGTH = maxBase58Length(39);

/** Decode and validate a WIF string. */
export function decodeWif(wif: string): DecodedWif {
  // Bound before decoding; base58 decoding is quadratic. See maxBase58Length.
  if (wif.length > MAX_WIF_LENGTH) {
    throw err(
      "input-too-long",
      "decodeWif",
      `${wif.length} characters exceeds the ${MAX_WIF_LENGTH}-character maximum`,
    );
  }
  const full = base58Decode(wif);
  if (full.length !== 39) throw err("bad-length", "decodeWif", `decoded to ${full.length} bytes, expected 39`);
  const data = full.subarray(0, 35);
  const checksum = full.subarray(35);
  const expected = wifChecksum(data);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expected[i]) throw err("bad-checksum", "decodeWif", "checksum does not match");
  }
  const prefix: [number, number] = [data[0]!, data[1]!];
  const signatureType = data[2]! as SignatureType;
  const privateKey = data.slice(3);

  const network = Object.values(networks).find(
    (n) => n.privateKeyId[0] === prefix[0] && n.privateKeyId[1] === prefix[1],
  );
  if (!network) throw err("unknown-prefix", "decodeWif", `no network has the private-key prefix 0x${prefix[0]!.toString(16).padStart(2, "0")}${prefix[1]!.toString(16).padStart(2, "0")}`);
  if (SignatureType[signatureType] === undefined) {
    throw err("unsupported-signature-type", "decodeWif", `unknown signature type ${signatureType}`);
  }
  return { privateKey, network, signatureType };
}
