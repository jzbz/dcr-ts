/**
 * WIF (Wallet Import Format) private keys, Decred style.
 *
 * Decred's WIF differs from Bitcoin's in two ways: the network prefix is two
 * bytes, and instead of Bitcoin's trailing "compressed" flag it carries a
 * leading signature-type byte selecting the key's signature suite. The layout
 * is `base58check(privateKeyId[2] || sigType[1] || privKey[32])`.
 */
import { base58Decode, base58Encode } from "./base58.js";
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
  if (privateKey.length !== 32) throw new Error("encodeWif: private key must be 32 bytes");
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

/** Decode and validate a WIF string. */
export function decodeWif(wif: string): DecodedWif {
  const full = base58Decode(wif);
  if (full.length !== 39) throw new Error("decodeWif: bad length");
  const data = full.subarray(0, 35);
  const checksum = full.subarray(35);
  const expected = wifChecksum(data);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expected[i]) throw new Error("decodeWif: bad checksum");
  }
  const prefix: [number, number] = [data[0]!, data[1]!];
  const signatureType = data[2]! as SignatureType;
  const privateKey = data.slice(3);

  const network = Object.values(networks).find(
    (n) => n.privateKeyId[0] === prefix[0] && n.privateKeyId[1] === prefix[1],
  );
  if (!network) throw new Error("decodeWif: unknown network prefix");
  if (SignatureType[signatureType] === undefined) {
    throw new Error(`decodeWif: unknown signature type ${signatureType}`);
  }
  return { privateKey, network, signatureType };
}
