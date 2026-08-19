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
import { bytesToBigInt, ED25519_CURVE_ORDER } from "./keys.js";
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

/**
 * Throw unless an Ed25519-suite key is a scalar dcrd would accept.
 *
 * dcrd runs suite-1 keys through `edwards.PrivKeyFromScalar` on both sides of the
 * codec — `NewWIF` and `DecodeWIF` — which rejects a zero scalar and anything
 * *above* the group order. The bound really is strict: `D.Cmp(N) > 0`, so a
 * scalar equal to the order is accepted, even though it derives the identity
 * point. Matched as written, so the accept/reject boundary is identical.
 *
 * The secp256k1 suites are deliberately left unchecked, as dcrd leaves them:
 * `secp256k1.PrivKeyFromBytes` cannot fail — it reduces mod n and discards the
 * overflow — so dcrd accepts a zero or all-`ff` key for suites 0 and 2.
 */
function assertWifScalar(privateKey: Uint8Array, signatureType: SignatureType, who: string): void {
  if (signatureType !== SignatureType.Ed25519) return;
  const scalar = bytesToBigInt(privateKey);
  if (scalar === 0n || scalar > ED25519_CURVE_ORDER) {
    throw err("invalid-private-key", who, "Ed25519 scalar is zero or above the group order");
  }
}

/** Encode a 32-byte private key as WIF. */
export function encodeWif(
  privateKey: Uint8Array,
  network: Network,
  signatureType: SignatureType = SignatureType.Ecdsa,
): string {
  if (privateKey.length !== 32) throw err("bad-length", "encodeWif", `private key must be 32 bytes, got ${privateKey.length}`);
  // Checked here as well as on decode, because `payload[2] = signatureType` is a
  // store into a Uint8Array, which coerces rather than rejects: 256 would land as
  // suite 0, -1 as suite 255, 1.5 as suite 1, and the enum *name* "Ed25519" as
  // suite 0 — a well-formed WIF for a suite the caller never asked for. dcrd's
  // `NewWIF` rejects an unsupported scheme too. The integer guard is what catches
  // the last of those, since `SignatureType["Ed25519"]` is 1.
  if (!Number.isInteger(signatureType) || SignatureType[signatureType] === undefined) {
    throw err("unsupported-signature-type", "encodeWif", `unknown signature type ${signatureType}`);
  }
  assertWifScalar(privateKey, signatureType, "encodeWif");
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
  // A deliberate divergence: dcrd's `DecodeWIF` switches on this byte with no
  // default arm, so an unknown suite yields a WIF holding a nil private key —
  // one whose own `String()` is no longer a WIF. Rejecting is the only sane read.
  if (SignatureType[signatureType] === undefined) {
    throw err("unsupported-signature-type", "decodeWif", `unknown signature type ${signatureType}`);
  }
  assertWifScalar(privateKey, signatureType, "decodeWif");
  return { privateKey, network, signatureType };
}
