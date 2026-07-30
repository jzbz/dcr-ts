/**
 * Transaction input signing for P2PKH (secp256k1 ECDSA, SigHashAll and friends).
 *
 * Signatures are deterministic (RFC 6979) and low-S normalised, matching dcrd
 * exactly — the same key and signature hash produce byte-identical DER. The
 * signature script for a P2PKH input is `<DER-sig ‖ hashType> <pubkey>`.
 */
import { secp256k1 } from "@noble/curves/secp256k1";
import { publicKeyFromPrivate } from "./keys.js";
import { pushData } from "./script.js";
import { assertSignableSigHashType, calcSignatureHash, SigHashType } from "./sighash.js";
import type { Transaction } from "./tx.js";

/** DER-encode a deterministic low-S ECDSA signature over a 32-byte hash. */
export function signHash(hash: Uint8Array, privateKey: Uint8Array): Uint8Array {
  const sig = secp256k1.sign(hash, privateKey, { lowS: true });
  return sig.toDERRawBytes();
}

/**
 * Verify a **DER** signature over a 32-byte hash against a public key.
 *
 * Strictly DER, and low-S. `@noble`'s `verify` falls back to the 64-byte compact
 * `r ‖ s` encoding when DER parsing fails, so without parsing the DER ourselves
 * first this would accept a signature encoding dcrd's script engine rejects — a
 * co-signer or hardware device emitting compact signatures would pass local
 * validation and then fail consensus.
 */
export function verifyHash(
  hash: Uint8Array,
  derSignature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    const sig = secp256k1.Signature.fromDER(derSignature);
    // Require the *canonical* DER encoding, matching dcrd's
    // IsStrictSignatureEncoding: re-encoding a parsed signature is canonical, so
    // any padding or non-minimal length in the input shows up as a mismatch.
    const canonical = sig.toDERRawBytes();
    if (canonical.length !== derSignature.length) return false;
    for (let i = 0; i < canonical.length; i++) {
      if (canonical[i] !== derSignature[i]) return false;
    }
    if (sig.hasHighS()) return false;
    // Verify from the unambiguous 64-byte form; passing bytes back in would let
    // noble re-guess the encoding.
    return secp256k1.verify(sig.toCompactRawBytes(), hash, publicKey, { lowS: true });
  } catch {
    return false;
  }
}

/**
 * Produce the raw signature for input `idx`: the DER signature over the Decred
 * signature hash with the one-byte hash type appended (as it appears in a
 * signature script and in a signature stack element).
 */
export function rawTxInSignature(
  tx: Transaction,
  idx: number,
  subScript: Uint8Array,
  hashType: SigHashType | number,
  privateKey: Uint8Array,
): Uint8Array {
  // Only the six hash types dcrd's engine accepts can produce a spendable input.
  // calcSignatureHash still computes a hash for other byte values, matching
  // dcrd's split between hashing and validation, but there is no reason to hand
  // back a signature that cannot be redeemed.
  assertSignableSigHashType(hashType);
  const hash = calcSignatureHash(subScript, hashType, tx, idx);
  const der = signHash(hash, privateKey);
  const out = new Uint8Array(der.length + 1);
  out.set(der);
  out[der.length] = hashType & 0xff;
  return out;
}

/**
 * Build the full P2PKH signature script for input `idx`:
 * `push(<DER-sig ‖ hashType>) push(<pubkey>)`.
 */
export function signatureScript(
  tx: Transaction,
  idx: number,
  subScript: Uint8Array,
  hashType: SigHashType | number,
  privateKey: Uint8Array,
  compressed = true,
): Uint8Array {
  const rawSig = rawTxInSignature(tx, idx, subScript, hashType, privateKey);
  const pubKey = publicKeyFromPrivate(privateKey, compressed);
  const a = pushData(rawSig);
  const b = pushData(pubKey);
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

/**
 * Sign input `idx` in place: compute and assign its P2PKH signature script.
 * Returns the signed transaction for chaining.
 */
export function signP2PKHInput(
  tx: Transaction,
  idx: number,
  subScript: Uint8Array,
  privateKey: Uint8Array,
  hashType: SigHashType | number = SigHashType.All,
  compressed = true,
): Transaction {
  tx.inputs[idx]!.signatureScript = signatureScript(
    tx,
    idx,
    subScript,
    hashType,
    privateKey,
    compressed,
  );
  return tx;
}
