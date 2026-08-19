/**
 * Transaction input signing for P2PKH (secp256k1 ECDSA, SigHashAll and friends).
 *
 * Signatures are deterministic (RFC 6979) and low-S normalised, matching dcrd
 * exactly — the same key and signature hash produce byte-identical DER. The
 * signature script for a P2PKH input is `<DER-sig ‖ hashType> <pubkey>`.
 */
import { secp256k1 } from "@noble/curves/secp256k1";
import { err } from "./errors.js";
import { assertPrivateKey, publicKeyFromPrivate } from "./keys.js";
import { pushData } from "./script.js";
import {
  assertSignableSigHashType,
  calcSignatureHash,
  sigHashPrefixAll,
  SigHashType,
} from "./sighash.js";
import type { Transaction } from "./tx.js";

/**
 * Throw unless `hash` is exactly 32 bytes.
 *
 * Both `@noble` and dcrd reduce the hash to a scalar with no length check, and
 * they agree byte-for-byte on what that produces — so this is not a divergence
 * in the signatures either side emits, it is a hazard both share. It bites
 * because the reduction is not injective:
 *
 * - a short hash signs identically to itself left-padded with zeros to 32 bytes
 *   (`sign(h31)` and `sign(0x00 ‖ h31)` are the same DER bytes), and
 * - a long hash is silently truncated to its first 32 bytes.
 *
 * So a caller who passes a mis-sliced buffer gets a valid signature committing
 * to a *different* message than the one they hold, with nothing raising. dcrd
 * needs no guard because its type system is the guard: `chainhash.Hash` is
 * `[32]byte` and the only thing that ever reaches `ecdsa.Sign` is a BLAKE-256
 * output. A `Uint8Array` carries no length in its type, so the check is explicit
 * here — the same reason {@link assertPrivateKey} exists.
 */
function assertHash32(hash: Uint8Array, who: string): void {
  if (hash.length !== 32) {
    throw err("bad-length", who, `signature hash must be 32 bytes, got ${hash.length}`);
  }
}

/** DER-encode a deterministic low-S ECDSA signature over a 32-byte hash. */
export function signHash(hash: Uint8Array, privateKey: Uint8Array): Uint8Array {
  assertHash32(hash, "signHash");
  assertPrivateKey(privateKey, "signHash");
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
  // Before the try, and thrown rather than returned as `false`: a wrong-length
  // hash is a caller bug, not a failed verification, and `false` would hide the
  // one case that matters — a 31-byte hash verifies against a signature over its
  // zero-padded 32-byte form, so `true` here would attest to the wrong message.
  assertHash32(hash, "verifyHash");
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
 *
 * For a transaction with several inputs prefer {@link signP2PKHInputs}, which
 * reuses one prefix hash instead of recomputing it per input.
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

/** One input to sign, for {@link signP2PKHInputs}. */
export interface P2PKHInputToSign {
  /** Index into `tx.inputs`. */
  idx: number;
  /** The script being satisfied — the prevout pkScript for P2PKH. */
  subScript: Uint8Array;
  privateKey: Uint8Array;
  /** Serialize the public key compressed (the default). */
  compressed?: boolean;
}

/**
 * Sign several P2PKH inputs in place, reusing one prefix hash.
 *
 * `calcSignatureHash` re-serializes and re-hashes the whole transaction prefix on
 * every call — every outpoint and every output script — which is the dominant
 * cost for a transaction with many inputs. Under `SigHashAll` without
 * `AnyOneCanPay` that half is input-independent, so it is computed once here and
 * reused, which is what dcrd's `cachedPrefix` parameter is for.
 *
 * This lowers the constant, not the exponent: the witness half still walks every
 * input per call, so signing stays O(N²). On the hashing alone it measured 12x at
 * 50 inputs and 26x at 500; end to end the gain is smaller (1.7x at 250) because
 * ECDSA dominates.
 *
 * The prefix hash is taken **before** any signature script is assigned, which is
 * also why this is correct: the prefix commits to no witness data, so writing
 * signature scripts cannot invalidate it. For other hash types the cache is
 * ignored and each input is hashed independently, so passing one is always safe.
 */
export function signP2PKHInputs(
  tx: Transaction,
  toSign: readonly P2PKHInputToSign[],
  hashType: SigHashType | number = SigHashType.All,
): Transaction {
  assertSignableSigHashType(hashType);
  const cachedPrefix = sigHashPrefixAll(tx);
  for (const { idx, subScript, privateKey, compressed = true } of toSign) {
    const hash = calcSignatureHash(subScript, hashType, tx, idx, cachedPrefix);
    const der = signHash(hash, privateKey);
    const rawSig = new Uint8Array(der.length + 1);
    rawSig.set(der);
    rawSig[der.length] = hashType & 0xff;
    const pubKey = publicKeyFromPrivate(privateKey, compressed);
    const a = pushData(rawSig);
    const b = pushData(pubKey);
    const script = new Uint8Array(a.length + b.length);
    script.set(a);
    script.set(b, a.length);
    tx.inputs[idx]!.signatureScript = script;
  }
  return tx;
}
