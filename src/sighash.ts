/**
 * The Decred signature hash.
 *
 * Decred does not use Bitcoin's BIP143. Instead the message to sign is
 * `BLAKE256( le32(hashType) || prefixHash || witnessHash )`, where the prefix
 * and witness are re-serialized subsets of the transaction selected by the
 * hash type. This mirrors dcrd's `txscript.CalcSignatureHash` byte-for-byte.
 *
 * The version words embedded in the prefix/witness serializations use dedicated
 * signature-hash serialization types (prefix = 1, witness = **3**), which are
 * fixed by consensus and differ from the wire serialization types.
 */
import { err } from "./errors.js";
import { blake256 } from "./hash.js";
import { Writer } from "./bytes.js";
import { scriptParses } from "./script.js";
import { packVersion, type Transaction } from "./tx.js";

export enum SigHashType {
  All = 0x01,
  None = 0x02,
  Single = 0x03,
  AnyOneCanPay = 0x80,
}

const SIG_HASH_MASK = 0x1f;
const SIG_HASH_SERIALIZE_PREFIX = 1;
const SIG_HASH_SERIALIZE_WITNESS = 3;

/**
 * True when `hashType` is one dcrd's script engine will accept, i.e. the six
 * values `CheckHashTypeEncoding` permits: All/None/Single, each optionally
 * OR'ed with AnyOneCanPay.
 *
 * Note {@link calcSignatureHash} deliberately still computes a hash for other
 * byte values, because dcrd's `calcSignatureHash` does — undefined types hash as
 * if they were All. Validation belongs at the point a signature is *produced*,
 * which is where {@link assertSignableSigHashType} is applied.
 */
export function isSignableSigHashType(hashType: number): boolean {
  if (!Number.isInteger(hashType) || hashType < 0 || hashType > 0xff) return false;
  const masked = hashType & 0x7f; // dcrd: hashType & ^SigHashAnyOneCanPay
  return masked >= SigHashType.All && masked <= SigHashType.Single;
}

/** Throw unless `hashType` is one dcrd's engine accepts. */
export function assertSignableSigHashType(hashType: number): void {
  if (!isSignableSigHashType(hashType)) {
    const shown = Number.isInteger(hashType)
      ? `0x${Number(hashType).toString(16)}`
      : String(hashType);
    throw err(
      "invalid-hash-type",
      "sighash",
      `hash type ${shown} is not one dcrd accepts (All/None/Single, optionally |AnyOneCanPay)`,
    );
  }
}

/**
 * The reusable prefix hash for `SigHashAll` without `AnyOneCanPay`.
 *
 * Under that hash type the prefix half of the signature hash does not depend on
 * which input is being signed, and its serialization is byte-identical to the
 * transaction's own prefix serialization — `SigHashSerializePrefix` and
 * `TxSerializeNoWitness` are both `1`, and the bodies are the same. So this is
 * exactly `tx.hash()`, and passing it to {@link calcSignatureHash} as
 * `cachedPrefix` removes the dominant per-input cost when signing.
 *
 * It does **not** make signing linear. The witness half still walks every input
 * on each call (one varint apiece), so signing N inputs stays O(N²) — but the
 * prefix half is the expensive one, since it re-serializes every outpoint and
 * every output script, so the constant drops by more than an order of magnitude.
 * Measured on the hashing alone: 12x at 50 inputs, 26x at 500.
 *
 * This is what dcrd's `cachedPrefix` parameter exists for.
 */
export function sigHashPrefixAll(tx: Transaction): Uint8Array {
  return tx.hash();
}

/**
 * Compute the signature hash for input `idx` of `tx` under `hashType`, with
 * `subScript` as the script being satisfied (the prevout pkScript for P2PKH, or
 * the redeem script for P2SH). Returns the 32-byte hash to be signed.
 *
 * `cachedPrefix` is an optional pre-computed prefix hash from
 * {@link sigHashPrefixAll}, honoured only for `SigHashAll` without
 * `AnyOneCanPay` — the one case where the prefix half is input-independent. It is
 * ignored for every other hash type rather than trusted, so it is safe to pass
 * for *any hash type*.
 *
 * It is **not** checked against `tx`, because a 32-byte hash carries nothing to
 * check it with: it must be this transaction's current prefix hash. Passing a
 * stale one — taken before the prefix was changed, or from a different
 * transaction — silently produces a signature over the wrong message. Take it
 * from the transaction you are about to sign, after the prefix is final, or use
 * {@link signP2PKHInputs}, which does that for you.
 */
export function calcSignatureHash(
  subScript: Uint8Array,
  hashType: SigHashType | number,
  tx: Transaction,
  idx: number,
  cachedPrefix?: Uint8Array,
): Uint8Array {
  // dcrd's SigHashType is a byte, and the final preimage commits to it as a
  // little-endian uint32 while a signature script carries only the low byte. A
  // value above 0xff would therefore be committed to in full but transmitted
  // truncated, so a verifier would recompute a different hash and the signature
  // could never verify. Reject rather than silently produce that.
  if (!Number.isInteger(hashType) || hashType < 0 || hashType > 0xff) {
    throw err("invalid-hash-type", "sighash", `hash type must be a byte (0..255), got ${hashType}`);
  }
  // NaN and fractional indices slip past both comparisons below (every relational
  // test against NaN is false), leaving a hash that commits the subScript to no
  // input at all.
  if (!Number.isInteger(idx)) {
    throw err("not-an-integer", "sighash", `input index must be an integer, got ${idx}`);
  }

  const masked = hashType & SIG_HASH_MASK;
  const anyoneCanPay = (hashType & SigHashType.AnyOneCanPay) !== 0;

  // dcrd's exported CalcSignatureHash gates on checkScriptParses before hashing;
  // signing against a script that does not tokenize yields a signature over a
  // message dcrd would refuse to compute, i.e. an unspendable input.
  if (!scriptParses(subScript)) {
    throw err("malformed-script", "sighash", "subScript does not tokenize (malformed data push)");
  }

  if (masked === SigHashType.Single && idx >= tx.outputs.length) {
    throw err(
      "out-of-range",
      "sighash",
      `SigHashSingle input ${idx} has no corresponding output`,
    );
  }
  if (idx < 0 || idx >= tx.inputs.length) {
    throw err("out-of-range", "sighash", `input index ${idx} out of range`);
  }

  // Inputs committed to: only the signed input under AnyOneCanPay, else all.
  const inputs = anyoneCanPay ? [tx.inputs[idx]!] : tx.inputs;
  const signInIdx = anyoneCanPay ? 0 : idx;

  // ---- Prefix hash ----
  // For SigHashAll without AnyOneCanPay the prefix half does not depend on which
  // input is being signed, so a caller signing N inputs can compute it once. Every
  // other hash type changes what the prefix commits to — cleared outputs, zeroed
  // sequences, or a single input — so the cache is ignored rather than trusted.
  const prefixIsInputIndependent = masked === SigHashType.All && !anyoneCanPay;
  let prefixHash: Uint8Array;
  if (cachedPrefix !== undefined && prefixIsInputIndependent) {
    if (cachedPrefix.length !== 32) {
      throw err("bad-length", "sighash", `cachedPrefix must be 32 bytes, got ${cachedPrefix.length}`);
    }
    prefixHash = cachedPrefix;
  } else {
    const pw = new Writer();
    pw.u32(packVersion(tx.version, SIG_HASH_SERIALIZE_PREFIX));

    pw.varInt(inputs.length);
    for (let i = 0; i < inputs.length; i++) {
      const input = inputs[i]!;
      const op = input.previousOutPoint;
      pw.bytes(op.hash).u32(op.index).u8(op.tree);
      let sequence = input.sequence;
      if ((masked === SigHashType.None || masked === SigHashType.Single) && i !== signInIdx) {
        sequence = 0;
      }
      pw.u32(sequence);
    }

    // Outputs committed to depend on the hash type.
    let outputs = tx.outputs;
    if (masked === SigHashType.None) outputs = [];
    else if (masked === SigHashType.Single) outputs = tx.outputs.slice(0, idx + 1);

    pw.varInt(outputs.length);
    for (let i = 0; i < outputs.length; i++) {
      const out = outputs[i]!;
      if (masked === SigHashType.Single && i !== idx) {
        // Cleared output: amount -1, empty script.
        pw.i64(-1n).u16(out.version).varInt(0);
      } else {
        pw.i64(out.value).u16(out.version).varBytes(out.pkScript);
      }
    }
    pw.u32(tx.lockTime).u32(tx.expiry);
    prefixHash = blake256(pw.finish());
  }

  // ---- Witness hash ----
  const ww = new Writer();
  ww.u32(packVersion(tx.version, SIG_HASH_SERIALIZE_WITNESS));
  ww.varInt(inputs.length);
  for (let i = 0; i < inputs.length; i++) {
    // Only the signed input commits to the sub script; the rest commit to nil.
    if (i === signInIdx) ww.varBytes(subScript);
    else ww.varInt(0);
  }
  const witnessHash = blake256(ww.finish());

  // ---- Final hash ----
  const fw = new Writer();
  fw.u32(hashType >>> 0).bytes(prefixHash).bytes(witnessHash);
  return blake256(fw.finish());
}
