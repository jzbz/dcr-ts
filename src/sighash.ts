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
import { blake256 } from "./hash.js";
import { Writer } from "./bytes.js";
import type { Transaction } from "./tx.js";

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
 * Compute the signature hash for input `idx` of `tx` under `hashType`, with
 * `subScript` as the script being satisfied (the prevout pkScript for P2PKH, or
 * the redeem script for P2SH). Returns the 32-byte hash to be signed.
 */
export function calcSignatureHash(
  subScript: Uint8Array,
  hashType: SigHashType | number,
  tx: Transaction,
  idx: number,
): Uint8Array {
  const masked = hashType & SIG_HASH_MASK;
  const anyoneCanPay = (hashType & SigHashType.AnyOneCanPay) !== 0;

  if (masked === SigHashType.Single && idx >= tx.outputs.length) {
    throw new Error(
      `sighash: SigHashSingle input ${idx} has no corresponding output`,
    );
  }
  if (idx < 0 || idx >= tx.inputs.length) {
    throw new Error(`sighash: input index ${idx} out of range`);
  }

  // Inputs committed to: only the signed input under AnyOneCanPay, else all.
  const inputs = anyoneCanPay ? [tx.inputs[idx]!] : tx.inputs;
  const signInIdx = anyoneCanPay ? 0 : idx;

  // ---- Prefix hash ----
  const pw = new Writer();
  pw.u32(((tx.version & 0xffff) | (SIG_HASH_SERIALIZE_PREFIX << 16)) >>> 0);

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
  const prefixHash = blake256(pw.finish());

  // ---- Witness hash ----
  const ww = new Writer();
  ww.u32(((tx.version & 0xffff) | (SIG_HASH_SERIALIZE_WITNESS << 16)) >>> 0);
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
