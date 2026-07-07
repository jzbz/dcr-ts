import { describe, expect, test } from "vitest";
import { outPointFromTxid, Transaction, TxTree } from "../src/tx.js";
import { Reader } from "../src/bytes.js";
import { calcSignatureHash, SigHashType } from "../src/sighash.js";
import { rawTxInSignature, signatureScript, signP2PKHInput, verifyHash } from "../src/sign.js";
import { payToPubKeyHashScript } from "../src/script.js";
import { publicKeyFromPrivate } from "../src/keys.js";
import { bytesToHex, hexToBytes, vectors } from "./helpers.js";

// Rebuild the exact transaction the dcrd generator serialized, so every byte
// (serialization, txid, sighash, signature script) can be compared directly.
function buildFixtureTx(): { tx: Transaction; subScript: Uint8Array } {
  const pkh = hexToBytes(vectors.keys.pubkeyHash160);
  const outScript = payToPubKeyHashScript(pkh);
  const tx = new Transaction();
  tx.version = 1;
  // Prevout hash in internal byte order (dcrd NewHashFromStr reverses the display string).
  const prevHashDisplay = "c672c1c5d15e58b9a5f1b6e2d3f4e5c6b7a8091011121314151617181920212a";
  const prevHash = hexToBytes(prevHashDisplay).reverse();
  tx.addInput(
    { hash: prevHash, index: 0, tree: TxTree.Regular },
    { sequence: 0xffffffff, valueIn: 100000000n, blockHeight: 123456, blockIndex: 2 },
  );
  tx.addOutput(60000000n, outScript, 0);
  tx.addOutput(39990000n, outScript, 0);
  tx.lockTime = 0;
  tx.expiry = 0;
  return { tx, subScript: outScript };
}

describe("transaction wire format", () => {
  const { tx } = buildFixtureTx();

  test("full, prefix and witness serialization match dcrd", () => {
    expect(bytesToHex(tx.serialize())).toBe(vectors.tx.serialized);
    expect(bytesToHex(tx.serializePrefix())).toBe(vectors.tx.prefixSer);
    expect(bytesToHex(tx.serializeWitness())).toBe(vectors.tx.witnessSer);
  });

  test("txid and full txid match dcrd", () => {
    expect(tx.txid()).toBe(vectors.tx.txid);
    expect(tx.fullTxid()).toBe(vectors.tx.txidFull);
  });

  test("rejects non-canonical varints (dcrd ErrNonCanonicalVarInt)", () => {
    // Direct Reader checks at each discriminant boundary.
    expect(new Reader(hexToBytes("fc")).varInt()).toBe(0xfc);
    expect(new Reader(hexToBytes("fdfd00")).varInt()).toBe(0xfd);
    expect(() => new Reader(hexToBytes("fd0100")).varInt()).toThrow(/non-canonical/);
    expect(new Reader(hexToBytes("fe00000100")).varInt()).toBe(0x10000);
    expect(() => new Reader(hexToBytes("feffff0000")).varInt()).toThrow(/non-canonical/);
    expect(new Reader(hexToBytes("ff0000000001000000")).varInt()).toBe(0x100000000);
    expect(() => new Reader(hexToBytes("ffffffffff00000000")).varInt()).toThrow(/non-canonical/);

    // A transaction whose input count is re-encoded non-canonically must not
    // parse: it would hash to a different txid than its own bytes.
    const canonical = vectors.tx.serialized;
    const mutated = canonical.slice(0, 8) + "fd0100" + canonical.slice(10);
    expect(() => Transaction.fromBytes(hexToBytes(mutated))).toThrow(/non-canonical/);
  });

  test("outPointFromTxid validates its input", () => {
    expect(() => outPointFromTxid("zz".repeat(32), 0)).toThrow(/hex/);
    expect(() => outPointFromTxid("ab", 0)).toThrow(/hex/);
    const op = outPointFromTxid("00".repeat(31) + "ff", 3);
    // Display order is reversed into internal order.
    expect(op.hash[0]).toBe(0xff);
    expect(op.hash[31]).toBe(0x00);
    expect(op.index).toBe(3);
  });

  test("round-trips through fromBytes", () => {
    const parsed = Transaction.fromBytes(hexToBytes(vectors.tx.serialized));
    expect(bytesToHex(parsed.serialize())).toBe(vectors.tx.serialized);
    expect(parsed.txid()).toBe(vectors.tx.txid);
    expect(parsed.inputs.length).toBe(1);
    expect(parsed.outputs.length).toBe(2);
    expect(parsed.inputs[0]!.valueIn).toBe(100000000n);
    expect(parsed.inputs[0]!.blockHeight).toBe(123456);
    expect(parsed.outputs[0]!.value).toBe(60000000n);
  });
});

// The multi-input/output transaction the generator built for exhaustive
// signature-hash coverage.
function buildFixtureTx2(): { tx: Transaction; subScript: Uint8Array } {
  const outScript = payToPubKeyHashScript(hexToBytes(vectors.keys.pubkeyHash160));
  const tx = new Transaction();
  tx.version = 1;
  tx.addInput(
    { hash: hexToBytes("11".repeat(32)).reverse(), index: 7, tree: TxTree.Regular },
    { sequence: 0xfffffffe, valueIn: 500000000n, blockHeight: 200, blockIndex: 1 },
  );
  tx.addInput(
    { hash: hexToBytes("22".repeat(32)).reverse(), index: 1, tree: TxTree.Stake },
    { sequence: 0xffffffff, valueIn: 250000000n, blockHeight: 201, blockIndex: 4 },
  );
  tx.addOutput(100000000n, outScript, 0);
  tx.addOutput(200000000n, outScript, 0);
  tx.addOutput(449990000n, outScript, 0);
  tx.lockTime = 500000;
  tx.expiry = 600000;
  return { tx, subScript: outScript };
}

describe("signature hash", () => {
  test("SigHashAll matches dcrd CalcSignatureHash", () => {
    const { tx, subScript } = buildFixtureTx();
    const h = calcSignatureHash(subScript, SigHashType.All, tx, 0);
    expect(bytesToHex(h)).toBe(vectors.tx.sigHashAll);
    expect(bytesToHex(subScript)).toBe(vectors.tx.subScript);
  });

  test("multi-io tx serializes and matches dcrd for all hash-type variants", () => {
    const { tx, subScript } = buildFixtureTx2();
    expect(bytesToHex(tx.serialize())).toBe(vectors.tx2.serialized);
    expect(tx.txid()).toBe(vectors.tx2.txid);

    const ht: Record<string, number> = {
      all: SigHashType.All,
      none: SigHashType.None,
      single: SigHashType.Single,
      all_acp: SigHashType.All | SigHashType.AnyOneCanPay,
      none_acp: SigHashType.None | SigHashType.AnyOneCanPay,
      single_acp: SigHashType.Single | SigHashType.AnyOneCanPay,
    };
    for (const idx of [0, 1]) {
      const expected = vectors.tx2.sighashes[`in${idx}`]!;
      for (const [name, type] of Object.entries(ht)) {
        const h = calcSignatureHash(subScript, type, tx, idx);
        expect(bytesToHex(h), `in${idx} ${name}`).toBe(expected[name]!);
      }
    }
  });
});

describe("signing", () => {
  const priv = hexToBytes(vectors.keys.privHex);

  test("deterministic signature and script match dcrd byte-for-byte", () => {
    const { tx, subScript } = buildFixtureTx();
    const rawSig = rawTxInSignature(tx, 0, subScript, SigHashType.All, priv);
    // DER portion (drop the trailing hash-type byte).
    expect(bytesToHex(rawSig.subarray(0, rawSig.length - 1))).toBe(vectors.tx.derSig);
    expect(rawSig[rawSig.length - 1]).toBe(SigHashType.All);

    const script = signatureScript(tx, 0, subScript, SigHashType.All, priv);
    expect(bytesToHex(script)).toBe(vectors.tx.sigScript);
  });

  test("produced signature verifies against the public key", () => {
    const { tx, subScript } = buildFixtureTx();
    const h = calcSignatureHash(subScript, SigHashType.All, tx, 0);
    const rawSig = rawTxInSignature(tx, 0, subScript, SigHashType.All, priv);
    const der = rawSig.subarray(0, rawSig.length - 1);
    expect(verifyHash(h, der, publicKeyFromPrivate(priv))).toBe(true);
  });

  test("signP2PKHInput assigns the signature script in place", () => {
    const { tx, subScript } = buildFixtureTx();
    signP2PKHInput(tx, 0, subScript, priv);
    expect(bytesToHex(tx.inputs[0]!.signatureScript)).toBe(vectors.tx.sigScript);
  });
});
