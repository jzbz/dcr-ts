import { describe, expect, test } from "vitest";
import {
  MAX_SEQUENCE,
  NULL_BLOCK_HEIGHT,
  NULL_BLOCK_INDEX,
  NULL_VALUE_IN,
  outPointFromTxid,
  Transaction,
  TxTree,
} from "../src/tx.js";
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

  test("txid, witness txid and full txid match dcrd", () => {
    expect(tx.txid()).toBe(vectors.tx.txid);
    expect(tx.witnessTxid()).toBe(vectors.tx.txidWitness);
    expect(tx.fullTxid()).toBe(vectors.tx.txidFull);
  });

  // The null witness sentinels are only observable in a transaction that does
  // not set blockHeight/blockIndex explicitly, and every other vector does — so
  // a wrong default sat unnoticed. This one comes from wire.NewTxIn.
  test("addInput defaults match dcrd's wire.NewTxIn sentinels", () => {
    const g = vectors.txNullWitness;
    // dcrd's asymmetry: null height is 0, null index is 0xffffffff.
    expect(String(NULL_VALUE_IN)).toBe(g.nullValueIn);
    expect(String(NULL_BLOCK_HEIGHT)).toBe(g.nullBlockHeight);
    expect(String(NULL_BLOCK_INDEX)).toBe(g.nullBlockIndex);
    expect(String(MAX_SEQUENCE)).toBe(g.maxSequence);
    expect(NULL_BLOCK_HEIGHT).not.toBe(NULL_BLOCK_INDEX);

    const t = new Transaction();
    t.version = 1;
    const prevHash = hexToBytes(
      "c672c1c5d15e58b9a5f1b6e2d3f4e5c6b7a8091011121314151617181920212a",
    ).reverse();
    t.addInput({ hash: prevHash, index: 0, tree: TxTree.Regular }); // no witness opts at all
    t.addOutput(50000000n, payToPubKeyHashScript(hexToBytes(vectors.keys.pubkeyHash160)), 0);

    expect(t.inputs[0]!.valueIn).toBe(NULL_VALUE_IN);
    expect(t.inputs[0]!.blockHeight).toBe(NULL_BLOCK_HEIGHT);
    expect(t.inputs[0]!.blockIndex).toBe(NULL_BLOCK_INDEX);
    expect(bytesToHex(t.serialize()), "full").toBe(g.serialized);
    expect(bytesToHex(t.serializePrefix()), "prefix").toBe(g.prefixSer);
    expect(bytesToHex(t.serializeWitness()), "witness").toBe(g.witnessSer);
    expect(t.txid(), "txid").toBe(g.txid);
    expect(t.witnessTxid(), "witness txid").toBe(g.txidWitness);
    expect(t.fullTxid(), "full txid").toBe(g.txidFull);
  });

  // 300 outputs: past the 0xfd varint discriminant and well past the writer's
  // initial 256-byte buffer, neither of which any other vector reaches.
  test("a 300-output transaction matches dcrd (multi-byte varint, writer growth)", () => {
    const g = vectors.txBig;
    const outScript = payToPubKeyHashScript(hexToBytes(vectors.keys.pubkeyHash160));
    const t = new Transaction();
    t.version = 1;
    const prevHash = hexToBytes(
      "c672c1c5d15e58b9a5f1b6e2d3f4e5c6b7a8091011121314151617181920212a",
    ).reverse();
    t.addInput(
      { hash: prevHash, index: 1, tree: TxTree.Regular },
      { sequence: MAX_SEQUENCE, valueIn: 1000000000n, blockHeight: 7, blockIndex: 8 },
    );
    for (let i = 0; i < g.numOutputs; i++) t.addOutput(BigInt(1000 + i), outScript, i % 3);

    expect(t.outputs.length).toBe(300);
    expect(bytesToHex(t.serialize()), "full").toBe(g.serialized);
    expect(bytesToHex(t.serializePrefix()), "prefix").toBe(g.prefixSer);
    expect(t.txid(), "txid").toBe(g.txid);
    expect(t.witnessTxid(), "witness txid").toBe(g.txidWitness);
    expect(t.fullTxid(), "full txid").toBe(g.txidFull);
    // Round-trips, so the multi-byte varint is read back the same way.
    expect(bytesToHex(Transaction.fromBytes(hexToBytes(g.serialized)).serialize())).toBe(
      g.serialized,
    );
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

// A 3-in/3-out transaction, so SigHashSingle can be taken at the LAST output
// index — tx2 has only 2 inputs and cannot reach idx 2 of 3 outputs.
function buildFixtureTx3(): { tx: Transaction; subScript: Uint8Array } {
  const outScript = payToPubKeyHashScript(hexToBytes(vectors.keys.pubkeyHash160));
  const tx = new Transaction();
  tx.version = 1;
  for (let i = 0; i < 3; i++) {
    const display = (0xa0 + i).toString(16).padStart(64, "0");
    tx.addInput(
      { hash: hexToBytes(display).reverse(), index: i, tree: TxTree.Regular },
      {
        sequence: 0xfffffff0 + i,
        valueIn: BigInt(100000000 * (i + 1)),
        blockHeight: 300 + i,
        blockIndex: i,
      },
    );
    tx.addOutput(BigInt(10000000 * (i + 1)), outScript, 0);
  }
  tx.lockTime = 12345;
  tx.expiry = 23456;
  return { tx, subScript: outScript };
}

describe("signature hash edge cases", () => {
  test("every hash type at every input index matches dcrd, including undefined ones", () => {
    // Covers SigHashSingle at the last output index (idx 2 of 3), and the hash
    // types dcrd's calcSignatureHash still defines even though its script engine
    // rejects them at verification: 0x00, 0x04, 0x05, 0x1f, 0x84, 0xff.
    const { tx, subScript } = buildFixtureTx3();
    expect(bytesToHex(tx.serialize())).toBe(vectors.tx3.serialized);
    expect(tx.txid()).toBe(vectors.tx3.txid);
    expect(bytesToHex(subScript)).toBe(vectors.tx3.subScript);

    const byType = Object.entries(vectors.tx3.sighashes);
    expect(byType.length).toBe(12);
    for (const [htHex, perInput] of byType) {
      const ht = Number.parseInt(htHex, 16);
      for (const [inKey, expected] of Object.entries(perInput)) {
        const idx = Number.parseInt(inKey.slice(2), 10);
        expect(bytesToHex(calcSignatureHash(subScript, ht, tx, idx)), `${htHex} ${inKey}`).toBe(
          expected,
        );
      }
    }
  });

  test("SigHashSingle past the last output is refused", () => {
    const { tx, subScript } = buildFixtureTx3();
    // idx 2 is the last valid output, so it must work...
    expect(() => calcSignatureHash(subScript, SigHashType.Single, tx, 2)).not.toThrow();
    // ...and a 4th input with only 3 outputs must not.
    tx.addInput({ hash: new Uint8Array(32).fill(9), index: 0, tree: TxTree.Regular });
    expect(() => calcSignatureHash(subScript, SigHashType.Single, tx, 3)).toThrow(
      /no corresponding output/,
    );
  });

  test("an existing signature script on another input does not leak into the sighash", () => {
    // The witness hash commits to the subScript for the signed input and nil for
    // the rest, so signing input 1 after input 0 already carries a signature must
    // produce the same hash as signing it first. Nothing proved this before.
    const { tx, subScript } = buildFixtureTx3();
    const before = bytesToHex(calcSignatureHash(subScript, SigHashType.All, tx, 1));
    tx.inputs[0]!.signatureScript = hexToBytes("deadbeef".repeat(20));
    expect(bytesToHex(calcSignatureHash(subScript, SigHashType.All, tx, 1))).toBe(before);
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
