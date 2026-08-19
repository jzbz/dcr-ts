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
import { calcSignatureHash, sigHashPrefixAll, SigHashType } from "../src/sighash.js";
import {
  rawTxInSignature,
  signatureScript,
  signP2PKHInput,
  signP2PKHInputs,
  verifyHash,
} from "../src/sign.js";
import { payToPubKeyHashScript } from "../src/script.js";
import { publicKeyFromPrivate } from "../src/keys.js";
import { bytesToHex, hexToBytes, vectors, errorCode } from "./helpers.js";

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
    expect(errorCode(() => new Reader(hexToBytes("fd0100")).varInt())).toBe("non-canonical-varint");
    expect(new Reader(hexToBytes("fe00000100")).varInt()).toBe(0x10000);
    expect(errorCode(() => new Reader(hexToBytes("feffff0000")).varInt())).toBe("non-canonical-varint");
    expect(new Reader(hexToBytes("ff0000000001000000")).varInt()).toBe(0x100000000);
    expect(errorCode(() => new Reader(hexToBytes("ffffffffff00000000")).varInt())).toBe("non-canonical-varint");

    // A transaction whose input count is re-encoded non-canonically must not
    // parse: it would hash to a different txid than its own bytes.
    const canonical = vectors.tx.serialized;
    const mutated = canonical.slice(0, 8) + "fd0100" + canonical.slice(10);
    expect(errorCode(() => Transaction.fromBytes(hexToBytes(mutated)))).toBe("non-canonical-varint");
  });

  test("outPointFromTxid validates its input", () => {
    expect(errorCode(() => outPointFromTxid("zz".repeat(32), 0))).toBe("invalid-argument");
    expect(errorCode(() => outPointFromTxid("ab", 0))).toBe("invalid-argument");
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

describe("cached prefix hash (the O(N^2) -> O(N) signing path)", () => {
  // One output per input, so SigHashSingle is valid at every index.
  function nInOut(n: number): Transaction {
    const outScript = payToPubKeyHashScript(hexToBytes(vectors.keys.pubkeyHash160));
    const tx = new Transaction();
    tx.version = 1;
    for (let i = 0; i < n; i++) {
      tx.addInput(
        { hash: new Uint8Array(32).fill(i & 0xff), index: i, tree: TxTree.Regular },
        { valueIn: BigInt(1000 + i), blockHeight: i, blockIndex: i },
      );
      tx.addOutput(BigInt(500 + i), outScript, 0);
    }
    tx.lockTime = 11;
    tx.expiry = 22;
    return tx;
  }
  const outScript = payToPubKeyHashScript(hexToBytes(vectors.keys.pubkeyHash160));

  test("sigHashPrefixAll is exactly the transaction prefix hash", () => {
    // SigHashSerializePrefix and TxSerializeNoWitness are both 1 and the bodies
    // are identical, which is the whole reason the prefix half is reusable.
    const tx = nInOut(4);
    expect(bytesToHex(sigHashPrefixAll(tx))).toBe(bytesToHex(tx.hash()));
  });

  test("a cached prefix gives byte-identical hashes for every type and index", () => {
    const tx = nInOut(5);
    const cached = sigHashPrefixAll(tx);
    for (const ht of [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]) {
      for (let i = 0; i < 5; i++) {
        expect(
          bytesToHex(calcSignatureHash(outScript, ht, tx, i, cached)),
          `0x${ht.toString(16)} in${i}`,
        ).toBe(bytesToHex(calcSignatureHash(outScript, ht, tx, i)));
      }
    }
  });

  test("the cache is ignored, not trusted, wherever it does not apply", () => {
    // Only SigHashAll without AnyOneCanPay has an input-independent prefix. For
    // everything else a wrong cache must have no effect at all.
    const tx = nInOut(3);
    const bogus = new Uint8Array(32).fill(0xee);
    for (const ht of [0x02, 0x03, 0x81, 0x82, 0x83]) {
      expect(
        bytesToHex(calcSignatureHash(outScript, ht, tx, 0, bogus)),
        `0x${ht.toString(16)}`,
      ).toBe(bytesToHex(calcSignatureHash(outScript, ht, tx, 0)));
    }
    // ...and for SigHashAll it *is* used, so a wrong one changes the result.
    expect(bytesToHex(calcSignatureHash(outScript, 0x01, tx, 0, bogus))).not.toBe(
      bytesToHex(calcSignatureHash(outScript, 0x01, tx, 0)),
    );
    expect(() => calcSignatureHash(outScript, 0x01, tx, 0, new Uint8Array(31))).toThrow(
      /must be 32 bytes/,
    );
  });

  test("signP2PKHInputs is byte-identical to signing one at a time", () => {
    const priv = hexToBytes(vectors.keys.privHex);
    for (const n of [1, 2, 8]) {
      const oneByOne = nInOut(n);
      const batched = nInOut(n);
      for (let i = 0; i < n; i++) signP2PKHInput(oneByOne, i, outScript, priv);
      signP2PKHInputs(
        batched,
        Array.from({ length: n }, (_, i) => ({ idx: i, subScript: outScript, privateKey: priv })),
      );
      expect(bytesToHex(batched.serialize()), `n=${n}`).toBe(bytesToHex(oneByOne.serialize()));
      expect(batched.fullTxid(), `n=${n} fullTxid`).toBe(oneByOne.fullTxid());
    }
  });

  test("signP2PKHInputs still rejects a hash type dcrd would not accept", () => {
    const priv = hexToBytes(vectors.keys.privHex);
    expect(
      errorCode(() =>
        signP2PKHInputs(nInOut(2), [{ idx: 0, subScript: outScript, privateKey: priv }], 0x04),
      ),
    ).toBe("invalid-hash-type");
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

describe("transaction version range", () => {
  // The version word packs the serialization type in its high 16 bits, so an
  // out-of-range version used to be masked into it: 65537 serialized as version
  // 1, NaN as 0, and the txid and every signature committed to a version the
  // caller never asked for. TxOutput.version, the other 16-bit field in this
  // serializer, has always thrown on the same inputs via Writer.u16.
  const badRange = [65536, 65537, -1, 0x10000000];
  const badKind = [NaN, 1.5, Infinity];

  test("serialization rejects a version outside 0..0xffff", () => {
    for (const v of badRange) {
      const { tx } = buildFixtureTx();
      tx.version = v;
      expect(errorCode(() => tx.serialize()), `serialize ${v}`).toBe("out-of-range");
      expect(errorCode(() => tx.serializePrefix()), `prefix ${v}`).toBe("out-of-range");
      expect(errorCode(() => tx.serializeWitness()), `witness ${v}`).toBe("out-of-range");
      expect(errorCode(() => tx.txid()), `txid ${v}`).toBe("out-of-range");
      expect(errorCode(() => tx.fullTxid()), `fullTxid ${v}`).toBe("out-of-range");
    }
    for (const v of badKind) {
      const { tx } = buildFixtureTx();
      tx.version = v;
      expect(errorCode(() => tx.serialize()), `serialize ${v}`).toBe("not-an-integer");
    }
  });

  test("the signature hash rejects it too, cached prefix or not", () => {
    for (const v of badRange) {
      const { tx, subScript } = buildFixtureTx();
      tx.version = v;
      expect(errorCode(() => calcSignatureHash(subScript, SigHashType.All, tx, 0))).toBe(
        "out-of-range",
      );
      // The prefix word is skipped when a cached prefix is supplied; the witness
      // word is not, so the check cannot be bypassed that way.
      expect(
        errorCode(() =>
          calcSignatureHash(subScript, SigHashType.All, tx, 0, new Uint8Array(32)),
        ),
      ).toBe("out-of-range");
    }
    for (const v of badKind) {
      const { tx, subScript } = buildFixtureTx();
      tx.version = v;
      expect(errorCode(() => calcSignatureHash(subScript, SigHashType.All, tx, 0))).toBe(
        "not-an-integer",
      );
    }
  });

  test("every in-range version still serializes to the same word as before", () => {
    // Not a regression detector — it passes either way. It pins the property that
    // actually matters: the guard moves no wire bytes for any legal version.
    for (const v of [0, 1, 2, 0x1234, 0xfffe, 0xffff]) {
      const { tx } = buildFixtureTx();
      tx.version = v;
      const wordOf = (b: Uint8Array): number =>
        new DataView(b.buffer, b.byteOffset).getUint32(0, true);
      expect(wordOf(tx.serialize()), `full v=${v}`).toBe(((0 << 16) | (v & 0xffff)) >>> 0);
      expect(wordOf(tx.serializePrefix()), `prefix v=${v}`).toBe(((1 << 16) | (v & 0xffff)) >>> 0);
      expect(wordOf(tx.serializeWitness()), `witness v=${v}`).toBe(((2 << 16) | (v & 0xffff)) >>> 0);
    }
  });
});
