import { describe, expect, test } from "vitest";
import { ExtendedKey } from "../src/hd.js";
import { networks } from "../src/networks.js";
import { Reader } from "../src/bytes.js";
import { payToPubKeyHashScript } from "../src/script.js";
import { outPointFromTxid, Transaction } from "../src/tx.js";
import { bytesToHex, hexToBytes, vectors, errorCode } from "./helpers.js";

/**
 * Node's `Buffer` is a `Uint8Array` subclass that overrides `slice()` to return a
 * *view* rather than a copy (deprecated, still the behaviour). Since `Buffer` is
 * what `fs.readFileSync`, `Buffer.from(hex, "hex")`, sockets and database drivers
 * all produce, a library that reaches for `.slice()` to defensively copy silently
 * aliases the caller's memory for its most common input type.
 *
 * Every test here passes a `Buffer`, then scribbles over it, and asserts the
 * parsed value did not move. With plain `Uint8Array` inputs they all pass either
 * way, which is exactly why this needs its own file.
 */
describe("parsed values never alias a caller's Buffer", () => {
  test("Buffer.prototype.slice really is a view (the premise)", () => {
    const b = Buffer.from("00112233", "hex");
    const viaSlice = b.slice(0, 2);
    viaSlice[0] = 0xff;
    expect(b[0], "Buffer slice aliases").toBe(0xff);

    const u = Uint8Array.from([0x00, 0x11, 0x22, 0x33]);
    const uSlice = u.slice(0, 2);
    uSlice[0] = 0xff;
    expect(u[0], "Uint8Array slice copies").toBe(0x00);
  });

  test("Reader.bytes copies", () => {
    const src = Buffer.from("deadbeefcafe", "hex");
    const got = new Reader(src).bytes(3);
    src.fill(0);
    expect(bytesToHex(got)).toBe("deadbe");
  });

  test("Transaction.fromBytes copies", () => {
    const src = Buffer.from(vectors.tx.serialized, "hex");
    const tx = Transaction.fromBytes(src);
    const txid = tx.txid();
    const script = bytesToHex(tx.outputs[0]!.pkScript);
    const prevHash = bytesToHex(tx.inputs[0]!.previousOutPoint.hash);
    src.fill(0);
    expect(tx.txid(), "txid").toBe(txid);
    expect(txid).toBe(vectors.tx.txid);
    expect(bytesToHex(tx.outputs[0]!.pkScript), "pkScript").toBe(script);
    expect(bytesToHex(tx.inputs[0]!.previousOutPoint.hash), "prevout hash").toBe(prevHash);
    // And it still re-serializes to the original bytes.
    expect(bytesToHex(tx.serialize())).toBe(vectors.tx.serialized);
  });

  test("ExtendedKey.fromSerialized copies", () => {
    // The worst case: a caller doing the right thing and wiping the
    // serialization after parsing would otherwise destroy the key it parsed.
    const key = ExtendedKey.fromSeed(new Uint8Array(32).fill(5), networks.mainnet);
    const src = Buffer.from(key.serialize());
    const parsed = ExtendedKey.fromSerialized(src);
    const str = parsed.toString();
    const priv = bytesToHex(parsed.privateKeyBytes());
    const child = parsed.derive(0).toString();
    src.fill(0);
    expect(parsed.toString(), "extended key string").toBe(str);
    expect(bytesToHex(parsed.privateKeyBytes()), "private scalar").toBe(priv);
    expect(parsed.derive(0).toString(), "derived child").toBe(child);
    expect(priv).toBe(bytesToHex(key.privateKeyBytes()));
  });

  test("addInput and addOutput copy the caller's buffers", () => {
    // Mutating a script buffer after adding it would rewrite the transaction's
    // bytes and txid, silently invalidating any signature already made over it.
    const hash = Buffer.alloc(32, 0x11);
    const script = Buffer.from(payToPubKeyHashScript(hexToBytes(vectors.keys.pubkeyHash160)));
    const sigScript = Buffer.from("abcdef", "hex");
    const tx = new Transaction();
    tx.addInput({ hash, index: 0, tree: 0 }, { valueIn: 1n, signatureScript: sigScript });
    tx.addOutput(1n, script);
    const before = tx.txid();
    const fullBefore = tx.fullTxid();

    hash.fill(0x99);
    script.fill(0x99);
    sigScript.fill(0x99);

    expect(tx.txid(), "txid unchanged").toBe(before);
    expect(tx.fullTxid(), "full txid unchanged").toBe(fullBefore);
  });

  test("a wrong-length outpoint hash is rejected up front", () => {
    // Previously accepted, then silently hashed into the sighash at the wrong
    // width by calcSignatureHash.
    const tx = new Transaction();
    for (const n of [0, 31, 33]) {
      expect(errorCode(() => tx.addInput({ hash: new Uint8Array(n), index: 0, tree: 0 })), `${n}`)
        .toBe("bad-length");
    }
    expect(() => tx.addInput(outPointFromTxid("11".repeat(32), 0))).not.toThrow();
  });

  test("ExtendedKey hands out no view into its own state", () => {
    // Memoizing identifier() turned a per-call throwaway digest into long-lived
    // shared state, and deriveInner passes fingerprint() straight into each child
    // as parentFingerprint — so a view would let one caller's write corrupt the
    // cache, this key's own fingerprint, every sibling and every later child.
    const parent = ExtendedKey.fromSeed(new Uint8Array(32).fill(4), networks.mainnet);
    const childA = parent.derive(0);
    const childB = parent.derive(1);
    const fp = bytesToHex(parent.fingerprint());
    const id = bytesToHex(parent.identifier());
    const bFp = bytesToHex(childB.parentFingerprint);

    // Scribble on every array the key hands out.
    childA.parentFingerprint[0] = 0xff;
    parent.fingerprint()[1] = 0xff;
    parent.identifier()[2] = 0xff;
    parent.publicKey()[3] = 0xff;
    parent.privateKeyBytes()[4] = 0xff;
    parent.chainCode[5] = 0xff;
    parent.serialize()[13] = 0xff;

    expect(bytesToHex(parent.fingerprint()), "fingerprint").toBe(fp);
    expect(bytesToHex(parent.identifier()), "identifier").toBe(id);
    expect(bytesToHex(childB.parentFingerprint), "sibling parentFingerprint").toBe(bFp);
    expect(bytesToHex(parent.derive(2).parentFingerprint), "later child").toBe(fp);
  });

  test("mutating chainCode cannot change what a key derives", () => {
    const key = ExtendedKey.fromSeed(new Uint8Array(32).fill(5), networks.mainnet);
    const before = key.derive(0).toString();
    const cc = key.chainCode;
    cc[0] = cc[0]! ^ 0xff;
    key.chainCode.fill(0);
    expect(key.derive(0).toString()).toBe(before);
  });

  test("Reader.bytes rejects a negative or fractional length", () => {
    // A negative length slipped past the upper-bound check, read nothing, and
    // rewound the offset.
    for (const n of [-1, -32, 1.5, NaN]) {
      const r = new Reader(Buffer.from("deadbeef", "hex"));
      expect(errorCode(() => r.bytes(n)), `${n}`).toBe(
        Number.isInteger(n) ? "out-of-range" : "not-an-integer",
      );
      expect(r.offset, "offset untouched").toBe(0);
    }
  });
});
