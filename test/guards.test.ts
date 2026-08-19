import { describe, expect, test } from "vitest";
import { ExtendedKey, MAX_EXTENDED_KEY_LENGTH } from "../src/hd.js";
import { MAX_ADDRESS_LENGTH, decodeAddress, isValidAddress } from "../src/address.js";
import { MAX_WIF_LENGTH, decodeWif } from "../src/wif.js";
import { maxBase58Length } from "../src/base58.js";
import {
  entropyToMnemonic,
  generateMnemonic,
  mnemonicToEntropy,
  mnemonicToMasterKey,
  mnemonicToSeed,
  validateMnemonic,
} from "../src/bip39.js";
import { wordlist as spanish } from "@scure/bip39/wordlists/spanish";
import { networks } from "../src/networks.js";
import { addressToScript, pubKeyHashAddress } from "../src/address.js";
import { DcrError, hasErrorCode, isDcrError } from "../src/errors.js";
import {
  assertSignableSigHashType,
  calcSignatureHash,
  isSignableSigHashType,
  SigHashType,
} from "../src/sighash.js";
import {
  rawTxInSignature,
  signatureScript,
  signHash,
  signP2PKHInput,
  signP2PKHInputs,
  verifyHash,
} from "../src/sign.js";
import { payToPubKeyHashScript, scriptParses } from "../src/script.js";
import { CURVE_ORDER, publicKeyFromPrivate, scalarToBytes } from "../src/keys.js";
import { Transaction, TxTree } from "../src/tx.js";
import { Writer } from "../src/bytes.js";
import { hexToBytes, vectors, errorCode } from "./helpers.js";

const priv = hexToBytes(vectors.keys.privHex);
const pkh = hexToBytes(vectors.keys.pubkeyHash160);
const subScript = payToPubKeyHashScript(pkh);

function oneInputTx(): Transaction {
  const tx = new Transaction();
  tx.version = 1;
  tx.addInput(
    { hash: new Uint8Array(32).fill(0xaa), index: 0, tree: TxTree.Regular },
    { valueIn: 100000000n, blockHeight: 1, blockIndex: 0 },
  );
  tx.addOutput(99000000n, subScript);
  return tx;
}

describe("signature hash guards", () => {
  // Ground truth from dcrd: each script was passed to txscript.CalcSignatureHash,
  // whose only structural gate is checkScriptParses, and the presence of an error
  // recorded. All 32 agree with scriptParses.
  const DCRD_PARSE_ORACLE: ReadonlyArray<readonly [string, boolean]> = [
    ["", true],
    ["51", true], // OP_1
    ["00", true], // OP_0
    ["4f", true], // OP_1NEGATE
    ["ac", true], // OP_CHECKSIG
    ["76a914aabbccddeeff00112233445566778899aabbccdd88ac", true], // real P2PKH
    ["76a914aabb", false], // OP_DATA_20 truncated
    ["21", false], // OP_DATA_33 with no data
    ["4c", false], // PUSHDATA1 with no length byte
    ["4c05aabb", false], // PUSHDATA1 claims 5, has 2
    ["4c00", true], // PUSHDATA1 of zero bytes
    ["4c01aa", true],
    ["4c02aa", false],
    ["4d", false], // PUSHDATA2 with no length
    ["4d01", false], // PUSHDATA2 with a 1-byte length
    ["4d0100aa", true], // PUSHDATA2 claims 1, has 1
    ["4d0500aa", false],
    ["4d0000", true],
    ["4e", false], // PUSHDATA4 with no length
    ["4e01000000aa", true],
    // dcrd reads the 4-byte length as a signed int32, so a high bit makes it
    // negative and it is rejected rather than treated as enormous. Its error
    // literally reads "pushes -1 bytes".
    ["4effffffff", false],
    ["4e00000080aa", false], // -2147483648
    ["4effffff7f", false], // 2147483647, larger than the script
    ["4b", false], // OP_DATA_75 with no data
    ["01", false], // OP_DATA_1 with no data
    ["0101", true],
    ["4baabbcc", false],
    ["ff", true], // unknown opcode: tokenizes fine, would fail at execution
    ["baad", true],
    ["6a", true], // bare OP_RETURN
    ["6a04deadbeef", true],
    ["6a05deadbeef", false],
  ];

  test("scriptParses agrees with dcrd on every oracle case", () => {
    for (const [hex, parses] of DCRD_PARSE_ORACLE) {
      expect(scriptParses(hexToBytes(hex)), `"${hex}"`).toBe(parses);
    }
    expect(scriptParses(subScript), "the library's own P2PKH script").toBe(true);
  });

  test("calcSignatureHash rejects a subScript that does not parse", () => {
    // dcrd's exported CalcSignatureHash gates on checkScriptParses first, so
    // hashing one of these would produce a signature over a message dcrd would
    // never compute — an unspendable input.
    for (const bad of ["76a914aabb", "4c", "21", "4effffffff"]) {
      expect(errorCode(() => calcSignatureHash(hexToBytes(bad), SigHashType.All, oneInputTx(), 0)),
        bad,
      ).toBe("malformed-script");
    }
  });

  test("calcSignatureHash rejects a hash type wider than a byte", () => {
    // The preimage commits to hashType as a uint32 but a signature script carries
    // only its low byte, so 0x101 would be committed in full and transmitted as
    // 0x01: the verifier recomputes a different hash and the signature can never
    // verify. dcrd's SigHashType is a byte, so this is unrepresentable there.
    for (const bad of [0x100, 0x101, 0x10001, -1, 1.5, NaN, Infinity]) {
      expect(errorCode(() => calcSignatureHash(subScript, bad, oneInputTx(), 0)), `${bad}`).toBe(
        "invalid-hash-type",
      );
    }
    // Undefined-but-byte-sized types still hash, matching dcrd, and are pinned
    // by the tx3 vectors.
    for (const ok of [0x00, 0x04, 0x1f, 0x84, 0xff]) {
      expect(calcSignatureHash(subScript, ok, oneInputTx(), 0).length).toBe(32);
    }
  });

  test("calcSignatureHash rejects a non-integer input index", () => {
    // NaN slipped past both range checks, since every relational test against NaN
    // is false, leaving a hash that committed the subScript to no input at all.
    for (const bad of [NaN, 1.5, Infinity, -Infinity]) {
      expect(
        errorCode(() => calcSignatureHash(subScript, SigHashType.All, oneInputTx(), bad)),
        `${bad}`,
      ).toBe("not-an-integer");
    }
    for (const bad of [-1, 1, 99]) {
      expect(
        errorCode(() => calcSignatureHash(subScript, SigHashType.All, oneInputTx(), bad)),
        `${bad}`,
      ).toBe("out-of-range");
    }
  });

  test("only the six hash types dcrd accepts can produce a signature", () => {
    // dcrd's CheckHashTypeEncoding: hashType & ~AnyOneCanPay must be All..Single.
    const good = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83];
    for (const ht of good) expect(isSignableSigHashType(ht), `0x${ht.toString(16)}`).toBe(true);
    for (const ht of [0x00, 0x04, 0x05, 0x1f, 0x80, 0x84, 0xff, 0x100, -1, 1.5, NaN]) {
      expect(isSignableSigHashType(ht), `0x${Number(ht).toString(16)}`).toBe(false);
      expect(errorCode(() => assertSignableSigHashType(ht))).toBe("invalid-hash-type");
    }
    // AnyOneCanPay alone is exported but invalid on its own.
    expect(isSignableSigHashType(SigHashType.AnyOneCanPay)).toBe(false);

    for (const ht of good) {
      expect(() => rawTxInSignature(oneInputTx(), 0, subScript, ht, priv), `sign 0x${ht.toString(16)}`)
        .not.toThrow();
    }
    for (const ht of [0x00, 0x04, 0x80, 0xff]) {
      expect(
        errorCode(() => rawTxInSignature(oneInputTx(), 0, subScript, ht, priv)),
        `sign 0x${ht.toString(16)}`,
      ).toBe("invalid-hash-type");
      expect(errorCode(() => signP2PKHInput(oneInputTx(), 0, subScript, priv, ht))).toBe(
        "invalid-hash-type",
      );
    }
  });
});

describe("verifyHash is strictly DER and low-S", () => {
  const hash = new Uint8Array(32).fill(9);
  const der = signHash(hash, priv);
  const pub = publicKeyFromPrivate(priv);

  test("accepts the canonical DER signature it produced", () => {
    expect(verifyHash(hash, der, pub)).toBe(true);
  });

  test("rejects the 64-byte compact encoding", () => {
    // @noble's verify() falls back from DER to compact r||s, but dcrd's engine
    // requires DER — so accepting compact would pass locally and fail consensus.
    const rLen = der[3]!;
    const r = der.subarray(4, 4 + rLen);
    const sLen = der[5 + rLen]!;
    const s = der.subarray(6 + rLen, 6 + rLen + sLen);
    const compact = new Uint8Array(64);
    compact.set(r.subarray(Math.max(0, r.length - 32)), 32 - Math.min(32, r.length));
    compact.set(s.subarray(Math.max(0, s.length - 32)), 64 - Math.min(32, s.length));
    expect(compact.length).toBe(64);
    expect(verifyHash(hash, compact, pub)).toBe(false);
  });

  test("rejects non-canonical DER, a tampered signature and a wrong key", () => {
    // Trailing garbage after a valid DER body.
    const padded = new Uint8Array(der.length + 1);
    padded.set(der);
    expect(verifyHash(hash, padded, pub)).toBe(false);
    // Overlong length prefix.
    const bumped = Uint8Array.from(der);
    bumped[1] = (bumped[1]! + 1) & 0xff;
    expect(verifyHash(hash, bumped, pub)).toBe(false);
    // Flipped byte inside r.
    const tampered = Uint8Array.from(der);
    tampered[6] = tampered[6]! ^ 0xff;
    expect(verifyHash(hash, tampered, pub)).toBe(false);
    // Right signature, wrong key and wrong message.
    expect(verifyHash(hash, der, publicKeyFromPrivate(new Uint8Array(32).fill(7)))).toBe(false);
    expect(verifyHash(new Uint8Array(32).fill(8), der, pub)).toBe(false);
    // Garbage.
    expect(verifyHash(hash, new Uint8Array(0), pub)).toBe(false);
    expect(verifyHash(hash, hexToBytes("deadbeef"), pub)).toBe(false);
  });
});

describe("base58 decoders bound their input", () => {
  // base58 decoding is quadratic, so an unbounded string is a cheap way to stall
  // the event loop. dcrd caps every decoder the same way.
  test("the caps match the ceil(len * log_58(256)) bound dcrd uses", () => {
    expect(maxBase58Length(39)).toBe(MAX_WIF_LENGTH);
    expect(MAX_ADDRESS_LENGTH).toBe(54); // dcrd's maxV0AddrLen
    expect(MAX_EXTENDED_KEY_LENGTH).toBe(maxBase58Length(82));
  });

  test("an over-long string is refused before decoding, and fast", () => {
    const huge = "z".repeat(200_000);
    for (const [what, fn] of [
      ["decodeAddress", () => decodeAddress(huge)],
      ["decodeWif", () => decodeWif(huge)],
      ["ExtendedKey.fromString", () => ExtendedKey.fromString(huge)],
    ] as const) {
      const started = process.hrtime.bigint();
      expect(errorCode(fn), what).toBe("input-too-long");
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      // Before the cap this took ~6 s for a 128 KB string and grew quadratically.
      expect(ms, `${what} took ${ms.toFixed(1)}ms`).toBeLessThan(50);
    }
    expect(isValidAddress(huge)).toBe(false);
  });

  test("real values are comfortably inside the caps", () => {
    const a = vectors.keys.addresses.mainnet!;
    expect(a.p2pkh.length).toBeLessThanOrEqual(MAX_ADDRESS_LENGTH);
    expect(a.pubkeyAddr.length).toBeLessThanOrEqual(MAX_ADDRESS_LENGTH);
    expect(vectors.keys.wif.mainnet!.wif.length).toBeLessThanOrEqual(MAX_WIF_LENGTH);
    expect(vectors.hd.nets.mainnet!.masterPriv.length).toBeLessThanOrEqual(
      MAX_EXTENDED_KEY_LENGTH,
    );
    // And they all still decode.
    expect(decodeAddress(a.pubkeyAddr).kind).toBe("pubkey-ecdsa");
    expect(decodeWif(vectors.keys.wif.mainnet!.wif).signatureType).toBe(0);
    expect(ExtendedKey.fromString(vectors.hd.nets.mainnet!.masterPriv).isPrivate).toBe(true);
  });
});

describe("mnemonicToMasterKey validates the phrase", () => {
  const good = "legal winner thank year wave sausage worth useful legal winner thank yellow";

  test("accepts a valid mnemonic", () => {
    expect(mnemonicToMasterKey(good, networks.mainnet).isPrivate).toBe(true);
  });

  test("accepts a non-English mnemonic against its own wordlist", () => {
    // validateMnemonic only knows the list it is given, so gating on the English
    // one would reject a perfectly valid Spanish or Japanese phrase. The seed
    // itself does not depend on the wordlist at all.
    const es = generateMnemonic(128, spanish);
    expect(errorCode(() => mnemonicToMasterKey(es, networks.mainnet))).toBe("invalid-mnemonic");
    const key = mnemonicToMasterKey(es, networks.mainnet, "", spanish);
    expect(key.isPrivate).toBe(true);
    // Same key as the unchecked primitive: validation gates, it does not alter.
    expect(key.toString()).toBe(
      ExtendedKey.fromSeed(mnemonicToSeed(es), networks.mainnet).toString(),
    );
    expect(validateMnemonic(es, spanish)).toBe(true);
    expect(validateMnemonic(es)).toBe(false);
  });

  test("rejects a bad checksum or an unknown word", () => {
    // BIP39 seed derivation is defined for any string, so without this a typo'd
    // phrase expands into a different valid-looking wallet and every operation
    // appears to succeed.
    const badChecksum = good.replace(/yellow$/, "zoo");
    const notAWord = good.replace(/^legal/, "zzzzzz");
    for (const bad of [badChecksum, notAWord, "", "legal winner"]) {
      expect(errorCode(() => mnemonicToMasterKey(bad, networks.mainnet)), JSON.stringify(bad))
        .toBe("invalid-mnemonic");
    }
    // The unchecked primitive is still available for callers who want it.
    expect(mnemonicToSeed(badChecksum).length).toBe(64);
  });
});

describe("every private-key entry point rejects an unusable key", () => {
  // `@noble` checks the same two conditions, but throws its own plain Error — so
  // without the guard a zeroed or wrong-length key buffer escapes the contract
  // and `hasErrorCode` cannot classify the one key mistake worth classifying.
  // dcrd is no help here: `PrivKeyFromBytes` cannot fail, so signing with a zero
  // key there yields a real DER signature under an all-zero-X public key, and a
  // short key is silently left-padded. Rejecting is deliberate.
  const unusable: Array<[string, Uint8Array, string]> = [
    ["zero", new Uint8Array(32), "invalid-private-key"],
    ["n", scalarToBytes(CURVE_ORDER), "invalid-private-key"],
    ["all-ff", new Uint8Array(32).fill(0xff), "invalid-private-key"],
    ["31 bytes", new Uint8Array(31).fill(7), "bad-length"],
    ["33 bytes", new Uint8Array(33).fill(7), "bad-length"],
  ];

  test("through all six of them", () => {
    for (const [name, key, code] of unusable) {
      const calls: Array<[string, () => unknown]> = [
        ["signHash", () => signHash(new Uint8Array(32).fill(9), key)],
        ["publicKeyFromPrivate", () => publicKeyFromPrivate(key)],
        [
          "rawTxInSignature",
          () => rawTxInSignature(oneInputTx(), 0, subScript, SigHashType.All, key),
        ],
        [
          "signatureScript",
          () => signatureScript(oneInputTx(), 0, subScript, SigHashType.All, key),
        ],
        ["signP2PKHInput", () => signP2PKHInput(oneInputTx(), 0, subScript, key)],
        [
          "signP2PKHInputs",
          () => signP2PKHInputs(oneInputTx(), [{ idx: 0, subScript, privateKey: key }]),
        ],
      ];
      for (const [who, fn] of calls) expect(errorCode(fn), `${who}(${name})`).toBe(code);
    }
  });

  test("and 1 and n - 1 still sign, so the bound is not off by one", () => {
    const h = new Uint8Array(32).fill(9);
    for (const key of [scalarToBytes(1n), scalarToBytes(CURVE_ORDER - 1n)]) {
      expect(verifyHash(h, signHash(h, key), publicKeyFromPrivate(key))).toBe(true);
    }
    // Non-vacuous the other way: the full script path still runs end to end.
    const script = signatureScript(oneInputTx(), 0, subScript, SigHashType.All, priv);
    expect(script.length).toBeGreaterThan(70);
    expect(scriptParses(script)).toBe(true);
  });
});

describe("the mnemonic wrappers keep their own errors", () => {
  // @scure throws plain Error/TypeError with messages that vary by case — an
  // unknown word inlines the entire 2048-word list — so these are wrapped rather
  // than matched on.
  const phrase = generateMnemonic(128);

  test("strength, entropy size and wordlist size are rejected with their own codes", () => {
    for (const s of [0, 64, 127, 129, 288]) {
      expect(errorCode(() => generateMnemonic(s)), `strength ${s}`).toBe("out-of-range");
    }
    for (const s of [NaN, 128.5, Infinity]) {
      expect(errorCode(() => generateMnemonic(s)), `strength ${s}`).toBe("not-an-integer");
    }
    for (const n of [15, 17, 18, 33, 0]) {
      expect(errorCode(() => entropyToMnemonic(new Uint8Array(n))), `entropy ${n}`).toBe(
        "bad-length",
      );
    }
    // `Wordlist` is readonly string[], so a short list type-checks fine.
    const short = ["abandon", "ability"];
    expect(errorCode(() => generateMnemonic(128, short))).toBe("invalid-argument");
    expect(errorCode(() => entropyToMnemonic(new Uint8Array(16), short))).toBe("invalid-argument");
    expect(errorCode(() => mnemonicToEntropy(phrase, short))).toBe("invalid-argument");
    expect(errorCode(() => mnemonicToMasterKey(phrase, networks.mainnet, "", short))).toBe(
      "invalid-argument",
    );
  });

  test("a bad phrase is invalid-mnemonic, whichever way it is bad", () => {
    const wrongCount = "abandon abandon abandon";
    const unknownWord = phrase.replace(/^\S+/, "zzzzzz");
    for (const bad of [wrongCount, unknownWord, ""]) {
      expect(errorCode(() => mnemonicToEntropy(bad)), JSON.stringify(bad)).toBe("invalid-mnemonic");
    }
    // The word count is enforced by @scure even on the unchecked primitive, so
    // this one is a DcrError too rather than a bare Error.
    expect(errorCode(() => mnemonicToSeed(wrongCount))).toBe("invalid-mnemonic");
    // Round-trip still works, so the wrappers are not swallowing valid input.
    expect(entropyToMnemonic(mnemonicToEntropy(phrase))).toBe(phrase);
  });
});

describe("typed errors", () => {
  // The motivating case: a wallet UI needs different copy for a mistyped address
  // than for a right-address-wrong-network paste. Message matching could not tell
  // them apart, and matching on prose is not an API in the first place.
  test("distinguish the failures a caller must react to differently", () => {
    const hash = hexToBytes(vectors.keys.pubkeyHash160);
    const onTestnet = pubKeyHashAddress(hash, networks.testnet3);
    const mainnetAddr = pubKeyHashAddress(hash, networks.mainnet);
    const typo = mainnetAddr.slice(0, -1) + (mainnetAddr.endsWith("X") ? "Y" : "X");

    expect(errorCode(() => addressToScript(onTestnet, networks.mainnet))).toBe("wrong-network");
    expect(errorCode(() => addressToScript(typo, networks.mainnet))).toBe("bad-checksum");
    expect(errorCode(() => addressToScript("not an address", networks.mainnet))).toBe(
      "invalid-base58",
    );
    expect(errorCode(() => addressToScript("z".repeat(500), networks.mainnet))).toBe(
      "input-too-long",
    );
  });

  test("every throw is a DcrError carrying a code", () => {
    const thrown = [
      () => decodeWif("nonsense"),
      () => ExtendedKey.fromString("nonsense"),
      () => mnemonicToMasterKey("not a mnemonic", networks.mainnet),
      () => calcSignatureHash(subScript, 0x100, oneInputTx(), 0),
      () => new Transaction().addInput({ hash: new Uint8Array(3), index: 0, tree: 0 }),
      () => signHash(new Uint8Array(32), new Uint8Array(32)),
      () => publicKeyFromPrivate(new Uint8Array(32)),
      () => signP2PKHInput(oneInputTx(), 0, subScript, new Uint8Array(32)),
      () => mnemonicToEntropy("not a mnemonic"),
      () => new Writer().varInt(1.5),
    ];
    for (const fn of thrown) {
      let caught: unknown;
      try {
        fn();
      } catch (e) {
        caught = e;
      }
      expect(caught, `${fn}`).toBeInstanceOf(DcrError);
      expect(isDcrError(caught)).toBe(true);
      expect(typeof (caught as DcrError).code).toBe("string");
      // The message still reads for humans, and names the operation.
      expect((caught as DcrError).message).toMatch(/^\w[\w.]*: \S/);
      expect((caught as DcrError).name).toBe("DcrError");
    }
  });

  test("hasErrorCode is safe on an unknown value", () => {
    expect(hasErrorCode(new Error("plain"), "bad-checksum")).toBe(false);
    expect(hasErrorCode(undefined, "bad-checksum")).toBe(false);
    expect(hasErrorCode("a string", "bad-checksum")).toBe(false);
    expect(isDcrError(new Error("plain"))).toBe(false);
    // A look-alike is not a DcrError: the brand is what counts, not the name.
    const lookAlike = Object.assign(new Error("x"), { name: "DcrError", code: "bad-checksum" });
    expect(isDcrError(lookAlike)).toBe(false);
    expect(hasErrorCode(lookAlike, "bad-checksum")).toBe(false);
  });

  test("the guards accept a DcrError from a second copy of the module", async () => {
    // A dual ESM+CJS install hands `import` one bundle and `require` the other,
    // so one process holds two DcrError classes and `instanceof` is false across
    // them. A query string makes the loader instantiate the module again, which
    // reproduces exactly that. Built at runtime so `tsc` does not resolve it.
    const other: typeof import("../src/errors.js") = await import(
      /* @vite-ignore */ "../src/errors.js" + "?copy=2"
    );
    expect(other.DcrError).not.toBe(DcrError);
    const foreign = other.err("bad-checksum", "decodeWif", "checksum does not match");
    expect(foreign instanceof DcrError).toBe(false);
    expect(isDcrError(foreign)).toBe(true);
    expect(hasErrorCode(foreign, "bad-checksum")).toBe(true);
    expect(hasErrorCode(foreign, "wrong-network")).toBe(false);
  });
});
