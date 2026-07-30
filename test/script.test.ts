import { describe, expect, test } from "vitest";
import {
  classifyScript,
  extractHash160,
  isPayToPubKeyHash,
  isPayToScriptHash,
  MAX_SCRIPT_ELEMENT_SIZE,
  OP,
  payToPubKeyHashAltScript,
  payToPubKeyHashScript,
  payToPubKeyScript,
  payToScriptHashScript,
  pushData,
} from "../src/script.js";
import { bytesToHex, hexToBytes, vectors } from "./helpers.js";

const pkh = hexToBytes(vectors.keys.pubkeyHash160);
const pub = hexToBytes(vectors.keys.pubkeyCompressed);

describe("pushData", () => {
  // dcrd applies checkMinimalDataPush to every executed push opcode with no
  // verification flag gating it (txscript/engine.go), so a non-minimal push is
  // a consensus failure, not a policy one. Mirrors scriptbuilder.go addData.
  test("uses the minimal opcode dcrd requires", () => {
    expect(bytesToHex(pushData(new Uint8Array(0)))).toBe("00"); // OP_0
    expect(bytesToHex(pushData(Uint8Array.of(0x00)))).toBe("00"); // OP_0, not 0100
    expect(bytesToHex(pushData(Uint8Array.of(0x01)))).toBe("51"); // OP_1
    expect(bytesToHex(pushData(Uint8Array.of(0x10)))).toBe("60"); // OP_16
    expect(bytesToHex(pushData(Uint8Array.of(0x81)))).toBe("4f"); // OP_1NEGATE
    // 0x11 is past OP_16, so a direct one-byte push is minimal again.
    expect(bytesToHex(pushData(Uint8Array.of(0x11)))).toBe("0111");
    expect(bytesToHex(pushData(Uint8Array.of(0x17, 0x2a)))).toBe("02172a");
  });

  test("picks the right length encoding at each boundary", () => {
    const at = (n: number) => bytesToHex(pushData(new Uint8Array(n))).slice(0, 6);
    expect(at(75)).toBe("4b0000"); // OP_DATA_75, direct
    expect(at(76)).toBe("4c4c00"); // OP_PUSHDATA1 76
    expect(at(255)).toBe("4cff00"); // OP_PUSHDATA1 255
    expect(at(256)).toBe("4d0001"); // OP_PUSHDATA2 256 (little-endian)
    expect(pushData(new Uint8Array(2048)).length).toBe(3 + 2048);
  });

  test("rejects a push larger than MaxScriptElementSize", () => {
    // dcrd rejects these both when building and at execution, so the script
    // could never run.
    expect(MAX_SCRIPT_ELEMENT_SIZE).toBe(2048);
    expect(() => pushData(new Uint8Array(2049))).toThrow(/MaxScriptElementSize/);
  });
});

describe("payment script builders", () => {
  test("match the dcrd payment scripts for every network", () => {
    for (const [name, a] of Object.entries(vectors.keys.addresses)) {
      expect(bytesToHex(payToPubKeyHashScript(pkh)), `${name} p2pkh`).toBe(a.p2pkh_script);
      expect(
        bytesToHex(payToScriptHashScript(hexToBytes(a.p2sh_scriptHash))),
        `${name} p2sh`,
      ).toBe(a.p2sh_script);
      expect(bytesToHex(payToPubKeyHashAltScript(pkh, 1)), `${name} ed25519`).toBe(
        a.p2pkh_ed25519_script,
      );
      expect(bytesToHex(payToPubKeyHashAltScript(pkh, 2)), `${name} schnorr`).toBe(
        a.p2pkh_schnorr_script,
      );
    }
  });

  test("bare P2PK matches dcrd, for both Y parities", () => {
    // The scripts are network-independent, so mainnet's vectors suffice; the
    // odd-Y one exists because the fixture's main key is even-Y.
    const a = vectors.keys.addresses.mainnet!;
    expect(bytesToHex(payToPubKeyScript(pub))).toBe(a.pubkeyAddr_script);
    const oddPub = hexToBytes(a.pubkeyAddrOddY_script).subarray(1, 34);
    expect(oddPub[0]).toBe(0x03);
    expect(bytesToHex(payToPubKeyScript(oddPub))).toBe(a.pubkeyAddrOddY_script);
  });

  test("rejects anything that is not a real public key", () => {
    // An output script built around non-key bytes is unspendable, so this must
    // not be buildable. The 32-byte case is the realistic slip: passing a
    // private key where the public key was meant type-checks silently.
    const priv = hexToBytes(vectors.keys.privHex);
    expect(() => payToPubKeyScript(priv)).toThrow(/33 compressed bytes/);
    expect(() => payToPubKeyScript(new Uint8Array(33))).toThrow(/0x02 or 0x03/);
    const offCurve = new Uint8Array(33);
    offCurve[0] = 0x02;
    offCurve.set(hexToBytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"), 1);
    expect(() => payToPubKeyScript(offCurve)).toThrow(/curve/);
  });

  test("rejects a wrong-length hash", () => {
    for (const n of [0, 19, 21, 32]) {
      expect(() => payToPubKeyHashScript(new Uint8Array(n)), `p2pkh ${n}`).toThrow(/20 bytes/);
      expect(() => payToScriptHashScript(new Uint8Array(n)), `p2sh ${n}`).toThrow(/20 bytes/);
      expect(() => payToPubKeyHashAltScript(new Uint8Array(n), 1), `alt ${n}`).toThrow(/20 bytes/);
    }
    expect(() => payToPubKeyHashAltScript(pkh, 3 as 1)).toThrow(/sigType/);
  });
});

describe("script classifiers", () => {
  test("recognise the templates they build and reject near-misses", () => {
    expect(isPayToPubKeyHash(payToPubKeyHashScript(pkh))).toBe(true);
    expect(isPayToScriptHash(payToScriptHashScript(pkh))).toBe(true);
    // An alt-suite P2PKH is 26 bytes and ends in OP_CHECKSIGALT, so it must not
    // be mistaken for the plain 25-byte P2PKH template.
    expect(isPayToPubKeyHash(payToPubKeyHashAltScript(pkh, 1))).toBe(false);
    expect(isPayToScriptHash(payToPubKeyHashScript(pkh))).toBe(false);
    expect(isPayToPubKeyHash(new Uint8Array(25))).toBe(false);
    expect(isPayToPubKeyHash(payToPubKeyHashScript(pkh).subarray(0, 24))).toBe(false);
  });

  test("extractHash160 returns the hash for both hash templates", () => {
    expect(bytesToHex(extractHash160(payToPubKeyHashScript(pkh))!)).toBe(
      vectors.keys.pubkeyHash160,
    );
    expect(bytesToHex(extractHash160(payToScriptHashScript(pkh))!)).toBe(
      vectors.keys.pubkeyHash160,
    );
    expect(extractHash160(payToPubKeyScript(pub))).toBeNull();
    expect(extractHash160(new Uint8Array(0))).toBeNull();
  });

  test("extractHash160 does not alias the caller's script", () => {
    const script = Buffer.from(payToPubKeyHashScript(pkh));
    const got = extractHash160(script)!;
    script.fill(0);
    expect(bytesToHex(got)).toBe(vectors.keys.pubkeyHash160);
  });

  test("classifyScript keeps the kind, which extractHash160 discards", () => {
    // Encoding a P2SH hash as a P2PKH address yields a different, valid address
    // for the same script, so losing the kind is a real hazard.
    expect(classifyScript(payToPubKeyHashScript(pkh))).toEqual({
      kind: "pubkeyhash",
      hash: pkh,
    });
    expect(classifyScript(payToScriptHashScript(pkh))).toEqual({
      kind: "scripthash",
      hash: pkh,
    });
    expect(classifyScript(payToPubKeyHashAltScript(pkh, 1))).toEqual({
      kind: "pubkeyhash-ed25519",
      hash: pkh,
    });
    expect(classifyScript(payToPubKeyHashAltScript(pkh, 2))).toEqual({
      kind: "pubkeyhash-schnorr",
      hash: pkh,
    });
    expect(classifyScript(payToPubKeyScript(pub))).toBeNull();
    // Right shape, unknown suite opcode.
    const bogus = payToPubKeyHashAltScript(pkh, 1);
    bogus[24] = OP.OP_16;
    expect(classifyScript(bogus)).toBeNull();
  });
});
