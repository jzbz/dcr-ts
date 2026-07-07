import { describe, expect, test } from "vitest";
import { atomsToDcr, ATOMS_PER_COIN, dcrToAtoms } from "../src/amount.js";
import {
  entropyToMnemonic,
  generateMnemonic,
  mnemonicToEntropy,
  mnemonicToMasterKey,
  mnemonicToSeed,
  validateMnemonic,
} from "../src/bip39.js";
import { networks } from "../src/networks.js";
import { bytesToHex, hexToBytes } from "./helpers.js";

describe("amount", () => {
  test("round-trips and known conversions", () => {
    expect(dcrToAtoms("1")).toBe(ATOMS_PER_COIN);
    expect(dcrToAtoms("1.5")).toBe(150_000_000n);
    expect(dcrToAtoms("0.00000001")).toBe(1n);
    expect(dcrToAtoms("-0.00000001")).toBe(-1n);
    expect(dcrToAtoms("21000000")).toBe(2_100_000_000_000_000n);
    expect(atomsToDcr(150_000_000n)).toBe("1.50000000");
    expect(atomsToDcr(1n)).toBe("0.00000001");
    expect(atomsToDcr(-1n)).toBe("-0.00000001");
    // Full-precision round-trips.
    const cases: Array<[string, string]> = [
      ["0", "0.00000000"],
      ["1", "1.00000000"],
      ["1.5", "1.50000000"],
      ["123.45678901", "123.45678901"],
      ["0.1", "0.10000000"],
      ["20999999.99999999", "20999999.99999999"],
    ];
    for (const [input, expected] of cases) {
      expect(atomsToDcr(dcrToAtoms(input)), input).toBe(expected);
    }
  });

  test("rejects malformed input and excess precision", () => {
    expect(() => dcrToAtoms("1.234567890")).toThrow();
    expect(() => dcrToAtoms("abc")).toThrow();
    expect(() => dcrToAtoms("")).toThrow();
  });
});

describe("bip39", () => {
  // Canonical BIP39 test vector (Trezor).
  const mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
  const expectedSeed =
    "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f" +
    "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607";

  test("mnemonicToSeed matches the reference vector", () => {
    expect(validateMnemonic(mnemonic)).toBe(true);
    expect(bytesToHex(mnemonicToSeed(mnemonic, "TREZOR"))).toBe(expectedSeed);
  });

  test("entropy round-trips", () => {
    const entropy = hexToBytes("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
    expect(entropyToMnemonic(entropy)).toBe(mnemonic);
    expect(bytesToHex(mnemonicToEntropy(mnemonic))).toBe("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
  });

  test("generateMnemonic produces valid mnemonics", () => {
    const m = generateMnemonic(256);
    expect(m.split(" ")).toHaveLength(24);
    expect(validateMnemonic(m)).toBe(true);
  });

  test("mnemonicToMasterKey yields a usable Decred key", () => {
    const key = mnemonicToMasterKey(mnemonic, networks.mainnet, "TREZOR");
    expect(key.isPrivate).toBe(true);
    expect(key.toString().startsWith("dprv")).toBe(true);
    expect(key.derivePath("m/44'/42'/0'/0/0").address().startsWith("Ds")).toBe(true);
  });
});
