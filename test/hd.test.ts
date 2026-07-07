import { describe, expect, test } from "vitest";
import { ExtendedKey, hardened } from "../src/hd.js";
import { networks } from "../src/networks.js";
import { bytesToHex, hexToBytes, vectors } from "./helpers.js";

describe("HD keys (BIP32, Decred serialization)", () => {
  const seed = hexToBytes(vectors.hd.seedHex);

  test("master, child, neuter and address match dcrd for every network", () => {
    for (const [name, network] of Object.entries(networks)) {
      const g = vectors.hd.nets[name]!;
      const master = ExtendedKey.fromSeed(seed, network);

      expect(master.toString(), `${name} master priv`).toBe(g.masterPriv);
      expect(master.neuter().toString(), `${name} master pub`).toBe(g.masterPub);

      const child = master.derivePath(`m/44'/${network.slip44}'/0'/0/0`);
      expect(child.toString(), `${name} child priv`).toBe(g.childPriv);
      expect(child.neuter().toString(), `${name} child pub`).toBe(g.childPub);
      expect(bytesToHex(child.publicKey()), `${name} child pubkey`).toBe(g.childPubKeyHex);
      expect(child.address(), `${name} child addr`).toBe(g.childAddr);
    }
  });

  test("public (watch-only) derivation matches private derivation", () => {
    const master = ExtendedKey.fromSeed(seed, networks.mainnet);
    // Neuter an account key, then derive the same non-hardened chain publicly.
    const account = master.derivePath("m/44'/42'/0'");
    const accountPub = account.neuter();

    for (let i = 0; i < 5; i++) {
      const fromPriv = account.derive(0).derive(i).neuter().toString();
      const fromPub = accountPub.derive(0).derive(i).toString();
      expect(fromPub, `external/${i}`).toBe(fromPriv);
    }
  });

  test("hardened derivation from a public key is rejected", () => {
    const pub = ExtendedKey.fromSeed(seed, networks.mainnet).neuter();
    expect(() => pub.derive(hardened(0))).toThrow(/hardened/);
  });

  test("round-trips through fromString", () => {
    const master = ExtendedKey.fromSeed(seed, networks.mainnet);
    const parsed = ExtendedKey.fromString(master.toString());
    expect(parsed.toString()).toBe(master.toString());
    expect(parsed.isPrivate).toBe(true);
    expect(bytesToHex(parsed.privateKeyBytes())).toBe(bytesToHex(master.privateKeyBytes()));

    const pub = ExtendedKey.fromString(master.neuter().toString());
    expect(pub.isPrivate).toBe(false);
    expect(pub.toString()).toBe(master.neuter().toString());
  });

  test("rejects malformed derivation paths", () => {
    const master = ExtendedKey.fromSeed(seed, networks.mainnet);
    for (const bad of ["m/0x10", "m/1e2", "m//0", "m/-1", "m/ 1", "m/1.5", "m/2147483648", "m/abc"]) {
      expect(() => master.derivePath(bad), bad).toThrow();
    }
    // Both hardened markers work and agree.
    expect(master.derivePath("m/44h/0h").toString()).toBe(master.derivePath("m/44'/0'").toString());
  });

  test("refuses to derive beyond depth 255", () => {
    let key = ExtendedKey.fromSeed(seed, networks.mainnet);
    for (let i = 0; i < 255; i++) key = key.derive(0);
    expect(key.depth).toBe(255);
    expect(() => key.derive(0)).toThrow(/depth/);
  });

  test("depth, childNumber and fingerprint are tracked", () => {
    const master = ExtendedKey.fromSeed(seed, networks.mainnet);
    expect(master.depth).toBe(0);
    expect(bytesToHex(master.parentFingerprint)).toBe("00000000");

    const child = master.derive(hardened(44));
    expect(child.depth).toBe(1);
    expect(child.childNumber).toBe(hardened(44));
    expect(bytesToHex(child.parentFingerprint)).toBe(bytesToHex(master.fingerprint()));
  });
});
