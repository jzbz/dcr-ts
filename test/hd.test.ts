import { describe, expect, test } from "vitest";
import { ExtendedKey, HARDENED_OFFSET, hardened } from "../src/hd.js";
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

  // The whole point of this block: dcrd's `Child` strips leading zero bytes
  // from a derived private key and carries the shortened key into the next
  // hardened HMAC, while `ChildBIP32Std` does not. dcrwallet uses `Child`, so
  // `derive` must too. The seed above cannot detect the difference — it has no
  // leading-zero ancestor, which is why the suite passed while `derive` was
  // strict. This one is chosen so it does.
  describe("Decred leading-zero variation (dcrd Child vs ChildBIP32Std)", () => {
    const g = vectors.hd.leadingZero;
    const lzSeed = hexToBytes(g.seedHex);
    const master = () => ExtendedKey.fromSeed(lzSeed, networks.mainnet);

    test("the intermediate key really does have a leading zero byte", () => {
      // dcrd holds it at 31 bytes; we keep the padded scalar and narrow only the
      // HMAC input, so check the padded form starts with 0x00.
      const m44 = master().derive(hardened(44));
      expect(g.m44hPrivLen).toBe(31);
      expect(bytesToHex(m44.privateKeyBytes())).toBe("00" + g.m44hPrivStripped);
      // ...and that its own serialization is identical either way, which is what
      // makes the divergence invisible one level up.
      expect(m44.toString()).toBe(g.m44hXprv);
      expect(master().deriveBip32Std(hardened(44)).toString()).toBe(g.m44hXprv);
    });

    test("derive matches dcrd Child, the variant dcrwallet uses", () => {
      const k = master().derivePath(g.path);
      expect(k.toString(), "childPriv").toBe(g.childPriv);
      expect(k.neuter().toString(), "childPub").toBe(g.childPub);
      expect(k.address(), "childAddr").toBe(g.childAddr);
    });

    test("deriveBip32Std matches dcrd ChildBIP32Std", () => {
      const k = master().derivePathBip32Std(g.path);
      expect(k.toString(), "childPrivBip32Std").toBe(g.childPrivBip32Std);
      expect(k.neuter().toString(), "childPubBip32Std").toBe(g.childPubBip32Std);
      expect(k.address(), "childAddrBip32Std").toBe(g.childAddrBip32Std);
    });

    test("the two variants really do disagree for this seed", () => {
      // Guards the guard: if these ever coincide, the vector has stopped
      // testing anything and needs replacing with another seed.
      expect(g.childAddr).not.toBe(g.childAddrBip32Std);
      expect(master().derivePath(g.path).address()).not.toBe(
        master().derivePathBip32Std(g.path).address(),
      );
    });

    test("non-hardened derivation is unaffected by the variation", () => {
      // There is no private key to strip on the public path, and a stripped
      // scalar has the same value, so an account dpub and every address below it
      // agree between the variants.
      const acct = master().derivePath("m/44'/42'/0'");
      const acctStd = master().derivePathBip32Std("m/44'/42'/0'");
      expect(acct.toString()).not.toBe(acctStd.toString()); // hardened: differ
      for (let i = 0; i < 3; i++) {
        // ...but below the account key, each variant agrees with itself both ways.
        expect(acct.derive(0).derive(i).toString()).toBe(
          acct.deriveBip32Std(0).deriveBip32Std(i).toString(),
        );
      }
    });

    test("serializing loses the stripped state, matching dcrd", () => {
      // dcrd pads the scalar back into the extended-key string, and
      // NewKeyFromString does not re-strip, so a round-tripped key derives
      // strictly from then on. Verified against dcrd directly.
      const m44 = master().derive(hardened(44));
      const roundTripped = ExtendedKey.fromString(m44.toString());
      expect(roundTripped.derive(hardened(42)).toString()).toBe(
        m44.deriveBip32Std(hardened(42)).toString(),
      );
      expect(roundTripped.derive(hardened(42)).toString()).not.toBe(
        m44.derive(hardened(42)).toString(),
      );
    });
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
    for (const bad of [
      "m/0x10",
      "m/1e2",
      "m//0",
      "m/-1",
      "m/ 1",
      "m/1.5",
      "m/2147483648",
      "m/abc",
      // Capital M means *public* derivation in BIP32, so it must not be
      // silently accepted as a private path.
      "M/0",
      "M",
    ]) {
      expect(() => master.derivePath(bad), bad).toThrow();
    }
    // Both hardened markers work and agree.
    expect(master.derivePath("m/44h/0h").toString()).toBe(master.derivePath("m/44'/0'").toString());
  });

  test("rejects out-of-range indices instead of silently wrapping", () => {
    const master = ExtendedKey.fromSeed(seed, networks.mainnet);
    // hardened() used to wrap: hardened(2**31) produced a NON-hardened index 0,
    // quietly deriving from the wrong branch.
    for (const bad of [HARDENED_OFFSET, HARDENED_OFFSET + 1, 2 ** 32, -1, 1.5, NaN, Infinity]) {
      expect(() => hardened(bad), `hardened(${bad})`).toThrow(/out of range|integer/);
    }
    expect(hardened(0)).toBe(HARDENED_OFFSET);
    expect(hardened(HARDENED_OFFSET - 1)).toBe(0xffffffff);
    // derive() itself also validates rather than coercing with >>> 0.
    for (const bad of [-1, 1.5, NaN, 2 ** 32, Infinity]) {
      expect(() => master.derive(bad), `derive(${bad})`).toThrow(/out of range|integer/);
    }
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
