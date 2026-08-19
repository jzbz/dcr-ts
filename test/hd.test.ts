import { describe, expect, test } from "vitest";
import { ExtendedKey, HARDENED_OFFSET, hardened } from "../src/hd.js";
import { networks } from "../src/networks.js";
import {
  parsePublicKeyPoint,
  privateKeyTweakAdd,
  publicKeyFromPrivate,
  publicKeyTweakAddPoint,
} from "../src/keys.js";
import { bytesToHex, hexToBytes, vectors, errorCode } from "./helpers.js";

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
      // dcrd pads the scalar back into the extended-key string and
      // NewKeyFromString does not re-strip, so a round-tripped key derives from a
      // padded parent from then on. Both values below come from dcrd
      // (hd.leadingZero.childPriv is m44.Child(42'), childPrivBip32Std is the
      // strict form of the same step).
      const m44 = master().derive(hardened(44));
      const roundTripped = ExtendedKey.fromString(m44.toString());
      const fromRoundTrip = roundTripped.derive(hardened(42)).toString();

      // The round-trip changes the result: the parent is now read padded.
      expect(fromRoundTrip).not.toBe(m44.derive(hardened(42)).toString());

      // From a *padded* parent the two variants agree, because the flag governs
      // only whether the derived child is stripped — which changes that child's
      // own children, not its serialization.
      expect(fromRoundTrip).toBe(roundTripped.deriveBip32Std(hardened(42)).toString());

      // And from the live stripped parent they also agree with each other, for the
      // same reason, while differing from the round-tripped pair.
      expect(m44.derive(hardened(42)).toString()).toBe(
        m44.deriveBip32Std(hardened(42)).toString(),
      );
    });
  });

  // dcrd's strictBIP32 flag decides only whether the *derived child* is stripped;
  // how the *parent* is read is fixed by how that parent is stored
  // (`copy(data[1:], k.key)` never consults the flag). Getting that backwards
  // yields correct keys for pure-legacy and pure-strict paths and wrong ones only
  // where the variants alternate — invisible to any single-variant vector, which is
  // why these programs are generated by dcrd and checked at every step.
  test("alternating the two variants along one path matches dcrd at every step", () => {
    const g = vectors.hd.mixedVariant;
    const seed = hexToBytes(g.seedHex);
    expect(g.network).toBe("mainnet");
    expect(g.programs.length).toBeGreaterThan(0);

    for (const program of g.programs) {
      let key = ExtendedKey.fromSeed(seed, networks.mainnet);
      expect(program.steps.length).toBe(program.xprvs.length);
      for (let i = 0; i < program.steps.length; i++) {
        const step = program.steps[i]!;
        key = step.strict ? key.deriveBip32Std(step.index) : key.derive(step.index);
        expect(key.toString(), `variants=${program.variants} step ${i} (index ${step.index})`).toBe(
          program.xprvs[i],
        );
      }
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
    expect(errorCode(() => pub.derive(hardened(0)))).toBe("hardened-from-public");
  });

  // dcrd's `child` rejects IL before the private/public split — `overflow ||
  // ilModN.IsZero()` — so an all-zero left HMAC half is an invalid child on BOTH
  // paths. BIP32 itself allows it on the private path, where it would make the
  // child byte-identical to its parent. Reaching it through derive() would need
  // an HMAC-SHA512 whose left half is zero, so the tweaks are exercised directly.
  test("IL == 0 is an invalid child on both derivation paths, as in dcrd", () => {
    const kPar = hexToBytes(vectors.keys.privHex);
    const zero = new Uint8Array(32);
    const overflow = new Uint8Array(32).fill(0xff);
    const one = new Uint8Array(32);
    one[31] = 1;

    expect(privateKeyTweakAdd(kPar, zero)).toBeNull();
    expect(privateKeyTweakAdd(kPar, overflow)).toBeNull();

    const parent = parsePublicKeyPoint(publicKeyFromPrivate(kPar));
    expect(parent).not.toBeNull();
    expect(publicKeyTweakAddPoint(parent!, zero)).toBeNull();
    expect(publicKeyTweakAddPoint(parent!, overflow)).toBeNull();

    // Non-vacuous: a legal IL still tweaks, and to something other than kPar.
    const child = privateKeyTweakAdd(kPar, one);
    expect(child).not.toBeNull();
    expect(bytesToHex(child!)).not.toBe(bytesToHex(kPar));
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
      "x/0",
      "mm/0",
    ]) {
      expect(errorCode(() => master.derivePath(bad)), bad).toBe("invalid-path");
    }
    // Both hardened markers work and agree.
    expect(master.derivePath("m/44h/0h").toString()).toBe(master.derivePath("m/44'/0'").toString());
  });

  test("accepts BIP32's capital-M public-chain spelling", () => {
    // `M/…` and `m/…` name the same path in BIP32; only the key you start from
    // differs. Rejecting `M` would break the notation a watch-only caller writes,
    // and deriving a hardened element from a public key is already refused.
    const master = ExtendedKey.fromSeed(seed, networks.mainnet);
    expect(master.derivePath("M/44'/42'/0'").toString()).toBe(
      master.derivePath("m/44'/42'/0'").toString(),
    );
    const acctPub = master.derivePath("m/44'/42'/0'").neuter();
    expect(acctPub.derivePath("M/0/5").toString()).toBe(acctPub.derivePath("m/0/5").toString());
    expect(errorCode(() => acctPub.derivePath("M/0'"))).toBe("hardened-from-public");
  });

  test("rejects out-of-range indices instead of silently wrapping", () => {
    const master = ExtendedKey.fromSeed(seed, networks.mainnet);
    // hardened() used to wrap: hardened(2**31) produced a NON-hardened index 0,
    // quietly deriving from the wrong branch.
    const expected = (v: number) => (Number.isInteger(v) ? "out-of-range" : "not-an-integer");
    for (const bad of [HARDENED_OFFSET, HARDENED_OFFSET + 1, 2 ** 32, -1, 1.5, NaN, Infinity]) {
      expect(errorCode(() => hardened(bad)), `hardened(${bad})`).toBe(expected(bad));
    }
    expect(hardened(0)).toBe(HARDENED_OFFSET);
    expect(hardened(HARDENED_OFFSET - 1)).toBe(0xffffffff);
    // derive() itself also validates rather than coercing with >>> 0.
    for (const bad of [-1, 1.5, NaN, 2 ** 32, Infinity]) {
      expect(errorCode(() => master.derive(bad)), `derive(${bad})`).toBe(expected(bad));
    }
  });

  test("refuses to derive beyond depth 255", () => {
    let key = ExtendedKey.fromSeed(seed, networks.mainnet);
    for (let i = 0; i < 255; i++) key = key.derive(0);
    expect(key.depth).toBe(255);
    expect(errorCode(() => key.derive(0))).toBe("max-depth");
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
