import { describe, expect, test } from "vitest";
import {
  base58Decode,
  base58Encode,
  checkDecode,
  checkEncode,
} from "../src/base58.js";
import { networks } from "../src/networks.js";
import {
  addressFromPubKey,
  addressFromScript,
  addressToScript,
  decodeAddress,
  isValidAddress,
  pubKeyAddress,
  pubKeyEd25519Address,
  pubKeySchnorrAddress,
  pubKeyHashAddress,
  pubKeyHashEd25519Address,
  pubKeyHashSchnorrAddress,
  scriptHashAddress,
} from "../src/address.js";
import {
  ED25519_CURVE_ORDER,
  isValidEd25519PublicKey,
  isValidPublicKey,
  scalarToBytes,
} from "../src/keys.js";
import { ed25519 } from "@noble/curves/ed25519";
import { blake256, hash160 } from "../src/hash.js";
import { decodeWif, encodeWif, SignatureType } from "../src/wif.js";
import { bytesToHex, hexToBytes, nonEmpty, vectors, errorCode } from "./helpers.js";

describe("base58", () => {
  test("raw encode/decode matches dcrd", () => {
    for (const v of nonEmpty(vectors.base58, "base58")) {
      const input = hexToBytes(v.input);
      expect(base58Encode(input), `encode ${v.input}`).toBe(v.base58);
      expect(bytesToHex(base58Decode(v.base58)), `decode ${v.base58}`).toBe(v.input);
    }
  });

  test("checkEncode matches dcrd base58check (prefix 073f)", () => {
    for (const v of nonEmpty(vectors.base58, "base58")) {
      const data = hexToBytes("073f" + v.input);
      expect(checkEncode(data)).toBe(v.base58check);
      expect(bytesToHex(checkDecode(v.base58check))).toBe("073f" + v.input);
    }
  });

  test("checkDecode rejects a corrupted checksum", () => {
    const good = checkEncode(hexToBytes("073f00"));
    const bad = good.slice(0, -1) + (good.at(-1) === "A" ? "B" : "A");
    expect(errorCode(() => checkDecode(bad))).toBe("bad-checksum");
  });
});

describe("networks", () => {
  test("constants match dcrd", () => {
    for (const [name, n] of Object.entries(networks)) {
      const g = vectors.networks[name]!;
      const hex2 = (a: readonly number[]) => a.map((b) => b.toString(16).padStart(2, "0")).join("");
      expect(hex2(n.pubKeyHashAddrId), `${name} pkh`).toBe(g.pubKeyHashAddrID);
      expect(hex2(n.scriptHashAddrId), `${name} sh`).toBe(g.scriptHashAddrID);
      expect(hex2(n.pubKeyAddrId), `${name} pk`).toBe(g.pubKeyAddrID);
      expect(hex2(n.pubKeyHashEdwardsAddrId), `${name} edw`).toBe(g.pkhEdwardsAddrID);
      expect(hex2(n.pubKeyHashSchnorrAddrId), `${name} schnorr`).toBe(g.pkhSchnorrAddrID);
      expect(hex2(n.privateKeyId), `${name} priv`).toBe(g.privateKeyID);
      expect(hex2(n.hdPrivateKeyId), `${name} hdpriv`).toBe(g.hdPrivateKeyID);
      expect(hex2(n.hdPublicKeyId), `${name} hdpub`).toBe(g.hdPublicKeyID);
      expect(n.slip44, `${name} slip44`).toBe(g.slip0044CoinType);
      expect(n.net >>> 0, `${name} net`).toBe(g.net);
    }
  });
});

describe("addresses", () => {
  const pkh = hexToBytes(vectors.keys.pubkeyHash160);
  const pub = hexToBytes(vectors.keys.pubkeyCompressed);

  test("P2PKH, P2SH and pubkey addresses match dcrd for all networks", () => {
    for (const [name, network] of Object.entries(networks)) {
      const a = vectors.keys.addresses[name]!;
      expect(pubKeyHashAddress(pkh, network), `${name} p2pkh`).toBe(a.p2pkh);
      expect(addressFromPubKey(pub, network), `${name} from pubkey`).toBe(a.p2pkh);
      expect(scriptHashAddress(hexToBytes(a.p2sh_scriptHash), network), `${name} p2sh`).toBe(a.p2sh);
      expect(addressFromScript(hexToBytes(a.p2pkh_script), network), `${name} from script`).toBe(
        a.p2sh,
      );
      expect(pubKeyAddress(pub, network), `${name} pubkey addr`).toBe(a.pubkeyAddr);
    }
  });

  test("decode classifies kind, hash and network", () => {
    const a = vectors.keys.addresses.mainnet!;
    // Narrowing on `kind` is what makes `hash`/`pubKey` reachable — the union
    // removes the non-null assertions these used to need.
    const d = decodeAddress(a.p2pkh);
    expect(d.kind).toBe("pubkeyhash-ecdsa");
    expect(d.network.name).toBe("mainnet");
    if (d.kind !== "pubkeyhash-ecdsa") throw new Error("unreachable");
    expect(bytesToHex(d.hash)).toBe(vectors.keys.pubkeyHash160);

    const s = decodeAddress(a.p2sh);
    expect(s.kind).toBe("scripthash");
    if (s.kind !== "scripthash") throw new Error("unreachable");
    expect(bytesToHex(s.hash)).toBe(a.p2sh_scriptHash);

    const p = decodeAddress(a.pubkeyAddr);
    expect(p.kind).toBe("pubkey-ecdsa");
    if (p.kind !== "pubkey-ecdsa") throw new Error("unreachable");
    expect(bytesToHex(p.pubKey)).toBe(vectors.keys.pubkeyCompressed);
  });

  test("addressToScript reproduces the dcrd pkScript", () => {
    const a = vectors.keys.addresses.mainnet!;
    expect(bytesToHex(addressToScript(a.p2pkh, networks.mainnet))).toBe(a.p2pkh_script);
    expect(bytesToHex(addressToScript(a.p2sh, networks.mainnet))).toBe(a.p2sh_script);
  });

  test("addressToScript refuses an address from another network", () => {
    // A payment script commits only to the 20-byte hash, so without the network
    // check a pasted testnet address produces bytes byte-identical to the mainnet
    // address for the same hash — paying whoever holds that hash on mainnet.
    const hash = hexToBytes(vectors.keys.pubkeyHash160);
    const onMainnet = pubKeyHashAddress(hash, networks.mainnet);
    const onTestnet = pubKeyHashAddress(hash, networks.testnet3);
    expect(onMainnet).not.toBe(onTestnet);
    // Not merely "invalid": the code says *why*, which is what a UI needs in
    // order to say "that is a testnet address" rather than "bad address".
    expect(errorCode(() => addressToScript(onTestnet, networks.mainnet))).toBe("wrong-network");
    expect(errorCode(() => addressToScript(onMainnet, networks.testnet3))).toBe("wrong-network");
    // The scripts really are identical, which is why the guard is load-bearing.
    expect(bytesToHex(addressToScript(onTestnet, networks.testnet3))).toBe(
      bytesToHex(addressToScript(onMainnet, networks.mainnet)),
    );
  });

  test("Ed25519 and Schnorr P2PKH addresses and scripts match dcrd", () => {
    for (const [name, network] of Object.entries(networks)) {
      const a = vectors.keys.addresses[name]!;
      expect(pubKeyHashEd25519Address(pkh, network), `${name} ed25519`).toBe(a.p2pkh_ed25519);
      expect(pubKeyHashSchnorrAddress(pkh, network), `${name} schnorr`).toBe(a.p2pkh_schnorr);

      const ed = decodeAddress(a.p2pkh_ed25519);
      expect(ed.kind).toBe("pubkeyhash-ed25519");
      expect(ed.network.name).toBe(name);
      const sch = decodeAddress(a.p2pkh_schnorr);
      expect(sch.kind).toBe("pubkeyhash-schnorr");

      // The OP_CHECKSIGALT payment scripts, byte-exact with dcrd.
      expect(bytesToHex(addressToScript(a.p2pkh_ed25519, network)), `${name} ed script`).toBe(
        a.p2pkh_ed25519_script,
      );
      expect(bytesToHex(addressToScript(a.p2pkh_schnorr, network)), `${name} sch script`).toBe(
        a.p2pkh_schnorr_script,
      );
    }
  });

  test("pay-to-pubkey addresses and scripts match dcrd for both Y parities", () => {
    // The fixture's main key is even-Y, so without the 6*G vector the encoder's
    // odd-Y flag branch would never run.
    for (const [name, network] of Object.entries(networks)) {
      const a = vectors.keys.addresses[name]!;
      expect(pubKeyAddress(pub, network), `${name} even-Y`).toBe(a.pubkeyAddr);
      expect(bytesToHex(addressToScript(a.pubkeyAddr, network)), `${name} even-Y script`).toBe(
        a.pubkeyAddr_script,
      );

      const oddPub = hexToBytes(a.pubkeyAddrOddY_script).subarray(1, 34);
      expect(oddPub[0], "the odd-Y vector really is odd-Y").toBe(0x03);
      expect(pubKeyAddress(oddPub, network), `${name} odd-Y`).toBe(a.pubkeyAddrOddY);
      expect(bytesToHex(addressToScript(a.pubkeyAddrOddY, network)), `${name} odd-Y script`).toBe(
        a.pubkeyAddrOddY_script,
      );
      // Decoding recovers the key with the right parity restored.
      const decodedOdd = decodeAddress(a.pubkeyAddrOddY);
      if (decodedOdd.kind !== "pubkey-ecdsa") throw new Error("unreachable");
      expect(bytesToHex(decodedOdd.pubKey), `${name} odd-Y decode`).toBe(bytesToHex(oddPub));
    }
  });

  test("pay-to-pubkey addresses for all three signature suites match dcrd", () => {
    // dcrd's DecodeAddressV0 accepts ECDSA, Ed25519 and Schnorr under one address
    // ID, distinguished by the payload's first byte. Handling only ECDSA meant
    // isValidAddress reported a legitimate mainnet address as invalid.
    for (const [name, network] of Object.entries(networks)) {
      const a = vectors.keys.addresses[name]!;

      // The Ed25519 key is the payload's 32 bytes; there is no oddness bit.
      const edPub = hexToBytes(a.pubkeyAddrEd25519_script).subarray(1, 33);
      expect(edPub.length).toBe(32);
      expect(pubKeyEd25519Address(edPub, network), `${name} ed25519 addr`).toBe(
        a.pubkeyAddrEd25519,
      );
      expect(bytesToHex(addressToScript(a.pubkeyAddrEd25519, network)), `${name} ed25519 script`)
        .toBe(a.pubkeyAddrEd25519_script);

      // Schnorr uses the compressed secp256k1 key, like ECDSA.
      expect(pubKeySchnorrAddress(pub, network), `${name} schnorr addr`).toBe(
        a.pubkeyAddrSchnorr,
      );
      expect(bytesToHex(addressToScript(a.pubkeyAddrSchnorr, network)), `${name} schnorr script`)
        .toBe(a.pubkeyAddrSchnorr_script);

      // All three decode, with the suite recovered from the payload.
      for (const [addr, kind, expectedKey] of [
        [a.pubkeyAddr, "pubkey-ecdsa", vectors.keys.pubkeyCompressed],
        [a.pubkeyAddrEd25519, "pubkey-ed25519", bytesToHex(edPub)],
        [a.pubkeyAddrSchnorr, "pubkey-schnorr", vectors.keys.pubkeyCompressed],
      ] as const) {
        const d = decodeAddress(addr, network);
        expect(d.kind, `${name} ${addr.slice(0, 8)}`).toBe(kind);
        expect(isValidAddress(addr, network), `${name} ${kind} valid`).toBe(true);
        if (d.kind === "pubkeyhash-ecdsa" || d.kind === "scripthash") throw new Error("unreachable");
        if ("pubKey" in d) expect(bytesToHex(d.pubKey), `${name} ${kind} key`).toBe(expectedKey);
      }
    }
  });

  test("a pay-to-pubkey address whose key is off the curve is refused", () => {
    // Same bug class as the ECDSA case: an unspendable address must not validate.
    const bad = new Uint8Array(35);
    bad[0] = networks.mainnet.pubKeyAddrId[0];
    bad[1] = networks.mainnet.pubKeyAddrId[1];
    bad[2] = 1; // Ed25519
    // Y = 2, for which (y^2-1)/(dy^2+1) is not a square, so no X exists — dcrd
    // rejects it with "point not on curve" for either sign bit. Filling the key
    // with 0xff would not do: that is Y = 2^255-1, which reduces to the perfectly
    // good point Y = 18 and is accepted by dcrd (see the ed25519Keys vectors).
    bad[3] = 2;
    const addr = checkEncode(bad);
    expect(errorCode(() => decodeAddress(addr))).toBe("invalid-public-key");
    expect(isValidAddress(addr)).toBe(false);
    // And an unknown suite byte is still rejected.
    bad[2] = 7;
    expect(errorCode(() => decodeAddress(checkEncode(bad)))).toBe("unsupported-signature-type");
  });

  test("Ed25519 keys are accepted exactly where dcrd accepts them", () => {
    // dcrd decodes the key through AGL's edwards25519, which masks off only the
    // sign bit, so an encoding of Y+P names the same point as Y and is accepted;
    // the one rejection in that range is X = 0 with the sign bit set, where
    // dcrd's sign fix-up produces exactly P. The fixture enumerates the entire
    // range where a stricter decoder can disagree (Y+P must fit in 255 bits, so
    // Y <= 18), with both sign bits, plus two ordinary keys.
    let accepted = 0;
    let refused = 0;
    for (const v of nonEmpty(vectors.ed25519Keys, "ed25519Keys")) {
      const key = hexToBytes(v.key);
      expect(isValidEd25519PublicKey(key), `${v.label} ${v.key}`).toBe(v.valid);
      expect(isValidAddress(v.addr, networks.mainnet), `${v.label} address`).toBe(v.valid);
      if (v.valid) {
        accepted++;
        const d = decodeAddress(v.addr, networks.mainnet);
        expect(d.kind, v.label).toBe("pubkey-ed25519");
        if (d.kind !== "pubkey-ed25519") throw new Error("unreachable");
        expect(bytesToHex(d.pubKey), `${v.label} round trip`).toBe(v.key);
        // The encoder shares the same check, so it must agree with the decoder.
        expect(pubKeyEd25519Address(key, networks.mainnet), `${v.label} encode`).toBe(v.addr);
      } else {
        refused++;
        expect(errorCode(() => decodeAddress(v.addr, networks.mainnet)), v.label).toBe(
          "invalid-public-key",
        );
        expect(
          errorCode(() => pubKeyEd25519Address(key, networks.mainnet)),
          `${v.label} encode`,
        ).toBe("invalid-public-key");
      }
    }
    // Neither branch is vacuous, and the accepted set really does include the
    // non-canonical encodings: 23 of them are on the curve.
    expect(accepted, "accepted").toBe(48);
    expect(refused, "refused").toBe(30);
    expect(
      vectors.ed25519Keys.filter((v) => v.valid && v.label.includes("+P")).length,
      "accepted non-canonical",
    ).toBe(23);
  });

  test("address encoders reject anything that is not a real public key", () => {
    // A well-formed address derived from non-key bytes is permanently
    // unspendable, and the way to produce one is mundane: passing a private key
    // where the public key was meant type-checks, since both are Uint8Array.
    const priv = hexToBytes(vectors.keys.privHex);
    expect(priv.length, "32 vs 33 is the whole trap").toBe(32);
    const offCurve = new Uint8Array(33);
    offCurve[0] = 0x02;
    offCurve.set(hexToBytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"), 1);

    for (const fn of [addressFromPubKey, pubKeyAddress]) {
      expect(errorCode(() => fn(priv, networks.mainnet)), `${fn.name} privkey`).toBe("invalid-public-key");
      expect(errorCode(() => fn(new Uint8Array(0), networks.mainnet)), `${fn.name} empty`).toBe(
        "invalid-public-key",
      );
      expect(errorCode(() => fn(offCurve, networks.mainnet)), `${fn.name} off-curve`).toBe(
        "invalid-public-key",
      );
    }

    // pubKeyAddress is compressed-only: its payload format is `sigType || X`,
    // which has no room for an uncompressed key.
    expect(errorCode(() => pubKeyAddress(hexToBytes(vectors.keys.pubkeyUncompressed), networks.mainnet))).toBe("invalid-public-key");
    const badPrefix = new Uint8Array(33);
    badPrefix[0] = 0x04;
    expect(errorCode(() => pubKeyAddress(badPrefix, networks.mainnet))).toBe("invalid-public-key");
  });

  test("addressFromPubKey accepts both serializations, which hash differently", () => {
    // Both are legitimate — dcrd hashes whichever form the caller holds — and they
    // produce different addresses. Refusing the uncompressed form would orphan the
    // only address a signatureScript(..., compressed = false) can ever satisfy.
    const compressed = hexToBytes(vectors.keys.pubkeyCompressed);
    const uncompressed = hexToBytes(vectors.keys.pubkeyUncompressed);
    expect(compressed.length).toBe(33);
    expect(uncompressed.length).toBe(65);
    expect(uncompressed[0]).toBe(0x04);

    const fromCompressed = addressFromPubKey(compressed, networks.mainnet);
    const fromUncompressed = addressFromPubKey(uncompressed, networks.mainnet);
    expect(fromCompressed).toBe(vectors.keys.addresses.mainnet!.p2pkh);
    expect(fromUncompressed).not.toBe(fromCompressed);
    // The uncompressed address is hash160 of the 65-byte serialization.
    expect(fromUncompressed).toBe(pubKeyHashAddress(hash160(uncompressed), networks.mainnet));
    // An uncompressed key that is not on the curve is still refused.
    const bad = Uint8Array.from(uncompressed);
    bad[1] = bad[1]! ^ 0xff;
    expect(errorCode(() => addressFromPubKey(bad, networks.mainnet))).toBe("invalid-public-key");
  });

  test("pubkey addresses encoding an invalid curve point are rejected", () => {
    // X = the field prime is never a valid coordinate (x must be < p).
    const fieldPrime = hexToBytes(
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    );
    const badPubKey = new Uint8Array(33);
    badPubKey[0] = 0x02;
    badPubKey.set(fieldPrime, 1);
    expect(isValidPublicKey(badPubKey)).toBe(false);

    // Hand-build a pubkey address whose payload carries that X coordinate.
    const payload = new Uint8Array(35);
    payload[0] = networks.mainnet.pubKeyAddrId[0];
    payload[1] = networks.mainnet.pubKeyAddrId[1];
    payload[2] = 0x00; // ECDSA, even Y
    payload.set(fieldPrime, 3);
    const addr = checkEncode(payload);
    expect(errorCode(() => decodeAddress(addr))).toBe("invalid-public-key");
    expect(isValidAddress(addr)).toBe(false);
  });

  test("network mismatch and bad addresses are rejected", () => {
    const a = vectors.keys.addresses.mainnet!;
    expect(isValidAddress(a.p2pkh, networks.mainnet)).toBe(true);
    expect(isValidAddress(a.p2pkh, networks.testnet3)).toBe(false);
    expect(isValidAddress("not an address")).toBe(false);
    expect(() => decodeAddress(a.p2pkh, networks.testnet3)).toThrow();
  });
});

describe("WIF", () => {
  // dcrd's NewWIF refuses to build any of the strings the negative cases need, so
  // they are assembled here. Not trusted on its own: the round-trip test below
  // pins this constructor against wif_ed25519, a string dcrd itself produced.
  const makeWif = (suite: number, key: Uint8Array): string => {
    const payload = new Uint8Array(35);
    payload[0] = networks.mainnet.privateKeyId[0]!;
    payload[1] = networks.mainnet.privateKeyId[1]!;
    payload[2] = suite;
    payload.set(key, 3);
    const full = new Uint8Array(39);
    full.set(payload);
    full.set(blake256(payload).subarray(0, 4), 35);
    return base58Encode(full);
  };

  test("all three signature suites round-trip against dcrd", () => {
    // wif_ed25519 and wif_schnorr were generated and then never read by any test.
    const w = vectors.keys.wif.mainnet!;
    const edKey = hexToBytes(w.wif_ed25519_payload).slice(3, 35);
    const secpKey = hexToBytes(vectors.keys.privHex);

    expect(decodeWif(w.wif_ed25519).signatureType).toBe(SignatureType.Ed25519);
    expect(bytesToHex(decodeWif(w.wif_ed25519).privateKey)).toBe(bytesToHex(edKey));
    expect(encodeWif(edKey, networks.mainnet, SignatureType.Ed25519)).toBe(w.wif_ed25519);

    expect(decodeWif(w.wif_schnorr).signatureType).toBe(SignatureType.SchnorrSecp256k1);
    expect(encodeWif(secpKey, networks.mainnet, SignatureType.SchnorrSecp256k1)).toBe(w.wif_schnorr);

    // The in-test constructor agrees with dcrd byte for byte.
    expect(makeWif(SignatureType.Ed25519, edKey)).toBe(w.wif_ed25519);
    expect(makeWif(SignatureType.SchnorrSecp256k1, secpKey)).toBe(w.wif_schnorr);
  });

  test("an unknown suite byte is refused by both halves of the codec", () => {
    const key = hexToBytes(vectors.keys.privHex);
    // dcrd's DecodeWIF has no default arm here and returns a WIF holding a nil
    // private key, with the scheme defaulted to ECDSA. A deliberate divergence.
    for (const bad of [3, 5, 255]) {
      expect(errorCode(() => decodeWif(makeWif(bad, key))), `decode ${bad}`).toBe(
        "unsupported-signature-type",
      );
    }
    // Encode-side: the payload byte is a Uint8Array store, so these all used to
    // coerce into a valid WIF for a suite the caller never asked for.
    for (const bad of [3, 5, 255, 256, -1, 1.5, NaN, "Ed25519"]) {
      expect(
        errorCode(() => encodeWif(key, networks.mainnet, bad as unknown as SignatureType)),
        `encode ${String(bad)}`,
      ).toBe("unsupported-signature-type");
    }
  });

  test("the written-out Ed25519 group order is the one @noble derives", () => {
    // `keys.ts` writes the order out instead of reading `ed25519.CURVE.n`, so that
    // an ECDSA-only consumer does not pull the whole curve into its bundle. That
    // trades a provenance property for bundle size, and this is where it is
    // bought back: the value still has to equal the audited source's, but only
    // the test imports it, so nothing follows the reference into a build.
    expect(ED25519_CURVE_ORDER).toBe(ed25519.CURVE.n);
  });

  test("Ed25519 scalars follow dcrd's bounds, secp256k1 suites stay unchecked", () => {
    const order = 2n ** 252n + 27742317777372353535851937790883648493n;
    const zero = new Uint8Array(32);
    const allFf = new Uint8Array(32).fill(0xff);
    // edwards.PrivKeyFromScalar rejects zero and anything *above* the order, and
    // accepts exactly the order (D.Cmp(N) > 0). Every case checked against dcrd.
    for (const key of [zero, scalarToBytes(order + 1n), allFf]) {
      expect(errorCode(() => decodeWif(makeWif(SignatureType.Ed25519, key)))).toBe(
        "invalid-private-key",
      );
      expect(errorCode(() => encodeWif(key, networks.mainnet, SignatureType.Ed25519))).toBe(
        "invalid-private-key",
      );
    }
    for (const s of [1n, order - 1n, order]) {
      const key = scalarToBytes(s);
      expect(bytesToHex(decodeWif(makeWif(SignatureType.Ed25519, key)).privateKey), `scalar ${s}`)
        .toBe(bytesToHex(key));
      expect(
        decodeWif(encodeWif(key, networks.mainnet, SignatureType.Ed25519)).signatureType,
      ).toBe(SignatureType.Ed25519);
    }
    // dcrd's secp256k1 PrivKeyFromBytes cannot fail — it reduces mod n and drops
    // the overflow — so the same scalars must still encode and decode there.
    for (const suite of [SignatureType.Ecdsa, SignatureType.SchnorrSecp256k1]) {
      for (const key of [zero, allFf]) {
        expect(decodeWif(makeWif(suite, key)).signatureType, `suite ${suite}`).toBe(suite);
        expect(decodeWif(encodeWif(key, networks.mainnet, suite)).signatureType).toBe(suite);
      }
    }
  });

  test("encode/decode matches dcrd for all networks", () => {
    const priv = hexToBytes(vectors.keys.privHex);
    for (const [name, network] of Object.entries(networks)) {
      const w = vectors.keys.wif[name]!;
      expect(encodeWif(priv, network), `${name} wif`).toBe(w.wif);
      const d = decodeWif(w.wif);
      expect(bytesToHex(d.privateKey)).toBe(vectors.keys.privHex);
      expect(d.network.name).toBe(name);
      expect(d.signatureType).toBe(SignatureType.Ecdsa);
    }
  });
});
