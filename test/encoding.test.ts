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
  pubKeyHashAddress,
  pubKeyHashEd25519Address,
  pubKeyHashSchnorrAddress,
  scriptHashAddress,
} from "../src/address.js";
import { isValidPublicKey } from "../src/keys.js";
import { decodeWif, encodeWif, SignatureType } from "../src/wif.js";
import { bytesToHex, hexToBytes, nonEmpty, vectors } from "./helpers.js";

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
    expect(() => checkDecode(bad)).toThrow(/checksum|base58/);
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
    const d = decodeAddress(a.p2pkh);
    expect(d.kind).toBe("pubkeyhash-ecdsa");
    expect(d.network.name).toBe("mainnet");
    expect(bytesToHex(d.hash!)).toBe(vectors.keys.pubkeyHash160);

    const s = decodeAddress(a.p2sh);
    expect(s.kind).toBe("scripthash");
    expect(bytesToHex(s.hash!)).toBe(a.p2sh_scriptHash);

    const p = decodeAddress(a.pubkeyAddr);
    expect(p.kind).toBe("pubkey-ecdsa");
    expect(bytesToHex(p.pubKey!)).toBe(vectors.keys.pubkeyCompressed);
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
    expect(() => addressToScript(onTestnet, networks.mainnet)).toThrow();
    expect(() => addressToScript(onMainnet, networks.testnet3)).toThrow();
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
      expect(bytesToHex(decodeAddress(a.pubkeyAddrOddY).pubKey!), `${name} odd-Y decode`).toBe(
        bytesToHex(oddPub),
      );
    }
  });

  test("address encoders reject anything that is not a real public key", () => {
    // A well-formed address derived from non-key bytes is permanently
    // unspendable, and the way to produce one is mundane: passing a private key
    // where the public key was meant type-checks, since both are Uint8Array.
    const priv = hexToBytes(vectors.keys.privHex);
    expect(priv.length, "32 vs 33 is the whole trap").toBe(32);
    for (const fn of [addressFromPubKey, pubKeyAddress]) {
      expect(() => fn(priv, networks.mainnet), `${fn.name} privkey`).toThrow(
        /33 compressed bytes/,
      );
      expect(() => fn(new Uint8Array(0), networks.mainnet), `${fn.name} empty`).toThrow(
        /33 compressed bytes/,
      );
      expect(() => fn(new Uint8Array(65), networks.mainnet), `${fn.name} uncompressed`).toThrow(
        /33 compressed bytes/,
      );
      // Right length, wrong prefix.
      const badPrefix = new Uint8Array(33);
      badPrefix[0] = 0x04;
      expect(() => fn(badPrefix, networks.mainnet), `${fn.name} prefix`).toThrow(/0x02 or 0x03/);
      // Right length and prefix, not on the curve.
      const offCurve = new Uint8Array(33);
      offCurve[0] = 0x02;
      offCurve.set(
        hexToBytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
        1,
      );
      expect(() => fn(offCurve, networks.mainnet), `${fn.name} off-curve`).toThrow(/curve/);
    }
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
    expect(() => decodeAddress(addr)).toThrow(/curve point/);
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
