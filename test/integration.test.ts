import { describe, expect, test } from "vitest";
import {
  addressFromPubKey,
  addressToScript,
  calcSignatureHash,
  decodeAddress,
  mnemonicToMasterKey,
  networks,
  outPointFromTxid,
  SigHashType,
  signP2PKHInput,
  Transaction,
  Transaction as Tx,
  verifyHash,
  publicKeyFromPrivate,
} from "../src/index.js";

describe("end-to-end wallet flow", () => {
  test("mnemonic → key → address → build → sign → verify → serialize round-trip", () => {
    const mnemonic =
      "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const master = mnemonicToMasterKey(mnemonic, networks.mainnet);

    // Derive an account key and two addresses.
    const account = master.derivePath("m/44'/42'/0'");
    const spendKey = account.derive(0).derive(0); // external/0
    const changeKey = account.derive(1).derive(0); // internal/0

    const spendPub = spendKey.publicKey();
    const spendAddr = addressFromPubKey(spendPub, networks.mainnet);
    expect(decodeAddress(spendAddr).kind).toBe("pubkeyhash-ecdsa");
    expect(spendKey.address()).toBe(spendAddr);

    // Build a transaction spending a fake previous output locked to spendAddr.
    const prevScript = addressToScript(spendAddr, networks.mainnet);
    const tx = new Transaction();
    tx.addInput(
      outPointFromTxid(
        "a".repeat(64),
        0,
      ),
      { valueIn: 200_000_000n, blockHeight: 100, blockIndex: 0 },
    );
    tx.addOutput(150_000_000n, addressToScript(addressFromPubKey(changeKey.publicKey(), networks.mainnet), networks.mainnet));
    tx.addOutput(49_990_000n, prevScript);

    // Sign input 0.
    signP2PKHInput(tx, 0, prevScript, spendKey.privateKeyBytes());
    expect(tx.inputs[0]!.signatureScript.length).toBeGreaterThan(0);

    // The signature verifies against the derived public key.
    const h = calcSignatureHash(prevScript, SigHashType.All, tx, 0);
    const rawSig = tx.inputs[0]!.signatureScript;
    // First push is <der||hashtype>; strip the 1-byte push opcode and trailing hashtype.
    const pushLen = rawSig[0]!;
    const der = rawSig.subarray(1, 1 + pushLen - 1);
    expect(verifyHash(h, der, publicKeyFromPrivate(spendKey.privateKeyBytes()))).toBe(true);

    // Serialization round-trips.
    const bytes = tx.serialize();
    const parsed = Tx.fromBytes(bytes);
    expect(parsed.txid()).toBe(tx.txid());
    expect(parsed.serialize()).toEqual(bytes);
  });
});
