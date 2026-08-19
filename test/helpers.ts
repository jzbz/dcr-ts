import { readFileSync } from "node:fs";
import { DcrError, type DcrErrorCode } from "../src/errors.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Ground-truth vectors generated from dcrd (see vectorgen/main.go). */
export const vectors = JSON.parse(
  readFileSync(join(__dirname, "fixtures", "dcrd-vectors.json"), "utf8"),
) as DcrdVectors;

/**
 * Assert a fixture-driven collection is non-empty before looping over it.
 *
 * Every `for (const v of vectors.x)` test passes vacuously if the fixture ever
 * loses a section — a regenerated or hand-edited file could silently reduce a
 * suite to zero assertions while still reporting green. Call this first so the
 * cardinality itself is checked.
 */
export function nonEmpty<T>(items: readonly T[], what: string): readonly T[] {
  if (!Array.isArray(items) || items.length === 0) {
    throw new Error(`fixture: expected ${what} to be a non-empty array`);
  }
  return items;
}

/**
 * Run `fn`, require it to throw a {@link DcrError}, and return the error's code.
 *
 * Assertions here used to match on message text (`toThrow(/bad checksum/)`),
 * which is not part of any API: rewording a message broke tests, and distinct
 * failures that happened to share wording were indistinguishable. Codes are the
 * contract, so assert on those.
 */
export function errorCode(fn: () => unknown): DcrErrorCode {
  try {
    fn();
  } catch (e) {
    if (e instanceof DcrError) return e.code;
    throw new Error(`expected a DcrError, got ${e instanceof Error ? e.name : typeof e}: ${e}`);
  }
  throw new Error("expected a throw, but the call returned normally");
}

export function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`invalid hex: "${hex.slice(0, 32)}"`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export interface DcrdVectors {
  networks: Record<string, NetConst>;
  hashes: Array<{ input: string; blake256: string; blake256d: string; hash160: string }>;
  sanity: Record<string, string>;
  base58: Array<{ input: string; base58: string; base58check: string }>;
  /** Mainnet pay-to-pubkey addresses for Ed25519 keys, with dcrd's verdict. */
  ed25519Keys: EdKeyVec[];
  keys: {
    privHex: string;
    pubkeyCompressed: string;
    pubkeyUncompressed: string;
    pubkeyHash160: string;
    addresses: Record<string, AddrVec>;
    /** One WIF per signature suite: ECDSA (unsuffixed), Schnorr, Ed25519. */
    wif: Record<string, WifVec>;
  };
  hd: {
    seedHex: string;
    nets: Record<string, HdVec>;
    leadingZero: LeadingZeroVec;
    mixedVariant: MixedVariantVec;
  };
  tx: {
    serialized: string;
    prefixSer: string;
    witnessSer: string;
    txid: string;
    txidWitness: string;
    txidFull: string;
    subScript: string;
    sigHashAll: string;
    derSig: string;
    sigScript: string;
    outScript: string;
  };
  tx2: {
    serialized: string;
    prefixSer: string;
    witnessSer: string;
    txid: string;
    txidWitness: string;
    txidFull: string;
    subScript: string;
    sighashes: Record<string, Record<string, string>>;
  };
  /** 3-in/3-out tx: SigHashSingle at the last output index, and undefined hash types. */
  tx3: {
    serialized: string;
    txid: string;
    subScript: string;
    /** hashType (as "0x01") -> input ("in0") -> sighash. */
    sighashes: Record<string, Record<string, string>>;
  };
  /** Built from wire.NewTxIn, so the null witness sentinels are pinned. */
  txNullWitness: {
    nullValueIn: string;
    nullBlockHeight: string;
    nullBlockIndex: string;
    maxSequence: string;
    serialized: string;
    prefixSer: string;
    witnessSer: string;
    txid: string;
    txidWitness: string;
    txidFull: string;
  };
  /** 300 outputs: exercises multi-byte varints and writer growth. */
  txBig: {
    numOutputs: number;
    serialized: string;
    prefixSer: string;
    txid: string;
    txidWitness: string;
    txidFull: string;
  };
  sighashPrefixReuse: { tx3PrefixHash: string; note: string };
}

/**
 * The leading-zero HD case. dcrd's `Child` (what dcrwallet derives with) strips
 * leading zero bytes from a derived private key; `ChildBIP32Std` does not. Both
 * are pinned because the difference is otherwise invisible — the affected key's
 * own extended-key string is identical either way, since dcrd pads it back out.
 */
export interface LeadingZeroVec {
  seedHex: string;
  network: string;
  path: string;
  m44hPrivStripped: string;
  m44hPrivLen: number;
  m44hXprv: string;
  childPriv: string;
  childPub: string;
  childAddr: string;
  childPrivBip32Std: string;
  childPubBip32Std: string;
  childAddrBip32Std: string;
}

export interface NetConst {
  name: string;
  net: number;
  networkAddressPrefix: string;
  pubKeyAddrID: string;
  pubKeyHashAddrID: string;
  pkhEdwardsAddrID: string;
  pkhSchnorrAddrID: string;
  scriptHashAddrID: string;
  privateKeyID: string;
  hdPrivateKeyID: string;
  hdPublicKeyID: string;
  slip0044CoinType: number;
  legacyCoinType: number;
}

/**
 * Paths that alternate the Decred and strict-BIP32 derivation variants, with the
 * extended key after every step. Pure-variant paths cannot detect a mix-up in
 * which of parent-read and child-strip the variant flag governs.
 */
export interface MixedVariantVec {
  seedHex: string;
  network: string;
  programs: Array<{
    steps: Array<{ index: number; strict: boolean }>;
    /** One char per step: `l` legacy/Decred, `s` strict BIP32. */
    variants: string;
    /** The extended private key after each step. */
    xprvs: string[];
  }>;
}

export interface WifVec {
  wif: string;
  wif_payload: string;
  wif_schnorr: string;
  wif_schnorr_payload: string;
  /** Ed25519 uses its own scalar; a secp256k1 key is not in the Edwards subgroup. */
  wif_ed25519: string;
  wif_ed25519_payload: string;
}

/**
 * An Ed25519 public key and dcrd's verdict on the pay-to-pubkey address built
 * from it, covering the encodings where a stricter decoder would disagree.
 */
export interface EdKeyVec {
  label: string;
  key: string;
  addr: string;
  valid: boolean;
}

export interface AddrVec {
  p2pkh: string;
  p2pkh_payload: string;
  p2pkh_script: string;
  p2pkh_ed25519: string;
  p2pkh_ed25519_script: string;
  p2pkh_schnorr: string;
  p2pkh_schnorr_script: string;
  p2sh: string;
  p2sh_payload: string;
  p2sh_scriptHash: string;
  p2sh_script: string;
  pubkeyAddr: string;
  pubkeyAddr_script: string;
  /** The same address ID also carries the two alternative signature suites. */
  pubkeyAddrEd25519: string;
  pubkeyAddrEd25519_script: string;
  pubkeyAddrSchnorr: string;
  pubkeyAddrSchnorr_script: string;
  /** Same encoding for a key whose Y coordinate is odd (sets the 0x80 flag). */
  pubkeyAddrOddY: string;
  pubkeyAddrOddY_script: string;
}

export interface HdVec {
  masterPriv: string;
  masterPrivPayload: string;
  masterPub: string;
  masterPubPayload: string;
  childPath: string;
  childPriv: string;
  childPub: string;
  childPubKeyHex: string;
  childAddr: string;
}
