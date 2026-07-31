/**
 * Minimal Decred script support: opcode constants, canonical data pushes, the
 * standard payment-script builders and matching classifiers.
 *
 * This is deliberately not a full script engine — it covers the templates a
 * wallet needs to build and recognise: P2PKH, P2SH and bare P2PK.
 */
import { copyOf } from "./bytes.js";
import { assertCompressedPubKey } from "./keys.js";

// The opcodes referenced by this library. Decred's opcode table matches
// Bitcoin's for these; `OP_CHECKSIGALT` is a Decred addition for the Ed25519 /
// Schnorr signature suites.
export const OP = {
  OP_0: 0x00,
  DATA_20: 0x14,
  DATA_32: 0x20,
  DATA_33: 0x21,
  PUSHDATA1: 0x4c,
  PUSHDATA2: 0x4d,
  PUSHDATA4: 0x4e,
  OP_1NEGATE: 0x4f,
  OP_1: 0x51,
  OP_2: 0x52,
  OP_16: 0x60,
  DUP: 0x76,
  EQUAL: 0x87,
  EQUALVERIFY: 0x88,
  HASH160: 0xa9,
  CHECKSIG: 0xac,
  CHECKSIGALT: 0xbe,
} as const;

/**
 * Largest a single stack element may be (dcrd `txscript.MaxScriptElementSize`).
 * dcrd rejects a bigger push both when building and at execution, so anything
 * over this can never run.
 */
export const MAX_SCRIPT_ELEMENT_SIZE = 2048;

/**
 * Encode a canonical data push — the smallest valid encoding for `data`.
 *
 * "Smallest" includes the small-integer opcodes, which is a consensus rule and
 * not a policy one: dcrd's script engine applies `checkMinimalDataPush` to every
 * executed push with no verification flag gating it, so `OP_DATA_1 0x05` fails
 * where `OP_5` succeeds. A script built with a non-minimal push is unspendable.
 */
export function pushData(data: Uint8Array): Uint8Array {
  const n = data.length;
  if (n > MAX_SCRIPT_ELEMENT_SIZE) {
    throw new Error(
      `pushData: ${n} bytes exceeds MaxScriptElementSize (${MAX_SCRIPT_ELEMENT_SIZE})`,
    );
  }
  // The single-byte cases dcrd requires a dedicated opcode for. Mirrors
  // txscript/scriptbuilder.go addData.
  if (n === 1) {
    const b = data[0]!;
    if (b === 0) return Uint8Array.of(OP.OP_0);
    if (b >= 1 && b <= 16) return Uint8Array.of(OP.OP_1 + b - 1);
    if (b === 0x81) return Uint8Array.of(OP.OP_1NEGATE);
  }
  if (n < OP.PUSHDATA1) {
    const out = new Uint8Array(1 + n);
    out[0] = n;
    out.set(data, 1);
    return out;
  }
  if (n <= 0xff) {
    const out = new Uint8Array(2 + n);
    out[0] = OP.PUSHDATA1;
    out[1] = n;
    out.set(data, 2);
    return out;
  }
  // No OP_PUSHDATA4 branch: the MaxScriptElementSize check above caps `n` at
  // 2048, so a 4-byte length is never the minimal encoding. If that cap is ever
  // relaxed, this is where the branch goes back.
  const out = new Uint8Array(3 + n);
  out[0] = OP.PUSHDATA2;
  out[1] = n & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out.set(data, 3);
  return out;
}

/**
 * True when `script` tokenizes cleanly as a version-0 script — i.e. every data
 * push declares a length that actually fits.
 *
 * The equivalent of dcrd's `checkScriptParses`, which its exported
 * `CalcSignatureHash` runs before hashing. Signing against a script that does
 * not parse produces a signature over a message dcrd would refuse to compute,
 * so the resulting transaction can never be spent.
 *
 * This is a structural check only, not an execution one: it says nothing about
 * whether the opcodes are valid or the script would succeed.
 */
export function scriptParses(script: Uint8Array): boolean {
  let i = 0;
  while (i < script.length) {
    const op = script[i]!;
    if (op >= 0x01 && op <= 0x4b) {
      // OP_DATA_1..OP_DATA_75: the opcode byte plus exactly that many more.
      if (script.length - i < op + 1) return false;
      i += op + 1;
    } else if (op === OP.PUSHDATA1 || op === OP.PUSHDATA2 || op === OP.PUSHDATA4) {
      const lenSize = op === OP.PUSHDATA1 ? 1 : op === OP.PUSHDATA2 ? 2 : 4;
      if (script.length - (i + 1) < lenSize) return false;
      let dataLen = 0;
      for (let b = 0; b < lenSize; b++) dataLen |= script[i + 1 + b]! << (8 * b);
      // dcrd reads the length as a signed int32, so a 4-byte length with the
      // high bit set comes out negative and is rejected rather than treated as
      // enormous. JS `<<` yields int32, so this matches for free.
      if (dataLen < 0 || dataLen > script.length - (i + 1 + lenSize)) return false;
      i += 1 + lenSize + dataLen;
    } else {
      i += 1;
    }
  }
  return true;
}

/** Build a P2PKH script: `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`. */
export function payToPubKeyHashScript(hash160: Uint8Array): Uint8Array {
  if (hash160.length !== 20) throw new Error("payToPubKeyHash: hash must be 20 bytes");
  // Preallocate and `set` rather than spreading through a JS number array, which
  // measured several times slower. Scripts are built once per output, so this is
  // on the hot path for any wallet assembling many transactions.
  const out = new Uint8Array(25);
  out[0] = OP.DUP;
  out[1] = OP.HASH160;
  out[2] = OP.DATA_20;
  out.set(hash160, 3);
  out[23] = OP.EQUALVERIFY;
  out[24] = OP.CHECKSIG;
  return out;
}

/**
 * Build a P2PKH script for an alternative signature suite (Ed25519 = 1,
 * secp256k1 Schnorr = 2): `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY
 * <OP_1|OP_2> OP_CHECKSIGALT`. The signature type is pushed as a small integer.
 */
export function payToPubKeyHashAltScript(hash160: Uint8Array, sigType: 1 | 2): Uint8Array {
  if (hash160.length !== 20) throw new Error("payToPubKeyHashAlt: hash must be 20 bytes");
  if (sigType !== 1 && sigType !== 2) throw new Error("payToPubKeyHashAlt: bad sigType");
  const out = new Uint8Array(26);
  out[0] = OP.DUP;
  out[1] = OP.HASH160;
  out[2] = OP.DATA_20;
  out.set(hash160, 3);
  out[23] = OP.EQUALVERIFY;
  out[24] = sigType === 1 ? OP.OP_1 : OP.OP_2;
  out[25] = OP.CHECKSIGALT;
  return out;
}

/** Build a P2SH script: `OP_HASH160 <20-byte hash> OP_EQUAL`. */
export function payToScriptHashScript(hash160: Uint8Array): Uint8Array {
  if (hash160.length !== 20) throw new Error("payToScriptHash: hash must be 20 bytes");
  const out = new Uint8Array(23);
  out[0] = OP.HASH160;
  out[1] = OP.DATA_20;
  out.set(hash160, 2);
  out[22] = OP.EQUAL;
  return out;
}

/**
 * Build a bare P2PK script: `<33-byte compressed pubkey> OP_CHECKSIG`.
 *
 * The key is validated as an actual curve point, not just measured. This is an
 * *output* script: paying to one built around arbitrary 33 bytes burns the coins,
 * because no signature can ever satisfy an `OP_CHECKSIG` whose key does not
 * parse. dcrd cannot express this — its constructor takes a parsed public key.
 */
export function payToPubKeyScript(compressedPubKey: Uint8Array): Uint8Array {
  assertCompressedPubKey(compressedPubKey, "payToPubKey");
  const out = new Uint8Array(35);
  out[0] = OP.DATA_33;
  out.set(compressedPubKey, 1);
  out[34] = OP.CHECKSIG;
  return out;
}

/** True when `script` is a canonical version-0 P2PKH template. */
export function isPayToPubKeyHash(script: Uint8Array): boolean {
  return (
    script.length === 25 &&
    script[0] === OP.DUP &&
    script[1] === OP.HASH160 &&
    script[2] === OP.DATA_20 &&
    script[23] === OP.EQUALVERIFY &&
    script[24] === OP.CHECKSIG
  );
}

/** True when `script` is a canonical version-0 P2SH template. */
export function isPayToScriptHash(script: Uint8Array): boolean {
  return (
    script.length === 23 &&
    script[0] === OP.HASH160 &&
    script[1] === OP.DATA_20 &&
    script[22] === OP.EQUAL
  );
}

/**
 * Extract the 20-byte hash from a P2PKH or P2SH script, or `null`.
 *
 * Note this deliberately loses *which* template matched, and the two need
 * different addresses — use {@link classifyScript} when that matters, or the
 * hash will be encoded as the wrong address kind.
 */
export function extractHash160(script: Uint8Array): Uint8Array | null {
  if (isPayToPubKeyHash(script)) return copyOf(script, 3, 20);
  if (isPayToScriptHash(script)) return copyOf(script, 2, 20);
  return null;
}

/** What {@link classifyScript} recognises. */
export type ScriptKind =
  | "pubkeyhash-ecdsa"
  | "pubkeyhash-ed25519"
  | "pubkeyhash-schnorr"
  | "scripthash";

/**
 * Classify a version-0 payment script and return its 20-byte hash.
 *
 * {@link extractHash160} returns a bare hash for either the P2PKH or the P2SH
 * template, so a caller labelling outputs by address has no way to tell which
 * encoder to use — and picking wrong produces a completely different, valid
 * address for the same script. This keeps the kind attached. Also recognises the
 * two `OP_CHECKSIGALT` templates the library can build, which nothing could
 * classify before.
 */
export function classifyScript(script: Uint8Array): { kind: ScriptKind; hash: Uint8Array } | null {
  if (isPayToPubKeyHash(script)) return { kind: "pubkeyhash-ecdsa", hash: copyOf(script, 3, 20) };
  if (isPayToScriptHash(script)) return { kind: "scripthash", hash: copyOf(script, 2, 20) };
  if (
    script.length === 26 &&
    script[0] === OP.DUP &&
    script[1] === OP.HASH160 &&
    script[2] === OP.DATA_20 &&
    script[23] === OP.EQUALVERIFY &&
    script[25] === OP.CHECKSIGALT
  ) {
    if (script[24] === OP.OP_1) {
      return { kind: "pubkeyhash-ed25519", hash: copyOf(script, 3, 20) };
    }
    if (script[24] === OP.OP_2) {
      return { kind: "pubkeyhash-schnorr", hash: copyOf(script, 3, 20) };
    }
  }
  return null;
}
