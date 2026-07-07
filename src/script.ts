/**
 * Minimal Decred script support: opcode constants, canonical data pushes, the
 * standard payment-script builders and matching classifiers.
 *
 * This is deliberately not a full script engine — it covers the templates a
 * wallet needs to build and recognise: P2PKH, P2SH and bare P2PK.
 */

// The opcodes referenced by this library. Decred's opcode table matches
// Bitcoin's for these; `OP_CHECKSIGALT` is a Decred addition for the Ed25519 /
// Schnorr signature suites.
export const OP = {
  DATA_20: 0x14,
  DATA_32: 0x20,
  DATA_33: 0x21,
  PUSHDATA1: 0x4c,
  PUSHDATA2: 0x4d,
  PUSHDATA4: 0x4e,
  OP_1: 0x51,
  OP_2: 0x52,
  DUP: 0x76,
  EQUAL: 0x87,
  EQUALVERIFY: 0x88,
  HASH160: 0xa9,
  CHECKSIG: 0xac,
  CHECKSIGALT: 0xbe,
} as const;

/** Encode a canonical data push (the smallest valid encoding for `data`). */
export function pushData(data: Uint8Array): Uint8Array {
  const n = data.length;
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
  if (n <= 0xffff) {
    const out = new Uint8Array(3 + n);
    out[0] = OP.PUSHDATA2;
    out[1] = n & 0xff;
    out[2] = (n >>> 8) & 0xff;
    out.set(data, 3);
    return out;
  }
  const out = new Uint8Array(5 + n);
  out[0] = OP.PUSHDATA4;
  out[1] = n & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = (n >>> 16) & 0xff;
  out[4] = (n >>> 24) & 0xff;
  out.set(data, 5);
  return out;
}

/** Build a P2PKH script: `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`. */
export function payToPubKeyHashScript(hash160: Uint8Array): Uint8Array {
  if (hash160.length !== 20) throw new Error("payToPubKeyHash: hash must be 20 bytes");
  return Uint8Array.from([
    OP.DUP,
    OP.HASH160,
    OP.DATA_20,
    ...hash160,
    OP.EQUALVERIFY,
    OP.CHECKSIG,
  ]);
}

/**
 * Build a P2PKH script for an alternative signature suite (Ed25519 = 1,
 * secp256k1 Schnorr = 2): `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY
 * <OP_1|OP_2> OP_CHECKSIGALT`. The signature type is pushed as a small integer.
 */
export function payToPubKeyHashAltScript(hash160: Uint8Array, sigType: 1 | 2): Uint8Array {
  if (hash160.length !== 20) throw new Error("payToPubKeyHashAlt: hash must be 20 bytes");
  if (sigType !== 1 && sigType !== 2) throw new Error("payToPubKeyHashAlt: bad sigType");
  return Uint8Array.from([
    OP.DUP,
    OP.HASH160,
    OP.DATA_20,
    ...hash160,
    OP.EQUALVERIFY,
    sigType === 1 ? OP.OP_1 : OP.OP_2,
    OP.CHECKSIGALT,
  ]);
}

/** Build a P2SH script: `OP_HASH160 <20-byte hash> OP_EQUAL`. */
export function payToScriptHashScript(hash160: Uint8Array): Uint8Array {
  if (hash160.length !== 20) throw new Error("payToScriptHash: hash must be 20 bytes");
  return Uint8Array.from([OP.HASH160, OP.DATA_20, ...hash160, OP.EQUAL]);
}

/** Build a bare P2PK script: `<33-byte compressed pubkey> OP_CHECKSIG`. */
export function payToPubKeyScript(compressedPubKey: Uint8Array): Uint8Array {
  if (compressedPubKey.length !== 33) throw new Error("payToPubKey: pubkey must be 33 bytes");
  return Uint8Array.from([OP.DATA_33, ...compressedPubKey, OP.CHECKSIG]);
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

/** Extract the 20-byte hash from a P2PKH or P2SH script, or `null`. */
export function extractHash160(script: Uint8Array): Uint8Array | null {
  if (isPayToPubKeyHash(script)) return script.slice(3, 23);
  if (isPayToScriptHash(script)) return script.slice(2, 22);
  return null;
}
