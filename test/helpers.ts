import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Ground-truth vectors generated from dcrd (see vectorgen/main.go). */
export const vectors = JSON.parse(
  readFileSync(join(__dirname, "fixtures", "dcrd-vectors.json"), "utf8"),
) as DcrdVectors;

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
  keys: {
    privHex: string;
    pubkeyCompressed: string;
    pubkeyUncompressed: string;
    pubkeyHash160: string;
    addresses: Record<string, AddrVec>;
    wif: Record<string, { wif: string; wif_payload: string }>;
  };
  hd: {
    seedHex: string;
    nets: Record<string, HdVec>;
  };
  tx: {
    serialized: string;
    prefixSer: string;
    witnessSer: string;
    txid: string;
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
    subScript: string;
    sighashes: Record<string, Record<string, string>>;
  };
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
