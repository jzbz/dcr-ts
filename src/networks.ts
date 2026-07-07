/**
 * Decred network parameters.
 *
 * The magic prefix bytes, private-key IDs, extended-key version bytes and coin
 * types are taken verbatim from dcrd's `chaincfg` package for the four
 * networks. They are what make an address human-readable as `Ds…`/`Ts…`/`Ss…`
 * and what bind a key to a specific network.
 */

/** Two-byte address version prefixes and related per-network identifiers. */
export interface Network {
  /** Human name, e.g. "mainnet". */
  readonly name: string;
  /** Network magic (wire protocol identifier). */
  readonly net: number;
  /** Leading character(s) of every address on this network (informational). */
  readonly addressPrefix: string;
  /** Version prefix for pay-to-pubkey (secp256k1 ECDSA) addresses. */
  readonly pubKeyAddrId: readonly [number, number];
  /** Version prefix for pay-to-pubkey-hash (secp256k1 ECDSA) addresses. */
  readonly pubKeyHashAddrId: readonly [number, number];
  /** Version prefix for pay-to-pubkey-hash (Ed25519) addresses. */
  readonly pubKeyHashEdwardsAddrId: readonly [number, number];
  /** Version prefix for pay-to-pubkey-hash (secp256k1 Schnorr) addresses. */
  readonly pubKeyHashSchnorrAddrId: readonly [number, number];
  /** Version prefix for pay-to-script-hash addresses. */
  readonly scriptHashAddrId: readonly [number, number];
  /** Version prefix for WIF private keys. */
  readonly privateKeyId: readonly [number, number];
  /** BIP32 extended private key version bytes (`dprv`/`tprv`/…). */
  readonly hdPrivateKeyId: readonly [number, number, number, number];
  /** BIP32 extended public key version bytes (`dpub`/`tpub`/…). */
  readonly hdPublicKeyId: readonly [number, number, number, number];
  /** SLIP-0044 registered coin type used in BIP44 derivation paths. */
  readonly slip44: number;
}

export const mainnet: Network = {
  name: "mainnet",
  net: 0xd9b400f9,
  addressPrefix: "D",
  pubKeyAddrId: [0x13, 0x86],
  pubKeyHashAddrId: [0x07, 0x3f],
  pubKeyHashEdwardsAddrId: [0x07, 0x1f],
  pubKeyHashSchnorrAddrId: [0x07, 0x01],
  scriptHashAddrId: [0x07, 0x1a],
  privateKeyId: [0x22, 0xde],
  hdPrivateKeyId: [0x02, 0xfd, 0xa4, 0xe8],
  hdPublicKeyId: [0x02, 0xfd, 0xa9, 0x26],
  slip44: 42,
};

export const testnet3: Network = {
  name: "testnet3",
  net: 0xb194aa75,
  addressPrefix: "T",
  pubKeyAddrId: [0x28, 0xf7],
  pubKeyHashAddrId: [0x0f, 0x21],
  pubKeyHashEdwardsAddrId: [0x0f, 0x01],
  pubKeyHashSchnorrAddrId: [0x0e, 0xe3],
  scriptHashAddrId: [0x0e, 0xfc],
  privateKeyId: [0x23, 0x0e],
  hdPrivateKeyId: [0x04, 0x35, 0x83, 0x97],
  hdPublicKeyId: [0x04, 0x35, 0x87, 0xd1],
  slip44: 1,
};

export const simnet: Network = {
  name: "simnet",
  net: 0x12141c16,
  addressPrefix: "S",
  pubKeyAddrId: [0x27, 0x6f],
  pubKeyHashAddrId: [0x0e, 0x91],
  pubKeyHashEdwardsAddrId: [0x0e, 0x71],
  pubKeyHashSchnorrAddrId: [0x0e, 0x53],
  scriptHashAddrId: [0x0e, 0x6c],
  privateKeyId: [0x23, 0x07],
  hdPrivateKeyId: [0x04, 0x20, 0xb9, 0x03],
  hdPublicKeyId: [0x04, 0x20, 0xbd, 0x3d],
  slip44: 1,
};

export const regnet: Network = {
  name: "regnet",
  net: 0xdab500fa,
  addressPrefix: "R",
  pubKeyAddrId: [0x25, 0xe5],
  pubKeyHashAddrId: [0x0e, 0x00],
  pubKeyHashEdwardsAddrId: [0x0d, 0xe0],
  pubKeyHashSchnorrAddrId: [0x0d, 0xc2],
  scriptHashAddrId: [0x0d, 0xdb],
  privateKeyId: [0x22, 0xfe],
  hdPrivateKeyId: [0xea, 0xb4, 0x04, 0x48],
  hdPublicKeyId: [0xea, 0xb4, 0xf9, 0x87],
  slip44: 1,
};

/** All networks keyed by name. */
export const networks = { mainnet, testnet3, simnet, regnet } as const;

export type NetworkName = keyof typeof networks;
