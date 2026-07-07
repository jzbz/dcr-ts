/**
 * dcr-ts — Decred (DCR) primitives for TypeScript.
 *
 * BLAKE-256, addresses, WIF, BIP32 HD keys, BIP39 mnemonics, the transaction
 * wire format, the Decred signature hash, and low-S ECDSA signing — byte-exact
 * with dcrd. Consensus-critical byte formats are implemented here; elliptic-curve
 * math and standard KDFs come from audited `@noble`/`@scure` packages.
 */

// Hashing
export {
  blake256,
  Blake256,
  hash256,
  hash160,
} from "./hash.js";
export {
  BLAKE256_BLOCK_LENGTH,
  BLAKE256_DIGEST_LENGTH,
} from "./blake256.js";

// Encoding
export {
  base58Encode,
  base58Decode,
  checkEncode,
  checkDecode,
} from "./base58.js";
export { Reader, Writer } from "./bytes.js";

// Networks
export {
  mainnet,
  testnet3,
  simnet,
  regnet,
  networks,
  type Network,
  type NetworkName,
} from "./networks.js";

// Keys
export {
  CURVE_ORDER,
  isValidPrivateKey,
  isValidPublicKey,
  publicKeyFromPrivate,
} from "./keys.js";

// Addresses
export {
  type AddressKind,
  type DecodedAddress,
  pubKeyHashAddress,
  pubKeyHashEd25519Address,
  pubKeyHashSchnorrAddress,
  scriptHashAddress,
  pubKeyAddress,
  addressFromPubKey,
  addressFromScript,
  decodeAddress,
  isValidAddress,
  addressToScript,
} from "./address.js";

// WIF
export {
  SignatureType,
  type DecodedWif,
  encodeWif,
  decodeWif,
} from "./wif.js";

// Scripts
export {
  OP,
  pushData,
  payToPubKeyHashScript,
  payToPubKeyHashAltScript,
  payToScriptHashScript,
  payToPubKeyScript,
  isPayToPubKeyHash,
  isPayToScriptHash,
  extractHash160,
} from "./script.js";

// HD keys
export {
  ExtendedKey,
  HARDENED_OFFSET,
  hardened,
} from "./hd.js";

// Mnemonics
export {
  generateMnemonic,
  validateMnemonic,
  mnemonicToEntropy,
  entropyToMnemonic,
  mnemonicToSeed,
  mnemonicToMasterKey,
} from "./bip39.js";

// Transactions
export {
  Transaction,
  TxSerializeType,
  TxTree,
  DEFAULT_TX_VERSION,
  MAX_SEQUENCE,
  NULL_VALUE_IN,
  NULL_BLOCK_HEIGHT,
  NULL_BLOCK_INDEX,
  outPointFromTxid,
  type OutPoint,
  type TxInput,
  type TxOutput,
} from "./tx.js";

// Signature hash + signing
export { calcSignatureHash, SigHashType } from "./sighash.js";
export {
  signHash,
  verifyHash,
  rawTxInSignature,
  signatureScript,
  signP2PKHInput,
} from "./sign.js";

// Amounts
export {
  ATOMS_PER_COIN,
  COIN_DECIMALS,
  dcrToAtoms,
  atomsToDcr,
} from "./amount.js";
