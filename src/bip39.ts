/**
 * BIP39 mnemonics.
 *
 * A thin, Decred-flavoured wrapper over the audited `@scure/bip39`. The mnemonic
 * standard is not Decred-specific; the Decred part is expanding the resulting
 * seed into a {@link ExtendedKey} with the right network version bytes.
 */
import {
  entropyToMnemonic as scureEntropyToMnemonic,
  generateMnemonic as scureGenerateMnemonic,
  mnemonicToEntropy as scureMnemonicToEntropy,
  mnemonicToSeedSync,
  validateMnemonic as scureValidateMnemonic,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { ExtendedKey } from "./hd.js";
import type { Network } from "./networks.js";

/** Generate a new English mnemonic. `strength` is entropy bits (128–256, default 128). */
export function generateMnemonic(strength = 128): string {
  return scureGenerateMnemonic(wordlist, strength);
}

/** Validate an English mnemonic's checksum and wordlist membership. */
export function validateMnemonic(mnemonic: string): boolean {
  return scureValidateMnemonic(mnemonic, wordlist);
}

/** Recover the raw entropy behind a mnemonic. */
export function mnemonicToEntropy(mnemonic: string): Uint8Array {
  return scureMnemonicToEntropy(mnemonic, wordlist);
}

/** Encode entropy (16–32 bytes, multiple of 4) as a mnemonic. */
export function entropyToMnemonic(entropy: Uint8Array): string {
  return scureEntropyToMnemonic(entropy, wordlist);
}

/** Expand a mnemonic (with optional passphrase) into the 64-byte BIP39 seed. */
export function mnemonicToSeed(mnemonic: string, passphrase = ""): Uint8Array {
  return mnemonicToSeedSync(mnemonic, passphrase);
}

/** Expand a mnemonic straight into a Decred master {@link ExtendedKey}. */
export function mnemonicToMasterKey(
  mnemonic: string,
  network: Network,
  passphrase = "",
): ExtendedKey {
  return ExtendedKey.fromSeed(mnemonicToSeed(mnemonic, passphrase), network);
}
