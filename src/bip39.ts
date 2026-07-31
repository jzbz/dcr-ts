/**
 * BIP39 mnemonics.
 *
 * A thin, Decred-flavoured wrapper over the audited `@scure/bip39`. The mnemonic
 * standard is not Decred-specific; the Decred part is expanding the resulting
 * seed into a {@link ExtendedKey} with the right network version bytes.
 *
 * Every function takes an optional `wordlist` and defaults to English. BIP39
 * defines eight more, and a phrase in one of them is just as valid — the seed
 * derivation itself does not depend on the wordlist at all, only the checksum
 * check does. Import the list you need from `@scure/bip39/wordlists/…`.
 */
import {
  entropyToMnemonic as scureEntropyToMnemonic,
  generateMnemonic as scureGenerateMnemonic,
  mnemonicToEntropy as scureMnemonicToEntropy,
  mnemonicToSeedSync,
  validateMnemonic as scureValidateMnemonic,
} from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english";
import { ExtendedKey } from "./hd.js";
import type { Network } from "./networks.js";

/** A BIP39 wordlist: 2048 words. Defaults to English throughout this module. */
export type Wordlist = readonly string[];

/** The English BIP39 wordlist, used wherever `wordlist` is omitted. */
export const englishWordlist: Wordlist = english;

/** Generate a new mnemonic. `strength` is entropy bits (128–256, default 128). */
export function generateMnemonic(strength = 128, wordlist: Wordlist = english): string {
  return scureGenerateMnemonic(wordlist as string[], strength);
}

/** Validate a mnemonic's checksum and wordlist membership. */
export function validateMnemonic(mnemonic: string, wordlist: Wordlist = english): boolean {
  return scureValidateMnemonic(mnemonic, wordlist as string[]);
}

/** Recover the raw entropy behind a mnemonic. */
export function mnemonicToEntropy(mnemonic: string, wordlist: Wordlist = english): Uint8Array {
  return scureMnemonicToEntropy(mnemonic, wordlist as string[]);
}

/** Encode entropy (16–32 bytes, multiple of 4) as a mnemonic. */
export function entropyToMnemonic(entropy: Uint8Array, wordlist: Wordlist = english): string {
  return scureEntropyToMnemonic(entropy, wordlist as string[]);
}

/**
 * Expand a mnemonic (with optional passphrase) into the 64-byte BIP39 seed.
 *
 * Unchecked, by design: BIP39 seed derivation is defined for any string and does
 * not consult a wordlist. Use {@link mnemonicToMasterKey} to get the checksum
 * verified first.
 */
export function mnemonicToSeed(mnemonic: string, passphrase = ""): Uint8Array {
  return mnemonicToSeedSync(mnemonic, passphrase);
}

/**
 * Expand a mnemonic straight into a Decred master {@link ExtendedKey}.
 *
 * The mnemonic's checksum is verified first, against `wordlist` (English by
 * default). Because seed derivation is defined for *any* string, a typo'd or
 * mis-transcribed phrase would otherwise expand happily into a different,
 * valid-looking wallet — one of the classic ways to lose funds while every
 * operation appears to succeed.
 *
 * Pass the matching `wordlist` for a non-English phrase; validating a Spanish
 * mnemonic against the English list would reject a perfectly good one. Use
 * {@link mnemonicToSeed} directly if you specifically want the unchecked
 * primitive.
 */
export function mnemonicToMasterKey(
  mnemonic: string,
  network: Network,
  passphrase = "",
  wordlist: Wordlist = english,
): ExtendedKey {
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error(
      "bip39: invalid mnemonic (bad checksum, or a word not in the wordlist — pass the " +
        "matching wordlist for a non-English phrase)",
    );
  }
  return ExtendedKey.fromSeed(mnemonicToSeed(mnemonic, passphrase), network);
}
