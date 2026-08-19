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
import { err } from "./errors.js";
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

/** The five word counts BIP39 defines. Anything else is not a mnemonic. */
const MNEMONIC_WORD_COUNTS: readonly number[] = [12, 15, 18, 21, 24];

/**
 * Throw unless `mnemonic` is a string.
 *
 * Separated from the phrase checks because it is a different fault with a
 * different remedy: `@scure` reports it as the same untyped throw as a bad
 * checksum, and folding the two together told a caller who passed a number that
 * their checksum was wrong.
 */
function assertMnemonicString(mnemonic: string, who: string): void {
  if (typeof mnemonic !== "string") {
    throw err("invalid-argument", who, `mnemonic must be a string, got ${typeof mnemonic}`);
  }
}

/**
 * Throw unless `wordlist` holds the 2048 words BIP39 requires.
 *
 * `Wordlist` is `readonly string[]`, so a list of the wrong size type-checks
 * fine — and this module invites callers to bring their own. `@scure` rejects it
 * with a plain `Error`, which would escape the typed-error contract.
 */
function assertWordlist(wordlist: Wordlist, who: string): void {
  if (wordlist.length !== 2048) {
    throw err("invalid-argument", who, `wordlist must hold 2048 words, got ${wordlist.length}`);
  }
}

/** Generate a new mnemonic. `strength` is entropy bits (128–256, default 128). */
export function generateMnemonic(strength = 128, wordlist: Wordlist = english): string {
  // `@scure` also rejects everything outside this set, but two layers down, as a
  // plain `Error` about a byte length the caller never named.
  if (!Number.isInteger(strength) || strength < 128 || strength > 256 || strength % 32 !== 0) {
    throw err(
      Number.isInteger(strength) ? "out-of-range" : "not-an-integer",
      "generateMnemonic",
      `strength must be 128, 160, 192, 224 or 256 bits, got ${strength}`,
    );
  }
  assertWordlist(wordlist, "generateMnemonic");
  return scureGenerateMnemonic(wordlist as string[], strength);
}

/** Validate a mnemonic's checksum and wordlist membership. */
export function validateMnemonic(mnemonic: string, wordlist: Wordlist = english): boolean {
  return scureValidateMnemonic(mnemonic, wordlist as string[]);
}

/** Recover the raw entropy behind a mnemonic. */
export function mnemonicToEntropy(mnemonic: string, wordlist: Wordlist = english): Uint8Array {
  assertMnemonicString(mnemonic, "mnemonicToEntropy");
  assertWordlist(wordlist, "mnemonicToEntropy");
  // Every remaining failure — word count, unknown word, checksum — is one code to
  // the caller, so catching is enough and costs nothing; pre-validating would
  // decode twice. `@scure`'s own message is worth discarding: for an unknown word
  // it inlines the whole 2048-word list.
  try {
    return scureMnemonicToEntropy(mnemonic, wordlist as string[]);
  } catch {
    throw err(
      "invalid-mnemonic",
      "mnemonicToEntropy",
      "bad checksum, wrong word count, or a word not in the wordlist — pass the " +
        "matching wordlist for a non-English phrase",
    );
  }
}

/** Encode entropy (16–32 bytes, multiple of 4) as a mnemonic. */
export function entropyToMnemonic(entropy: Uint8Array, wordlist: Wordlist = english): string {
  if (entropy.length < 16 || entropy.length > 32 || entropy.length % 4 !== 0) {
    throw err(
      "bad-length",
      "entropyToMnemonic",
      `entropy must be 16–32 bytes and a multiple of 4, got ${entropy.length}`,
    );
  }
  assertWordlist(wordlist, "entropyToMnemonic");
  return scureEntropyToMnemonic(entropy, wordlist as string[]);
}

/**
 * Expand a mnemonic (with optional passphrase) into the 64-byte BIP39 seed.
 *
 * Checksum-unchecked, by design: derivation does not consult a wordlist, so any
 * phrase of a legal length expands whether or not its words are in a list and
 * whether or not its checksum holds. Use {@link mnemonicToMasterKey} to get the
 * checksum verified first. The word count *is* enforced: BIP39 is defined only
 * for 12, 15, 18, 21 or 24 words.
 *
 * Both failures are checked here rather than caught from `@scure`, and the two
 * checks are exhaustive: `mnemonicToSeedSync` reaches the caller's input only
 * through `nfkd`, which rejects a non-string, and `normalize`, which rejects a
 * word count outside the five. Its salt is `"mnemonic" + passphrase`, a
 * concatenation that always yields a string, and its PBKDF2 parameters are
 * constants — so nothing else in it can throw. Catching instead would report
 * `invalid-mnemonic` for a future `@scure` failure that has nothing to do with
 * the mnemonic, which is the one direction that wastes the most debugging time.
 */
export function mnemonicToSeed(mnemonic: string, passphrase = ""): Uint8Array {
  assertMnemonicString(mnemonic, "mnemonicToSeed");
  // NFKD before counting, and split on a single space, because that is what
  // `@scure` does: normalization can *create* a word boundary, since it maps a
  // no-break space to a plain one.
  const words = mnemonic.normalize("NFKD").split(" ").length;
  if (!MNEMONIC_WORD_COUNTS.includes(words)) {
    throw err(
      "invalid-mnemonic",
      "mnemonicToSeed",
      `a mnemonic is 12, 15, 18, 21 or 24 words, got ${words}`,
    );
  }
  return mnemonicToSeedSync(mnemonic, passphrase);
}

/**
 * Expand a mnemonic straight into a Decred master {@link ExtendedKey}.
 *
 * The mnemonic's checksum is verified first, against `wordlist` (English by
 * default). Because seed derivation consults no wordlist, a typo'd or
 * mis-transcribed phrase of the right length would otherwise expand happily into
 * a different, valid-looking wallet — one of the classic ways to lose funds while
 * every operation appears to succeed.
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
  // `validateMnemonic` answers `false` for a non-string rather than throwing, so
  // without this the message below would blame the checksum for a type error.
  assertMnemonicString(mnemonic, "mnemonicToMasterKey");
  assertWordlist(wordlist, "mnemonicToMasterKey");
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw err(
      "invalid-mnemonic",
      "mnemonicToMasterKey",
      "bad checksum, or a word not in the wordlist — pass the matching wordlist " +
        "for a non-English phrase",
    );
  }
  return ExtendedKey.fromSeed(mnemonicToSeed(mnemonic, passphrase), network);
}
