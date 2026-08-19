/**
 * Typed errors.
 *
 * Everything this library throws is a {@link DcrError} carrying a stable
 * {@link DcrErrorCode}. Without one, the only way to tell a mistyped address from
 * a right-address-wrong-network paste is to match on prose — which is not part of
 * any API, breaks the moment a message is reworded, and cannot express the cases
 * that share wording. The tests in this repository had exactly that problem.
 *
 * ```ts
 * try {
 *   addressToScript(pasted, mainnet);
 * } catch (e) {
 *   if (hasErrorCode(e, "bad-checksum")) showTypoHelp();
 *   else if (hasErrorCode(e, "wrong-network")) showWrongNetworkHelp();
 *   else throw e;
 * }
 * ```
 *
 * Codes are the stable part; messages are for humans and may be reworded.
 */

/**
 * What went wrong, as a value rather than a sentence.
 *
 * Grouped by concern. New codes may be added in a minor release, so treat an
 * unrecognised one as a generic failure rather than assuming the set is closed.
 */
export type DcrErrorCode =
  // --- Encoding and parsing ---
  /** A character outside the base58 alphabet. */
  | "invalid-base58"
  /** base58check or WIF checksum did not match. Usually a typo. */
  | "bad-checksum"
  /** Input longer than the format allows; rejected before the quadratic decode. */
  | "input-too-long"
  /** A field or payload was not the required size. */
  | "bad-length"
  /** A varint that could have been encoded in fewer bytes (dcrd's ErrNonCanonicalVarInt). */
  | "non-canonical-varint"
  /** Ran off the end of the input while reading. */
  | "unexpected-end"
  /** Input parsed, but bytes remained after it. */
  | "trailing-bytes"

  // --- Keys ---
  /** Not a valid private scalar (zero, or out of range for the suite's group order). */
  | "invalid-private-key"
  /** Wrong length or prefix, or not a point on the curve. */
  | "invalid-public-key"

  // --- Addresses ---
  /** The two-byte version prefix belongs to no known network and kind. */
  | "unknown-prefix"
  /** Well-formed, but for a different network than the one required. */
  | "wrong-network"
  /** A signature-suite identifier this library does not support. */
  | "unsupported-signature-type"

  // --- HD keys ---
  /** Cannot derive a hardened child from a public key. */
  | "hardened-from-public"
  /** The derived child is invalid; retry the next index (BIP32 says this is ~2^-127). */
  | "invalid-child"
  /** Refused to derive past the depth a single byte can serialize. */
  | "max-depth"
  /** A derivation path that does not parse. */
  | "invalid-path"
  /** A private-key operation was asked of a public (neutered) key. */
  | "not-a-private-key"
  /** Extended-key version bytes matching no known network. */
  | "unknown-version"
  /** Mnemonic failed its checksum, or used a word outside the wordlist. */
  | "invalid-mnemonic"

  // --- Scripts and signing ---
  /** A script whose data pushes do not tokenize (dcrd's checkScriptParses). */
  | "malformed-script"
  /** A signature hash type dcrd would not accept, or one wider than a byte. */
  | "invalid-hash-type"
  /** A push above MaxScriptElementSize, which dcrd can never execute. */
  | "element-too-large"

  // --- Values ---
  /** A numeric argument outside its permitted range. */
  | "out-of-range"
  /** A numeric argument that was not an integer (includes NaN and Infinity). */
  | "not-an-integer"
  /** A malformed or unrepresentable amount. */
  | "invalid-amount"
  /** A required argument was missing or of the wrong shape. */
  | "invalid-argument";

/**
 * Identity that survives duplicate copies of this package.
 *
 * A dual ESM+CJS build can be loaded twice in one process: Node's exports map
 * hands `import` the ESM bundle and `require` the CJS one, and bundlers land in
 * the same place resolving `module` for application code and `main` for a
 * CommonJS dependency. Each copy defines its own class, so `instanceof` is false
 * across them. A registry symbol is the same value in every copy, and in every
 * realm.
 */
const BRAND = Symbol.for("dcr-ts.DcrError");

/** Every error this library throws. */
export class DcrError extends Error {
  override readonly name = "DcrError";

  constructor(
    /** Stable, machine-readable. Branch on this, not on {@link message}. */
    readonly code: DcrErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    // Not a class field: keeping it off the declared shape keeps the two builds'
    // `.d.ts` types mutually assignable, and keeps it off `Object.keys`.
    Object.defineProperty(this, BRAND, { value: true });
  }
}

/**
 * True when `e` is a {@link DcrError}, including one thrown by another copy of
 * this package loaded into the same process.
 */
export function isDcrError(e: unknown): e is DcrError {
  return e instanceof DcrError || (typeof e === "object" && e !== null && BRAND in e);
}

/**
 * True when `e` is a {@link DcrError} with this code.
 *
 * Safe on an `unknown` from a `catch`, so it needs no type guard at the call site.
 */
export function hasErrorCode(e: unknown, code: DcrErrorCode): boolean {
  return isDcrError(e) && e.code === code;
}

/** Construct a {@link DcrError}, prefixing `message` with the operation name. */
export function err(code: DcrErrorCode, who: string, message: string): DcrError {
  return new DcrError(code, `${who}: ${message}`);
}
