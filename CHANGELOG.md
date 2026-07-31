# Changelog

Notable changes per release. Dates are release dates; `Unreleased` is what is on
`master`.

This library has **not** been independently audited. See [SECURITY.md](SECURITY.md).

## Unreleased

### Fixed — consensus

- **HD derivation now matches dcrd and every real Decred wallet.** Hardened
  derivation followed strict BIP32, but Decred deliberately deviates: dcrd's
  `hdkeychain.Child` strips leading zero bytes from a derived private key and
  carries the shortened key into the next hardened HMAC, and dcrwallet uses that
  variant for the whole wallet path. For roughly **1 seed in 128** on a BIP44 path
  this library derived an entirely different wallet — a restored seed would show an
  empty wallet, and coins sent to a dcr-ts address would be invisible to any other
  wallet holding the same phrase. Verified against dcrd over 400 seeds.
  `deriveBip32Std` / `derivePathBip32Std` provide the strict form.
- **`NULL_BLOCK_HEIGHT` was `0xffffffff`; dcrd's `wire.NullBlockHeight` is `0`.**
  Only `NullBlockIndex` is `0xffffffff`. Every transaction built without an
  explicit `blockHeight` carried four wrong witness bytes and a wrong
  `TxHashWitness`/`TxHashFull`.
- **`pushData` emitted non-minimal pushes.** dcrd enforces minimal data pushes
  unconditionally in its script engine, with no verification flag gating it, so a
  single byte in `1..16` must use `OP_1..OP_16` and `0x81` must use `OP_1NEGATE`.
  Scripts built with the old output were unspendable. Pushes are also now capped at
  `MaxScriptElementSize` (2048).
- **`calcSignatureHash` accepted a `subScript` that does not parse.** dcrd's
  exported `CalcSignatureHash` gates on `checkScriptParses` first, so signing
  against a malformed script produced a signature over a message dcrd would refuse
  to compute.
- **`calcSignatureHash` accepted hash types wider than a byte.** The preimage
  commits to the hash type as a `uint32` while a signature script carries only its
  low byte, so `0x101` was committed in full and transmitted as `0x01` — the
  verifier recomputes a different hash and the signature can never verify. Signing
  is now restricted to the six values dcrd's `CheckHashTypeEncoding` accepts.

### Fixed — memory and validation

- **Parsed values no longer alias a caller's `Buffer`.** Node's `Buffer` overrides
  `slice()` to return a *view*, so `Reader.bytes`, `ExtendedKey.fromSerialized` and
  `extractHash160` aliased the caller's memory for the most common input type in
  Node. Reusing or zeroing that buffer rewrote an already-parsed transaction's txid
  and scripts, and destroyed a just-parsed extended key — so a caller correctly
  wiping a serialized key was the thing that broke it. `addInput`/`addOutput` now
  copy as well.
- **Public keys are validated before becoming addresses or output scripts.**
  `addressFromPubKey`, `pubKeyAddress` and `payToPubKeyScript` accepted any bytes,
  producing well-formed, valid-checksum, permanently unspendable results. The
  realistic way in: passing `privateKeyBytes()` where `publicKey()` was meant
  type-checks silently, because both are `Uint8Array`.
- **`verifyHash` is strictly DER and canonical.** `@noble`'s `verify` falls back to
  the 64-byte compact encoding, which dcrd's engine rejects — a co-signer emitting
  compact signatures passed local validation and then failed consensus.
- **`mnemonicToMasterKey` validates the mnemonic.** BIP39 seed derivation is
  defined for any string, so a typo'd phrase expanded into a different
  valid-looking wallet with every operation appearing to succeed.
  `mnemonicToSeed` remains the unchecked primitive.
- **`hardened()` no longer wraps.** For an argument at or above `2^31` it produced
  a *non*-hardened index, silently deriving from the wrong branch. `derive()` and
  `Writer.u8/u16/u32` likewise reject out-of-range values instead of coercing them,
  and `calcSignatureHash` rejects a non-integer input index (`NaN` slipped past both
  range checks and produced a hash committing the subScript to no input).

### Fixed — availability

- **base58 decoding is bounded before it runs.** It is quadratic in input length,
  and `isValidAddress` is exactly where untrusted input arrives: a 128 KB string
  blocked the event loop for ~6 seconds. `decodeAddress`, `decodeWif` and
  `ExtendedKey.fromString` now apply dcrd's own bounds (54, 54 and 113 characters);
  the same string costs 0.002 ms.

### Fixed — regressions introduced while fixing the above

Found by re-auditing the cumulative diff against dcrd rather than trusting the
suite, which passed throughout.

- **`deriveBip32Std` read the parent scalar wrong.** dcrd's `strictBIP32` flag
  governs only whether the newly derived *child* is stripped; the parent is always
  read as stored. Letting the requested variant suppress that made
  `derive(a).deriveBip32Std(b)` disagree with dcrd's `Child(a).ChildBIP32Std(b)`.
  Caught by 903 dcrd-generated mixed-variant cases (3 diverged, all at a
  strict-hardened step following a legacy one); zero divergences after the fix.
  Pure-variant paths — including every real wallet path — were never affected.
  The round-trip test had been asserting an equality dcrd does not have, so it was
  pinning the bug rather than catching it; it is replaced with `hd.mixedVariant`
  vectors that check the key after every step.
- **`fingerprint()` handed out a live view of the memoized identifier**, which
  `derive` passes into each child as its public `parentFingerprint`. One write
  corrupted the parent's cache, its own fingerprint, every sibling and every later
  child. `chainCode` and `parentFingerprint` are now copying getters, so nothing
  the class exposes aliases its internals — mutating `chainCode` also used to
  change what the key derived.

### Added

- `deriveBip32Std` / `derivePathBip32Std` — strict BIP32 derivation, mirroring
  dcrd's `ChildBIP32Std`. Note that from a given parent both variants produce the
  same extended key; the flag changes only that child's *own* children.
- `signP2PKHInputs` — signs several inputs reusing one prefix hash instead of
  recomputing it per input. This lowers the constant, not the exponent: the
  witness half still walks every input per call, so signing stays O(N²).
  `calcSignatureHash` takes an optional `cachedPrefix` from the new
  `sigHashPrefixAll`.
- `classifyScript` — returns *which* template matched along with the hash, which
  `extractHash160` discards; also recognises the two `OP_CHECKSIGALT` templates.
- **Pay-to-pubkey addresses for the Ed25519 and Schnorr signature suites.** dcrd
  accepts all three suites under one address ID, distinguished by the payload's
  first byte, so decoding only ECDSA meant `isValidAddress` reported a legitimate
  mainnet address as invalid. Adds `pubKeyEd25519Address`, `pubKeySchnorrAddress`
  and `payToPubKeyAltScript`, all pinned against dcrd. Ed25519 keys are validated
  as real curve points too — `@noble/curves` shares its field arithmetic with
  secp256k1, so this costs 0.13 KB of bundle.
- `DecodedAddress` is now a **discriminated union** on `kind`, so `hash` and
  `pubKey` exist exactly where they are valid. This removes the non-null
  assertions it previously forced on the library and on every consumer; narrowing
  on `kind` replaces them.
- Optional `wordlist` on every BIP39 entry point, so a non-English mnemonic is
  validated against its own list rather than English.
- `scriptParses`, `isSignableSigHashType`, `assertSignableSigHashType`,
  `assertCompressedPubKey`, `assertPubKey`, `copyOf`, `maxBase58Length`, and the
  `MAX_ADDRESS_LENGTH` / `MAX_WIF_LENGTH` / `MAX_EXTENDED_KEY_LENGTH` /
  `MAX_SCRIPT_ELEMENT_SIZE` bounds.

### Changed — performance

Measured against the previous build on one machine; every vector still matches
dcrd byte for byte.

| | |
|---|---|
| BLAKE-256 (inlined `G`, no BigInt counter) | **2.44x** — 232 MiB/s, from 0.6x behind `@noble` to 4x ahead |
| script builders | **7.5x** |
| `Writer.i64` / `Reader.i64` (DataView) | **4.2x** / **5.0x** |
| transaction serialize (1000 in/out) | 1.5x |
| watch-only address scan (cached parent point) | 1.26x |
| signature hashing across N inputs | 12–26x for N=50–1000; 1.7x end to end at N=250, since ECDSA dominates |

### Changed — breaking

`0.x`, so these land without a major bump. Ordered by how likely they are to
affect you.

- **HD derivation produces different hardened children** for ~1 seed in 128. This
  is the fix described above, not a regression: the new output is what dcrd and
  dcrwallet produce. Anything that persisted addresses derived by an earlier build
  must re-derive and check both variants.
- `addressToScript(address, network)` — `network` is now **required**. A payment
  script commits only to the 20-byte hash, so the network-agnostic form returned
  bytes identical to the mainnet address for the same hash: a pasted testnet
  address would pay whoever controls that hash on mainnet.
- `NULL_BLOCK_HEIGHT` changed from `0xffffffff` to `0`.
- `pushData` output changed for single-byte data (see above).
- `verifyHash` no longer accepts 64-byte compact signatures.
- `mnemonicToMasterKey` throws on an invalid mnemonic.
- `hardened()`, `derive()`, `Writer.u8/u16/u32`, `Reader.bytes` and
  `calcSignatureHash` throw on input they previously coerced.

### Changed — packaging

- `npm run coverage` works: `@vitest/coverage-v8` is now a devDependency, and
  thresholds live in `vitest.config.ts` (currently 97.6% statements, 90.4%
  branches) so a real regression fails CI.
- The tarball no longer ships `src/`, which was unreachable — `exports` declares
  no subpath, so nothing could import it. It now carries `dist`, the README,
  SECURITY.md, CHANGELOG.md and the licence: 11 files.
- Dropped the `lint` script, which was a byte-identical duplicate of `typecheck`
  that CI never ran. Added `npm run vectors` for regenerating the fixture.
- CI gains three jobs: coverage with thresholds, a package check that both module
  formats load and export the same symbols plus `npm pack --dry-run` and
  `npm audit`, and the fixture-drift check. The test matrix now includes Node 24.

### Fixed — test infrastructure

- **The committed fixture was not reproducible from its generator.** It carried
  four alternative-signature-suite vectors and twelve BLAKE-256 padding-boundary
  vectors that `vectorgen` never emitted, so the documented regeneration command
  deleted them and broke the suite — and the README's claim that every vector comes
  from a Go program importing dcrd was not true for those values. CI now
  regenerates the fixture and fails on any diff.
- Added dcrd ground truth for surfaces that had none: `TxHashWitness`, the null
  witness sentinels, a 300-output transaction (multi-byte varints and writer
  growth), `SigHashSingle` at the last output index, twelve hash types including
  the undefined ones, pay-to-pubkey scripts with an odd-Y key, one WIF per
  signature suite, and a seed chosen to make the two HD variants disagree.
- Fixture-driven loops are guarded with `nonEmpty()`; they previously reported
  green with zero assertions if a section went missing.
- Tests: 41 → 103.

## 0.1.0

Initial release.
