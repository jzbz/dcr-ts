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

- **Ed25519 public keys decode the way dcrd decodes them.** `@noble` enforces the
  RFC 8032 range `Y < P`; dcrd's `edwards.ParsePubKey` goes through AGL's
  `edwards25519`, which masks off only the sign bit, so an encoding of `Y+P` names
  the same point and is accepted. 23 byte strings — every one of them, since `Y+P`
  must fit in 255 bits, bounding `Y` at 18 — decoded as a valid pay-to-pubkey
  address in dcrd and threw `invalid-public-key` here, on both the decoder and the
  encoder. Only acceptance widens; the one encoding dcrd does reject in that
  range, `X = 0` with the sign bit set, is still rejected. Every such key is the
  identity, an order-4 point, or a point of unknown discrete log, so no address
  built from one is spendable — this is a parity fix, not a security one.
  `@noble/curves` moves to `^1.9.2`, the first release whose types declare the
  ZIP-215 argument; nothing upgrades, since the installed 1.9.7 already satisfies
  the old range.

- **`encodeWif` validated nothing about the signature-suite argument.** It went
  straight into the payload byte, and a `Uint8Array` store coerces rather than
  rejects: `256` became suite 0, `-1` became suite 255, `1.5` became suite 1, and
  the enum *name* `"Ed25519"` became suite 0 — a well-formed WIF for a suite the
  caller never asked for, or one this library's own `decodeWif` refuses. dcrd's
  `NewWIF` errors on an unsupported scheme. `decodeWif` continues to reject
  unknown suite bytes, which is a **deliberate divergence**: dcrd's `DecodeWIF`
  has no default arm and accepts them as a WIF holding a nil private key, whose
  own `String()` is not a WIF.
- **`decodeWif` did not bound the Ed25519 scalar.** dcrd runs suite-1 keys through
  `edwards.PrivKeyFromScalar` in both `NewWIF` and `DecodeWIF`, which rejects zero
  and anything above the group order, so a zero-key or all-`ff` Ed25519 WIF
  decoded here and then failed to import anywhere else. Matched exactly, including
  dcrd's acceptance of a scalar equal to the order — the check there is
  `D.Cmp(N) > 0`. Both sides of the codec validate, because Ed25519 keys are 32
  uniform bytes against an order near 2^252: about 15 of every 16 random keys
  exceed it, so a decode-only check would have left `encodeWif` minting strings
  its own decoder rejects. The secp256k1 suites stay unchecked, as in dcrd, whose
  `PrivKeyFromBytes` cannot fail — it reduces mod n and discards the overflow.

- **A zero HMAC left half is an invalid child on both derivation paths.** dcrd's
  `hdkeychain` rejects `IL` when `overflow || ilModN.IsZero()`, before it splits
  on private-vs-public, so a zero `IL` invalidates the index for either. This
  library applied the zero check only on the public path; on the private path the
  derived child would have been byte-identical to its parent, silently diverging
  every descendant from what dcrd derives. A zero `IL` is a 2^-256 HMAC output, so
  nothing observable changes — it removes an asymmetry between two sibling
  functions in `keys.ts`. Note this is stricter than BIP32 itself, which permits
  `IL == 0` on the private path.

- **`Transaction.version` was masked to 16 bits instead of range-checked.**
  `serialize()` packed it as `(serType << 16) | (version & 0xffff)`, so 65537
  serialized as version 1, -1 as 65535 and `NaN` as 0 — and the txid and every
  signature committed to a version the caller never asked for, with nothing
  raising. The same mask sat in both signature-hash words, so `calcSignatureHash`
  could sign a silently-wrong version without `serialize()` ever being called.
  All three now go through one guard. `TxOutput.version`, the other 16-bit field
  in the same serializer, has always thrown on these inputs via `Writer.u16`.
  dcrd cannot express the case at all — `wire.MsgTx.Version` is a uint16 — so no
  byte changes for any legal version. Decoding stays permissive, matching dcrd's
  own `uint16(version & 0xffff)`.

### Fixed — the typed-error contract at foreign boundaries

The contract above held at every one of this library's own `throw` sites, but not
where a builtin or a dependency threw first. Four boundaries leaked, so a caller
branching on `hasErrorCode` could not classify the failure.

- **`Writer.varInt` threw a bare `RangeError`.** A non-integer `number` reached
  `BigInt(v)`, which the engine rejects itself. It is checked first now, with the
  same `not-an-integer` code `checkUint` already used one screen up.
- **`signHash` and `verifyHash` accepted a hash of any length, and scalar
  reduction is not injective.** A short hash signs identically to itself
  left-padded with zeros to 32 bytes — `signHash(h31)` and
  `signHash(0x00 ‖ h31)` are the same DER bytes — and a long hash is silently
  truncated to its first 32. A caller passing a mis-sliced buffer got a valid
  signature committing to a *different* message than the one they held, with
  nothing raising, and `verifyHash` returned `true` for the short form against a
  signature over the padded one. Both now require exactly 32 bytes. `@noble` and
  dcrd agree byte-for-byte on every one of these malformed cases, so this is not
  a behavioural divergence but a hazard both share; dcrd needs no guard because
  `chainhash.Hash` is `[32]byte` and the only thing reaching `ecdsa.Sign` is a
  BLAKE-256 output, whereas a `Uint8Array` carries no length in its type.

- **The signing paths let `@noble`'s own `Error` escape.** `signHash`,
  `publicKeyFromPrivate`, `rawTxInSignature`, `signatureScript`, `signP2PKHInput`
  and `signP2PKHInputs` passed a zeroed, over-order or wrong-length private key
  straight through. They throw `invalid-private-key` or `bad-length` via the new
  `assertPrivateKey(key, who)`, exported alongside `assertPubKey`. This is a
  deliberate divergence: dcrd's `secp256k1.PrivKeyFromBytes` cannot fail — it
  reduces mod n and left-pads a short slice — so a zero key there yields a real
  DER signature under an all-zero-X public key, and a 31-byte key is silently
  padded and signed. Rejecting is the safer contract for a signing API.
- **The mnemonic wrappers let `@scure`'s errors escape.** `generateMnemonic`,
  `entropyToMnemonic`, `mnemonicToEntropy` and `mnemonicToSeed` now report
  `out-of-range`/`not-an-integer` for a bad strength, `bad-length` for bad entropy
  size, `invalid-argument` for a wordlist that is not 2048 words, and
  `invalid-mnemonic` for the phrase itself. Wrapping also drops `@scure`'s message
  for an unknown word, which inlined the entire 2048-word list.
- **`mnemonicToSeed` was documented as unchecked and is not.** `@scure` enforces a
  word count of 12, 15, 18, 21 or 24 before the PBKDF2, so `mnemonicToSeed("hello")`
  always threw. Only the checksum and the wordlist go unchecked; the doc comment
  said "defined for any string" and now says what is actually true.

- **`isDcrError` and `hasErrorCode` no longer depend on class identity.** The dual
  ESM+CJS build can be loaded twice in one process — Node's exports map hands
  `import` the ESM bundle and `require` the CJS one, and bundlers land in the same
  place resolving `module` for application code and `main` for a CommonJS
  dependency — and `instanceof` is false across the two copies, so
  `hasErrorCode(e, "bad-checksum")` returned false for an error a CommonJS
  dependency threw. Both predicates now also accept a `Symbol.for("dcr-ts.DcrError")`
  brand, which is the same value in every copy and every realm.

### Documented — deliberate divergences from dcrd

Byte formats are not the whole contract: two implementations can agree on every
byte they emit and still disagree on what they accept. Four such divergences were
undocumented, which is the dangerous shape for a parity-targeted library — a
consumer assuming "accepted by dcr-ts ⇔ accepted by dcrd" had no way to know
otherwise. They are now stated in a README section and pinned by tests, so they
stay deliberate rather than becoming accidents.

- **An extended key whose version and key type disagree is refused.** dcrd's
  `NewKeyFromString` decides private-vs-public from `keyData[0]` and treats the
  version bytes only as a network tag, so a `dpub`-prefixed string wrapping
  `0x00 ‖ privkey32` parses there as a *private* key and re-serializes as `dprv`.
  Aligning was considered and rejected: it would make a string a user reads as
  public decode to a live private key. Related, and also documented:
  `ExtendedKey.fromString` takes no network and recognises all four, where dcrd
  requires `NetworkParams` and answers `ErrWrongNetwork`.
- **`Transaction.fromBytes` applies no input/output count caps**, where dcrd
  rejects counts over 780336 / 3728271. dcrd's caps bound an allocation it makes
  from the count before reading; nothing here is sized from a count, so the caps
  would bound nothing. Only blobs of ~43 MiB or larger differ, which are neither
  relayable nor valid. The caller-side sizing advice that does matter is now in
  SECURITY.md and on `fromBytes` itself.
- The WIF unknown-suite and private-key-rejection divergences recorded above are
  covered in the same section.

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
- The signing entry points and `publicKeyFromPrivate` require a 32-byte
  `Uint8Array`. A hex *string* used to reach `@noble` and sign successfully, off
  the typed API; it is rejected with `bad-length`.

### Added — typed errors

- **Every throw is now a `DcrError` carrying a stable `code`.** Previously all 88
  throw sites raised a bare `Error`, so the only way to tell a mistyped address
  from a right-address-wrong-network paste was to match on prose — which is not
  part of any API, breaks when a message is reworded, and cannot separate failures
  that happen to share wording. The tests had exactly that problem, and 44 of
  their assertions matched on message text.

  ```ts
  import { hasErrorCode } from "dcr-ts";

  try {
    addressToScript(pasted, mainnet);
  } catch (e) {
    if (hasErrorCode(e, "bad-checksum")) showTypoHelp();
    else if (hasErrorCode(e, "wrong-network")) showWrongNetworkHelp();
    else throw e;
  }
  ```

  `decodeAddress` now distinguishes `wrong-network` from `unknown-prefix`, which
  folding both into one prefix lookup had made impossible. Codes are the stable
  contract; messages remain human-readable and name the operation that failed.
  Exports `DcrError`, `DcrErrorCode`, `isDcrError` and `hasErrorCode`.

### Changed — packaging

- `npm run coverage` works: `@vitest/coverage-v8` is now a devDependency, and
  thresholds live in `vitest.config.ts` (currently 97.6% statements, 90.4%
  branches) so a real regression fails CI.
- The tarball no longer ships `src/`, which was unreachable — `exports` declares
  no subpath, so nothing could import it. It now carries `dist`, the README,
  SECURITY.md, CHANGELOG.md and the licence: 11 files.
- Dropped the `lint` script, which was a byte-identical duplicate of `typecheck`
  that CI never ran. Added `npm run vectors` for regenerating the fixture.
- Upgraded vitest to 3.2.7 and pinned vite to 6.x, clearing the critical
  advisories the old 2.x tree carried. Deliberately *not* vitest 4: it requires
  Node `^20 || ^22 || >=24`, and vite 7 requires `>=20.19`, either of which would
  quietly drop the Node 18 this package's `engines` field promises. 3.2.7 is above
  the advisory range (`<=3.2.5`) and still supports `^18.0.0`, so the security fix
  costs no supported runtime.
- The blocking `npm audit` gate is scoped with `--omit=dev`. Production
  dependencies are what a consumer installs, and a CVE in the test runner never
  reaches them, so letting dev-tool advisories break a library's CI only trains
  people to ignore the signal. Production dependencies audit clean; the full
  audit still runs for visibility, without failing.
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
