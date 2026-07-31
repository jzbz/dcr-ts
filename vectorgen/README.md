# vectorgen

Ground-truth test-vector generator for `dcr-ts`.

This is a small Go program that imports **dcrd itself** (`chaincfg`, `dcrutil`,
`txscript`, `wire`, `hdkeychain`, `crypto/blake256`, `dcrec/secp256k1`) and emits
a JSON file of known-answer vectors: BLAKE-256 digests, network constants,
base58/base58check, addresses, WIF, HD (`dprv`/`dpub`) keys, transaction
serializations, txids, and signature hashes for every hash-type variant.

The TypeScript implementation is written from the dcrd specification and then
checked against these vectors, so every consensus-critical byte format is pinned
to dcrd's own output rather than to a second hand-rolled reference.

## Regenerate

```bash
cd vectorgen
go run . > ../test/fixtures/dcrd-vectors.json
```

Requires Go and network access to fetch the dcrd modules (pinned in `go.sum`).
The generated `test/fixtures/dcrd-vectors.json` is committed, so running the
TypeScript test suite does **not** require Go.

CI runs this and fails on any diff against the committed file, so the fixture
cannot drift from what dcrd actually produces — and cannot be edited by hand to
make a failing test pass.

## What is deliberately pinned twice

Two vectors exist because a single-variant fixture cannot see the defect they
guard against:

- **`hd.leadingZero`** — dcrd's `hdkeychain.Child` strips leading zero bytes from
  a derived private key and carries the shortened key into the next hardened
  HMAC; `ChildBIP32Std` follows BIP32 strictly. Both are emitted. The difference
  only shows below a key with a leading zero byte (~1 seed in 128 on a BIP44
  path), and it is invisible in that key's own extended-key string because dcrd
  pads it back to 32 bytes — so only its hardened descendants diverge.
- **`txNullWitness`** — built from `wire.NewTxIn` rather than an explicit
  `TxIn`, so the null witness sentinels come from dcrd instead of from this
  file. `NullBlockHeight` is `0` while `NullBlockIndex` is `0xffffffff`; every
  other transaction here sets both fields explicitly, which would let a wrong
  default sit unnoticed.
