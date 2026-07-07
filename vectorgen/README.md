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
