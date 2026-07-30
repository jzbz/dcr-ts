package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/decred/base58"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/sign"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/wire"
)

func hx(b []byte) string { return hex.EncodeToString(b) }

func blake256d(b []byte) []byte {
	h1 := blake256.Sum256(b)
	h2 := blake256.Sum256(h1[:])
	return h2[:]
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func ck(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

// A private key whose public key has an odd Y coordinate, so the odd-Y branch of
// the pay-to-pubkey address encoding gets a vector too. 6*G is the first small
// multiple with an odd Y; the main test key above is even-Y, so without this the
// encoder's odd-Y flag would never be exercised. Asserted in script.test.ts,
// which checks the serialized key really does start with 0x03.
const oddYPrivHex = "0000000000000000000000000000000000000000000000000000000000000006"

// An Ed25519 scalar. dcrutil.NewWIF runs the key through
// edwards.PrivKeyFromScalar for the Ed25519 suite, which rejects anything not in
// the subgroup, so the secp256k1 test key above cannot be reused here. The top
// nibble is cleared to keep the value below the Edwards group order (~2^252).
const edPrivHex = "0ef02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694"

// A seed whose m/44' child private key has a leading zero byte. dcrd's
// hdkeychain.Child strips that byte and carries the shortened key into the next
// hardened HMAC, so this seed's m/44'/42' differs between Child (what dcrwallet
// derives) and ChildBIP32Std (strict BIP32). Roughly 1 seed in 112 is affected
// on a BIP44 path; without a vector like this one the difference is invisible,
// because the leading-zero key's own dprv is identical either way.
const leadingZeroSeedHex = "7b03a6c5e4032241607f9ebddcfb1a39587796b5d4f31231506f8eadcceb0a29"

type NetConst struct {
	Name                 string `json:"name"`
	Net                  uint32 `json:"net"`
	NetworkAddressPrefix string `json:"networkAddressPrefix"`
	PubKeyAddrID         string `json:"pubKeyAddrID"`
	PubKeyHashAddrID     string `json:"pubKeyHashAddrID"`
	PKHEdwardsAddrID     string `json:"pkhEdwardsAddrID"`
	PKHSchnorrAddrID     string `json:"pkhSchnorrAddrID"`
	ScriptHashAddrID     string `json:"scriptHashAddrID"`
	PrivateKeyID         string `json:"privateKeyID"`
	HDPrivateKeyID       string `json:"hdPrivateKeyID"`
	HDPublicKeyID        string `json:"hdPublicKeyID"`
	SLIP0044CoinType     uint32 `json:"slip0044CoinType"`
	LegacyCoinType       uint32 `json:"legacyCoinType"`
}

func netConst(p *chaincfg.Params) NetConst {
	return NetConst{
		Name:                 p.Name,
		Net:                  uint32(p.Net),
		NetworkAddressPrefix: p.NetworkAddressPrefix,
		PubKeyAddrID:         hx(p.PubKeyAddrID[:]),
		PubKeyHashAddrID:     hx(p.PubKeyHashAddrID[:]),
		PKHEdwardsAddrID:     hx(p.PKHEdwardsAddrID[:]),
		PKHSchnorrAddrID:     hx(p.PKHSchnorrAddrID[:]),
		ScriptHashAddrID:     hx(p.ScriptHashAddrID[:]),
		PrivateKeyID:         hx(p.PrivateKeyID[:]),
		HDPrivateKeyID:       hx(p.HDPrivateKeyID[:]),
		HDPublicKeyID:        hx(p.HDPublicKeyID[:]),
		SLIP0044CoinType:     p.SLIP0044CoinType,
		LegacyCoinType:       p.LegacyCoinType,
	}
}

type HashVec struct {
	Input     string `json:"input"`
	Blake256  string `json:"blake256"`
	Blake256d string `json:"blake256d"`
	Hash160   string `json:"hash160"`
}

func main() {
	out := map[string]interface{}{}

	nets := map[string]*chaincfg.Params{
		"mainnet":  chaincfg.MainNetParams(),
		"testnet3": chaincfg.TestNet3Params(),
		"simnet":   chaincfg.SimNetParams(),
		"regnet":   chaincfg.RegNetParams(),
	}
	nc := map[string]NetConst{}
	for k, p := range nets {
		nc[k] = netConst(p)
	}
	out["networks"] = nc

	// ---- Hash vectors ----
	inputs := [][]byte{
		[]byte(""),
		[]byte("abc"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		mustHex("00"),
		mustHex("deadbeef"),
		mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
	}
	// BLAKE-256 padding boundaries. These cover every branch of the final-block
	// logic: rem <= 55 (everything fits in one block), rem == 55 (where the
	// 0x80 padding byte and the 0x01 domain bit merge into 0x81), rem 56..63
	// (a data block followed by a padding-only block), and exact multiples of
	// the 64-byte block, which take the zero-counter "nullt" path. The byte
	// pattern is (i*7)&0xff rather than i so that a transposition in the
	// message schedule cannot cancel out.
	for _, n := range []int{54, 55, 56, 57, 63, 64, 65, 72, 119, 127, 128, 129} {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i * 7)
		}
		inputs = append(inputs, b)
	}
	var hvs []HashVec
	for _, in := range inputs {
		s := blake256.Sum256(in)
		hvs = append(hvs, HashVec{
			Input:     hx(in),
			Blake256:  hx(s[:]),
			Blake256d: hx(blake256d(in)),
			Hash160:   hx(dcrutil.Hash160(in)),
		})
	}
	out["hashes"] = hvs
	out["sanity"] = map[string]string{
		"chainhash_abc": hx(chainhash.HashB([]byte("abc"))),
	}

	// ---- base58 / base58check (blake256d checksum, mainnet PKH prefix 073f) ----
	b58 := []map[string]string{}
	for _, in := range [][]byte{mustHex(""), mustHex("00"), mustHex("61"), mustHex("626262"), mustHex("516b6fcd0f"), mustHex("00010966776006953d5567439e5e39f86a0d273beed61967f6")} {
		b58 = append(b58, map[string]string{
			"input":       hx(in),
			"base58":      base58.Encode(in),
			"base58check": base58.CheckEncode(in, [2]byte{0x07, 0x3f}),
		})
	}
	out["base58"] = b58

	// ---- Keys / Addresses / WIF ----
	privHex := "eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694"
	priv := secp256k1.PrivKeyFromBytes(mustHex(privHex))
	pub := priv.PubKey()
	pkComp := pub.SerializeCompressed()
	pkUncomp := pub.SerializeUncompressed()
	pkh := dcrutil.Hash160(pkComp)

	keyOut := map[string]interface{}{
		"privHex":            privHex,
		"pubkeyCompressed":   hx(pkComp),
		"pubkeyUncompressed": hx(pkUncomp),
		"pubkeyHash160":      hx(pkh),
	}

	addrs := map[string]map[string]interface{}{}
	wifs := map[string]map[string]string{}
	for name, p := range nets {
		a, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(pkh, p)
		ck(err)
		_, script := a.PaymentScript()
		sh := dcrutil.Hash160(script)
		sa, err := stdaddr.NewAddressScriptHashV0FromHash(sh, p)
		ck(err)
		_, p2shScript := sa.PaymentScript()
		pa, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pub, p)
		ck(err)
		_, pubkeyScript := pa.PaymentScript()

		// The alternative signature suites. These share the P2PKH hash but pay
		// to OP_CHECKSIGALT with the suite pushed as a small integer, so both
		// the address prefix and the payment script have to be pinned.
		ed, err := stdaddr.NewAddressPubKeyHashEd25519V0(pkh, p)
		ck(err)
		_, edScript := ed.PaymentScript()
		sch, err := stdaddr.NewAddressPubKeyHashSchnorrSecp256k1V0(pkh, p)
		ck(err)
		_, schScript := sch.PaymentScript()

		// An odd-Y key, so the SIG_TYPE_ODD_FLAG branch of the pay-to-pubkey
		// address encoding is covered as well as the even-Y one above.
		oddPub := secp256k1.PrivKeyFromBytes(mustHex(oddYPrivHex)).PubKey()
		oddPa, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(oddPub, p)
		ck(err)
		_, oddPubkeyScript := oddPa.PaymentScript()

		addrs[name] = map[string]interface{}{
			"p2pkh":                 a.String(),
			"p2pkh_payload":         hx(base58.Decode(a.String())),
			"p2pkh_script":          hx(script),
			"p2pkh_ed25519":         ed.String(),
			"p2pkh_ed25519_script":  hx(edScript),
			"p2pkh_schnorr":         sch.String(),
			"p2pkh_schnorr_script":  hx(schScript),
			"p2sh":                  sa.String(),
			"p2sh_payload":          hx(base58.Decode(sa.String())),
			"p2sh_scriptHash":       hx(sh),
			"p2sh_script":           hx(p2shScript),
			"pubkeyAddr":            pa.String(),
			"pubkeyAddr_script":     hx(pubkeyScript),
			"pubkeyAddrOddY":        oddPa.String(),
			"pubkeyAddrOddY_script": hx(oddPubkeyScript),
		}

		// One WIF per signature suite, so decoding the suite byte is pinned for
		// all three values and not just ECDSA. Ed25519 needs its own scalar.
		w := map[string]string{}
		for _, v := range []struct {
			label  string
			key    []byte
			scheme dcrec.SignatureType
		}{
			{"", priv.Serialize(), dcrec.STEcdsaSecp256k1},
			{"_schnorr", priv.Serialize(), dcrec.STSchnorrSecp256k1},
			{"_ed25519", mustHex(edPrivHex), dcrec.STEd25519},
		} {
			wif, err := dcrutil.NewWIF(v.key, p.PrivateKeyID, v.scheme)
			ck(err)
			w["wif"+v.label] = wif.String()
			w["wif"+v.label+"_payload"] = hx(base58.Decode(wif.String()))
		}
		wifs[name] = w
	}
	keyOut["addresses"] = addrs
	keyOut["wif"] = wifs
	out["keys"] = keyOut

	// ---- HD keys (BIP32 Decred) ----
	mp0 := chaincfg.MainNetParams()
	seed := mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	hdOut := map[string]interface{}{"seedHex": hx(seed)}
	hdNets := map[string]map[string]interface{}{}
	for name, p := range nets {
		master, err := hdkeychain.NewMaster(seed, p)
		ck(err)
		masterPub := master.Neuter()
		coin := p.SLIP0044CoinType
		path := []uint32{
			hdkeychain.HardenedKeyStart + 44,
			hdkeychain.HardenedKeyStart + coin,
			hdkeychain.HardenedKeyStart + 0,
			0,
			0,
		}
		k := master
		for _, idx := range path {
			k, err = k.Child(idx)
			ck(err)
		}
		kPub := k.Neuter()
		childPkh := dcrutil.Hash160(k.SerializedPubKey())
		childAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(childPkh, p)
		ck(err)
		hdNets[name] = map[string]interface{}{
			"masterPriv":        master.String(),
			"masterPrivPayload": hx(base58.Decode(master.String())),
			"masterPub":         masterPub.String(),
			"masterPubPayload":  hx(base58.Decode(masterPub.String())),
			"childPath":         fmt.Sprintf("m/44'/%d'/0'/0/0", coin),
			"childPriv":         k.String(),
			"childPub":          kPub.String(),
			"childPubKeyHex":    hx(k.SerializedPubKey()),
			"childAddr":         childAddr.String(),
		}
	}
	hdOut["nets"] = hdNets

	// The leading-zero case, mainnet only. `Child` is dcrd's Decred variant and
	// is what dcrwallet uses for the whole wallet path; `ChildBIP32Std` is
	// strict BIP32. They agree everywhere except below a private key with a
	// leading zero byte, so pinning both is what keeps the two apart.
	lzSeed := mustHex(leadingZeroSeedHex)
	lzMaster, err := hdkeychain.NewMaster(lzSeed, mp0)
	ck(err)
	lzPath := []uint32{
		hdkeychain.HardenedKeyStart + 44,
		hdkeychain.HardenedKeyStart + mp0.SLIP0044CoinType,
		hdkeychain.HardenedKeyStart + 0,
		0,
		0,
	}
	lzLegacy, lzStrict := lzMaster, lzMaster
	for _, idx := range lzPath {
		lzLegacy, err = lzLegacy.Child(idx)
		ck(err)
		lzStrict, err = lzStrict.ChildBIP32Std(idx)
		ck(err)
	}
	lzMid, err := lzMaster.Child(hdkeychain.HardenedKeyStart + 44)
	ck(err)
	lzMidPriv, err := lzMid.SerializedPrivKey()
	ck(err)
	lzLegacyPkh := dcrutil.Hash160(lzLegacy.SerializedPubKey())
	lzLegacyAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(lzLegacyPkh, mp0)
	ck(err)
	lzStrictPkh := dcrutil.Hash160(lzStrict.SerializedPubKey())
	lzStrictAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(lzStrictPkh, mp0)
	ck(err)
	hdOut["leadingZero"] = map[string]interface{}{
		"seedHex": leadingZeroSeedHex,
		"network": mp0.Name,
		"path":    fmt.Sprintf("m/44'/%d'/0'/0/0", mp0.SLIP0044CoinType),
		// The intermediate key that triggers it, and the proof that its own
		// serialization is NOT what differs: dcrd pads it back to 32 bytes.
		"m44hPrivStripped": hx(lzMidPriv),
		"m44hPrivLen":      len(lzMidPriv),
		"m44hXprv":         lzMid.String(),
		// Decred variant (dcrd Child / dcrwallet) — this is what dcr-ts must match.
		"childPriv": lzLegacy.String(),
		"childPub":  lzLegacy.Neuter().String(),
		"childAddr": lzLegacyAddr.String(),
		// Strict BIP32 (dcrd ChildBIP32Std) — the opt-in variant.
		"childPrivBip32Std": lzStrict.String(),
		"childPubBip32Std":  lzStrict.Neuter().String(),
		"childAddrBip32Std": lzStrictAddr.String(),
	}
	out["hd"] = hdOut

	// ---- Transaction / sighash / signing ----
	mp := chaincfg.MainNetParams()
	prevHash, err := chainhash.NewHashFromStr("c672c1c5d15e58b9a5f1b6e2d3f4e5c6b7a8091011121314151617181920212a")
	ck(err)
	tx := wire.NewMsgTx()
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: 0, Tree: wire.TxTreeRegular},
		Sequence:         wire.MaxTxInSequenceNum,
		ValueIn:          100000000,
		BlockHeight:      123456,
		BlockIndex:       2,
	})
	outAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(pkh, mp)
	ck(err)
	_, outScript := outAddr.PaymentScript()
	tx.AddTxOut(&wire.TxOut{Value: 60000000, Version: 0, PkScript: outScript})
	tx.AddTxOut(&wire.TxOut{Value: 39990000, Version: 0, PkScript: outScript})
	tx.LockTime = 0
	tx.Expiry = 0

	fullSer, err := tx.Bytes()
	ck(err)
	noWitnessSer, err := tx.BytesPrefix()
	ck(err)
	onlyWitnessSer, err := tx.BytesWitness()
	ck(err)
	subScript := outScript
	sigHash, err := txscript.CalcSignatureHash(subScript, txscript.SigHashAll, tx, 0, nil)
	ck(err)
	sigScript, err := sign.SignatureScript(tx, 0, subScript, txscript.SigHashAll, priv.Serialize(), dcrec.STEcdsaSecp256k1, true)
	ck(err)
	sig := ecdsa.Sign(priv, sigHash)
	der := sig.Serialize()

	out["tx"] = map[string]interface{}{
		"serialized":  hx(fullSer),
		"prefixSer":   hx(noWitnessSer),
		"witnessSer":  hx(onlyWitnessSer),
		"txid":        tx.TxHash().String(),
		"txidWitness": tx.TxHashWitness().String(),
		"txidFull":    tx.TxHashFull().String(),
		"subScript":   hx(subScript),
		"sigHashAll":  hx(sigHash),
		"derSig":      hx(der),
		"sigScript":   hx(sigScript),
		"outScript":   hx(outScript),
	}

	// ---- A transaction built from wire.NewTxIn defaults ----
	// NewTxIn is what pins the null witness sentinels: BlockHeight is
	// NullBlockHeight (0x00000000, "references the genesis block") while
	// BlockIndex is NullBlockIndex (0xffffffff). Every other transaction in this
	// file sets both explicitly, which is exactly why a wrong default sentinel
	// would otherwise never be caught.
	txNull := wire.NewMsgTx()
	txNull.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: *prevHash, Index: 0, Tree: wire.TxTreeRegular},
		wire.NullValueIn, nil))
	txNull.AddTxOut(&wire.TxOut{Value: 50000000, Version: 0, PkScript: outScript})
	out["txNullWitness"] = map[string]interface{}{
		"nullValueIn":     fmt.Sprintf("%d", wire.NullValueIn),
		"nullBlockHeight": fmt.Sprintf("%d", wire.NullBlockHeight),
		"nullBlockIndex":  fmt.Sprintf("%d", wire.NullBlockIndex),
		"maxSequence":     fmt.Sprintf("%d", uint32(wire.MaxTxInSequenceNum)),
		"serialized":      hxMust(txNull.Bytes()),
		"prefixSer":       hxMust(txNull.BytesPrefix()),
		"witnessSer":      hxMust(txNull.BytesWitness()),
		"txid":            txNull.TxHash().String(),
		"txidWitness":     txNull.TxHashWitness().String(),
		"txidFull":        txNull.TxHashFull().String(),
	}

	// ---- A transaction large enough to exercise multi-byte varints ----
	// 300 outputs pushes the output count past 0xfd (so the varint takes the
	// 3-byte form) and the serialization well past the writer's initial 256-byte
	// buffer, neither of which any other vector reaches.
	txBig := wire.NewMsgTx()
	txBig.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: 1, Tree: wire.TxTreeRegular},
		Sequence:         wire.MaxTxInSequenceNum,
		ValueIn:          1000000000, BlockHeight: 7, BlockIndex: 8,
	})
	for i := 0; i < 300; i++ {
		txBig.AddTxOut(&wire.TxOut{Value: int64(1000 + i), Version: uint16(i % 3), PkScript: outScript})
	}
	out["txBig"] = map[string]interface{}{
		"numOutputs":  300,
		"serialized":  hxMust(txBig.Bytes()),
		"prefixSer":   hxMust(txBig.BytesPrefix()),
		"txid":        txBig.TxHash().String(),
		"txidWitness": txBig.TxHashWitness().String(),
		"txidFull":    txBig.TxHashFull().String(),
	}

	// ---- Multi-input/output tx with every sighash variant ----
	tx2 := wire.NewMsgTx()
	tx2.Version = 1
	ph0, _ := chainhash.NewHashFromStr("1111111111111111111111111111111111111111111111111111111111111111")
	ph1, _ := chainhash.NewHashFromStr("2222222222222222222222222222222222222222222222222222222222222222")
	tx2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *ph0, Index: 7, Tree: wire.TxTreeRegular},
		Sequence:         0xfffffffe, ValueIn: 500000000, BlockHeight: 200, BlockIndex: 1,
	})
	tx2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *ph1, Index: 1, Tree: wire.TxTreeStake},
		Sequence:         0xffffffff, ValueIn: 250000000, BlockHeight: 201, BlockIndex: 4,
	})
	tx2.AddTxOut(&wire.TxOut{Value: 100000000, Version: 0, PkScript: outScript})
	tx2.AddTxOut(&wire.TxOut{Value: 200000000, Version: 0, PkScript: outScript})
	tx2.AddTxOut(&wire.TxOut{Value: 449990000, Version: 0, PkScript: outScript})
	tx2.LockTime = 500000
	tx2.Expiry = 600000

	tx2Full, _ := tx2.Bytes()
	sigTypes := map[string]txscript.SigHashType{
		"all":        txscript.SigHashAll,
		"none":       txscript.SigHashNone,
		"single":     txscript.SigHashSingle,
		"all_acp":    txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
		"none_acp":   txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
		"single_acp": txscript.SigHashSingle | txscript.SigHashAnyOneCanPay,
	}
	sighashes := map[string]map[string]string{}
	for _, idx := range []int{0, 1} {
		for name, ht := range sigTypes {
			sh, err := txscript.CalcSignatureHash(outScript, ht, tx2, idx, nil)
			ck(err)
			key := fmt.Sprintf("in%d", idx)
			if sighashes[key] == nil {
				sighashes[key] = map[string]string{}
			}
			sighashes[key][name] = hx(sh)
		}
	}
	out["tx2"] = map[string]interface{}{
		"serialized":  hx(tx2Full),
		"prefixSer":   hxMust(tx2.BytesPrefix()),
		"witnessSer":  hxMust(tx2.BytesWitness()),
		"txid":        tx2.TxHash().String(),
		"txidWitness": tx2.TxHashWitness().String(),
		"txidFull":    tx2.TxHashFull().String(),
		"subScript":   hx(outScript),
		"sighashes":   sighashes,
	}

	// ---- Signature-hash edge cases ----
	// A 3-in/3-out transaction so SigHashSingle can be taken at the LAST output
	// index (idx == len(TxOut)-1), which tx2 cannot reach with only 2 inputs.
	// Also covers hash types with bits dcrd's calcSignatureHash leaves undefined:
	// it still produces a hash for them (the prefix logic treats anything that is
	// not None/Single as All), even though the script engine's
	// CheckHashTypeEncoding rejects them at verification time.
	tx3 := wire.NewMsgTx()
	for i := 0; i < 3; i++ {
		ph, err := chainhash.NewHashFromStr(fmt.Sprintf("%064x", 0xa0+i))
		ck(err)
		tx3.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: *ph, Index: uint32(i), Tree: wire.TxTreeRegular},
			Sequence:         uint32(0xfffffff0 + i), ValueIn: int64(100000000 * (i + 1)),
			BlockHeight: uint32(300 + i), BlockIndex: uint32(i),
		})
		tx3.AddTxOut(&wire.TxOut{Value: int64(10000000 * (i + 1)), Version: 0, PkScript: outScript})
	}
	tx3.LockTime = 12345
	tx3.Expiry = 23456

	tx3Hashes := map[string]map[string]string{}
	for _, ht := range []txscript.SigHashType{
		txscript.SigHashAll, txscript.SigHashNone, txscript.SigHashSingle,
		txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
		txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
		txscript.SigHashSingle | txscript.SigHashAnyOneCanPay,
		0x00, 0x04, 0x05, 0x1f, 0x84, 0xff,
	} {
		key := fmt.Sprintf("0x%02x", uint8(ht))
		tx3Hashes[key] = map[string]string{}
		for idx := 0; idx < 3; idx++ {
			sh, err := txscript.CalcSignatureHash(outScript, ht, tx3, idx, nil)
			ck(err)
			tx3Hashes[key][fmt.Sprintf("in%d", idx)] = hx(sh)
		}
	}
	out["tx3"] = map[string]interface{}{
		"serialized": hxMust(tx3.Bytes()),
		"txid":       tx3.TxHash().String(),
		"subScript":  hx(outScript),
		"sighashes":  tx3Hashes,
	}

	// The SigHashAll prefix hash is the plain transaction prefix hash, because
	// SigHashSerializePrefix (1) and TxSerializeNoWitness (1) are the same value
	// and the serialized bodies are identical. dcrd exposes this as the
	// cachedPrefix argument to CalcSignatureHash; pinning it lets a signer reuse
	// one prefix hash across every input instead of recomputing it per input.
	out["sighashPrefixReuse"] = map[string]interface{}{
		"tx3PrefixHash": tx3.TxHash().String(),
		"note":          "blake256(prefixSer) == the prefix hash inside a SigHashAll sighash",
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	ck(enc.Encode(out))
}

func hxMust(b []byte, err error) string {
	ck(err)
	return hx(b)
}
