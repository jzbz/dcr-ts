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
	big := make([]byte, 72)
	for i := range big {
		big[i] = byte(i)
	}
	inputs = append(inputs, big)
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
		addrs[name] = map[string]interface{}{
			"p2pkh":           a.String(),
			"p2pkh_payload":   hx(base58.Decode(a.String())),
			"p2pkh_script":    hx(script),
			"p2sh":            sa.String(),
			"p2sh_payload":    hx(base58.Decode(sa.String())),
			"p2sh_scriptHash": hx(sh),
			"p2sh_script":     hx(p2shScript),
			"pubkeyAddr":      pa.String(),
		}
		wif, err := dcrutil.NewWIF(priv.Serialize(), p.PrivateKeyID, dcrec.STEcdsaSecp256k1)
		ck(err)
		wifs[name] = map[string]string{
			"wif":         wif.String(),
			"wif_payload": hx(base58.Decode(wif.String())),
		}
	}
	keyOut["addresses"] = addrs
	keyOut["wif"] = wifs
	out["keys"] = keyOut

	// ---- HD keys (BIP32 Decred) ----
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
		"serialized": hx(fullSer),
		"prefixSer":  hx(noWitnessSer),
		"witnessSer": hx(onlyWitnessSer),
		"txid":       tx.TxHash().String(),
		"txidFull":   tx.TxHashFull().String(),
		"subScript":  hx(subScript),
		"sigHashAll": hx(sigHash),
		"derSig":     hx(der),
		"sigScript":  hx(sigScript),
		"outScript":  hx(outScript),
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
		"serialized": hx(tx2Full),
		"prefixSer":  hxMust(tx2.BytesPrefix()),
		"witnessSer": hxMust(tx2.BytesWitness()),
		"txid":       tx2.TxHash().String(),
		"subScript":  hx(outScript),
		"sighashes":  sighashes,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	ck(enc.Encode(out))
}

func hxMust(b []byte, err error) string {
	ck(err)
	return hx(b)
}
