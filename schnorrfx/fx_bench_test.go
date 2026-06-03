// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schnorrfx

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
)

func benchSetup(b *testing.B) (*Fx, *TransferOutput, *TransferInput, *Credential, *TestTx) {
	sk, err := btcec.NewPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	pkBytes := schnorr.SerializePubKey(sk.PubKey())
	addrBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, err := ids.ToShortID(addrBytes)
	if err != nil {
		b.Fatal(err)
	}

	vm := &TestVM{
		Log:   log.NewNoOpLogger(),
	}
	vm.Clk.Set(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))

	fx := &Fx{}
	if err := fx.Initialize(vm); err != nil {
		b.Fatal(err)
	}
	_ = fx.Bootstrapping()
	_ = fx.Bootstrapped()

	txBytes := []byte("benchmark transaction bytes for BIP-340 Schnorr verify")
	digest := taggedDigest(utxoSignCtx, txBytes)
	sig, err := schnorr.Sign(sk, digest)
	if err != nil {
		b.Fatal(err)
	}
	var sigArr [SigLen]byte
	copy(sigArr[:], sig.Serialize())

	utx := &TestTx{UnsignedBytes: txBytes}
	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	in := &TransferInput{
		Amt:   1,
		Input: Input{SigIndices: []uint32{0}},
	}
	cred := &Credential{
		Sigs:    [][SigLen]byte{sigArr},
		PubKeys: [][]byte{pkBytes},
	}
	return fx, out, in, cred, utx
}

// BenchmarkSchnorrVerify benchmarks cold (cache-cleared) verification.
func BenchmarkSchnorrVerify(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fx, out, in, cred, utx := benchSetup(b)
		if err := fx.VerifyTransfer(utx, in, cred, out); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSchnorrVerifyCached benchmarks warm (cache-hit) verification.
func BenchmarkSchnorrVerifyCached(b *testing.B) {
	fx, out, in, cred, utx := benchSetup(b)
	if err := fx.VerifyTransfer(utx, in, cred, out); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := fx.VerifyTransfer(utx, in, cred, out); err != nil {
			b.Fatal(err)
		}
	}
}
