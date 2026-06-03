// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsafx

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/luxfi/crypto/slhdsa"
	log "github.com/luxfi/log"
)

// BenchmarkSLH192fVerify measures SLH-DSA-SHA2-192f signature verification cost.
// SLH-DSA is significantly slower than secp256k1 due to hash tree traversal.
func BenchmarkSLH192fVerify(b *testing.B) {
	sk, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_192f)
	if err != nil {
		b.Fatal(err)
	}
	pkBytes := sk.PublicKey.Bytes()

	vm := &TestVM{
		Log:   log.NewNoOpLogger(),
	}
	vm.Clk.Set(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))

	fx := &Fx{}
	if err := fx.Initialize(vm); err != nil {
		b.Fatal(err)
	}
	if err := fx.Bootstrapped(); err != nil {
		b.Fatal(err)
	}

	txBytes := []byte("benchmark tx payload for SLH-DSA verify")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig, err := sk.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	if err != nil {
		b.Fatal(err)
	}

	out := &OutputOwners{
		Level:     SecLevelSLH192f,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pkBytes},
	}
	in := &Input{SigIndices: []uint32{0}}
	cred := &Credential{Level: SecLevelSLH192f, Sigs: [][]byte{sig}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fx.verifyCache.Flush()
		if err := fx.VerifyCredentials(tx, in, cred, out); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSLH192fVerifyCached measures cache-hit performance.
func BenchmarkSLH192fVerifyCached(b *testing.B) {
	sk, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_192f)
	if err != nil {
		b.Fatal(err)
	}
	pkBytes := sk.PublicKey.Bytes()

	vm := &TestVM{
		Log:   log.NewNoOpLogger(),
	}
	vm.Clk.Set(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))

	fx := &Fx{}
	if err := fx.Initialize(vm); err != nil {
		b.Fatal(err)
	}
	if err := fx.Bootstrapped(); err != nil {
		b.Fatal(err)
	}

	txBytes := []byte("benchmark tx payload for SLH-DSA verify cached")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig, err := sk.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	if err != nil {
		b.Fatal(err)
	}

	out := &OutputOwners{
		Level:     SecLevelSLH192f,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pkBytes},
	}
	in := &Input{SigIndices: []uint32{0}}
	cred := &Credential{Level: SecLevelSLH192f, Sigs: [][]byte{sig}}

	if err := fx.VerifyCredentials(tx, in, cred, out); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := fx.VerifyCredentials(tx, in, cred, out); err != nil {
			b.Fatal(err)
		}
	}
}
