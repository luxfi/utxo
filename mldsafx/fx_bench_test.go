// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsafx

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/luxfi/crypto/mldsa"
	log "github.com/luxfi/log"
)

// BenchmarkMLDSA65Verify measures ML-DSA-65 signature verification cost.
// Compare with secp256k1fx BenchmarkVerify to calibrate CostPerSignature.
// ML-DSA-65 verify is ~5-10x slower than secp256k1 ecrecover.
func BenchmarkMLDSA65Verify(b *testing.B) {
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
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

	txBytes := []byte("benchmark tx payload for ML-DSA verify")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig, err := sk.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	if err != nil {
		b.Fatal(err)
	}

	out := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pkBytes},
	}
	in := &Input{SigIndices: []uint32{0}}
	cred := &Credential{Level: SecLevelMLDSA65, Sigs: [][]byte{sig}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clear cache each iteration to measure raw verify cost
		fx.verifyCache.Flush()
		if err := fx.VerifyCredentials(tx, in, cred, out); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMLDSA65VerifyCached measures cache-hit performance.
func BenchmarkMLDSA65VerifyCached(b *testing.B) {
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
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

	txBytes := []byte("benchmark tx payload for ML-DSA verify cached")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig, err := sk.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	if err != nil {
		b.Fatal(err)
	}

	out := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pkBytes},
	}
	in := &Input{SigIndices: []uint32{0}}
	cred := &Credential{Level: SecLevelMLDSA65, Sigs: [][]byte{sig}}

	// Prime the cache
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
