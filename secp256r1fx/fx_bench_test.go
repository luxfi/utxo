// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256r1fx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
)

// BenchmarkP256Verify measures P-256 ECDSA signature verification cost.
// P-256 verify is roughly on par with secp256k1 (~1x cost).
func BenchmarkP256Verify(b *testing.B) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	pkBytes := pubKeyBytes(&sk.PublicKey)
	addressBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, err := ids.ToShortID(addressBytes)
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
	if err := fx.Bootstrapped(); err != nil {
		b.Fatal(err)
	}

	txBytes := []byte("benchmark tx payload for P-256 verify")
	tx := &TestTx{UnsignedBytes: txBytes}

	sigBytes, err := signP256(sk, txBytes)
	if err != nil {
		b.Fatal(err)
	}
	var sigArr [SigLen]byte
	copy(sigArr[:], sigBytes)

	out := &OutputOwners{
		Locktime:  0,
		Threshold: 1,
		Addrs:     []ids.ShortID{addr},
	}
	in := &Input{SigIndices: []uint32{0}}
	cred := &Credential{Sigs: [][SigLen]byte{sigArr}, PubKeys: [][]byte{pkBytes}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fx.verifyCache.Flush()
		if err := fx.VerifyCredentials(tx, in, cred, out); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkP256VerifyCached measures cache-hit performance.
func BenchmarkP256VerifyCached(b *testing.B) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	pkBytes := pubKeyBytes(&sk.PublicKey)
	addressBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, err := ids.ToShortID(addressBytes)
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
	if err := fx.Bootstrapped(); err != nil {
		b.Fatal(err)
	}

	txBytes := []byte("benchmark tx payload for P-256 verify cached")
	tx := &TestTx{UnsignedBytes: txBytes}

	sigBytes, err := signP256(sk, txBytes)
	if err != nil {
		b.Fatal(err)
	}
	var sigArr [SigLen]byte
	copy(sigArr[:], sigBytes)

	out := &OutputOwners{
		Locktime:  0,
		Threshold: 1,
		Addrs:     []ids.ShortID{addr},
	}
	in := &Input{SigIndices: []uint32{0}}
	cred := &Credential{Sigs: [][SigLen]byte{sigArr}, PubKeys: [][]byte{pkBytes}}

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
