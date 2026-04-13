// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519fx

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/luxfi/codec/linearcodec"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
)

// BenchmarkEd25519Verify measures Ed25519 signature verification cost.
// Ed25519 verify is faster than secp256k1 ecrecover (~0.5-0.7x cost).
func BenchmarkEd25519Verify(b *testing.B) {
	pub, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	addressBytes := hash.PubkeyBytesToAddress(pub)
	addr, err := ids.ToShortID(addressBytes)
	if err != nil {
		b.Fatal(err)
	}

	vm := &TestVM{
		Codec: linearcodec.NewDefault(),
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

	txBytes := []byte("benchmark tx payload for Ed25519 verify")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig := ed25519.Sign(sk, txBytes)
	var sigArr [SigLen]byte
	copy(sigArr[:], sig)

	out := &OutputOwners{
		Locktime:  0,
		Threshold: 1,
		Addrs:     []ids.ShortID{addr},
	}
	in := &Input{SigIndices: []uint32{0}}
	cred := &Credential{Sigs: [][SigLen]byte{sigArr}, PubKeys: [][]byte{pub}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fx.verifyCache.Flush()
		if err := fx.VerifyCredentials(tx, in, cred, out); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEd25519VerifyCached measures cache-hit performance.
func BenchmarkEd25519VerifyCached(b *testing.B) {
	pub, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	addressBytes := hash.PubkeyBytesToAddress(pub)
	addr, err := ids.ToShortID(addressBytes)
	if err != nil {
		b.Fatal(err)
	}

	vm := &TestVM{
		Codec: linearcodec.NewDefault(),
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

	txBytes := []byte("benchmark tx payload for Ed25519 verify cached")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig := ed25519.Sign(sk, txBytes)
	var sigArr [SigLen]byte
	copy(sigArr[:], sig)

	out := &OutputOwners{
		Locktime:  0,
		Threshold: 1,
		Addrs:     []ids.ShortID{addr},
	}
	in := &Input{SigIndices: []uint32{0}}
	cred := &Credential{Sigs: [][SigLen]byte{sigArr}, PubKeys: [][]byte{pub}}

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
