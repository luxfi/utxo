// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1fx

import (
	"testing"
	"time"

	"github.com/luxfi/codec/linearcodec"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
)

// BenchmarkSecp256k1Verify is the BASELINE for CostPerSignature calibration.
// All other plugins' costs should be proportional to this measurement.
func BenchmarkSecp256k1Verify(b *testing.B) {
	sk, err := secp256k1.NewPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	pkBytes := sk.PublicKey().Bytes()
	addressBytes := hash.PubkeyBytesToAddress(pkBytes)
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

	txBytes := []byte("benchmark tx payload for secp256k1 verify baseline")
	tx := &TestTx{UnsignedBytes: txBytes}

	txHash := hash.ComputeHash256(txBytes)
	sig, err := sk.SignHash(txHash)
	if err != nil {
		b.Fatal(err)
	}
	var sigArr [65]byte
	copy(sigArr[:], sig)

	out := &OutputOwners{
		Locktime:  0,
		Threshold: 1,
		Addrs:     []ids.ShortID{addr},
	}
	in := &Input{SigIndices: []uint32{0}}
	cred := &Credential{Sigs: [][65]byte{sigArr}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := fx.VerifyCredentials(tx, in, cred, out); err != nil {
			b.Fatal(err)
		}
	}
}
