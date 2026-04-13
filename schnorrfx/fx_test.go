// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schnorrfx

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/codec/linearcodec"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
)

func newTestFx(t *testing.T) (*Fx, *btcec.PrivateKey, []byte, ids.ShortID) {
	t.Helper()
	require := require.New(t)

	sk, err := btcec.NewPrivateKey()
	require.NoError(err)

	vm := &TestVM{
		Codec: linearcodec.NewDefault(),
		Log:   log.NewNoOpLogger(),
	}
	vm.Clk.Set(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))

	fx := &Fx{}
	require.NoError(fx.Initialize(vm))
	require.NoError(fx.Bootstrapping())
	require.NoError(fx.Bootstrapped())

	pkBytes := schnorr.SerializePubKey(sk.PubKey())
	addrBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, err := ids.ToShortID(addrBytes)
	require.NoError(err)
	return fx, sk, pkBytes, addr
}

func signSchnorr(t *testing.T, sk *btcec.PrivateKey, msg []byte) [SigLen]byte {
	t.Helper()
	digest := taggedDigest(utxoSignCtx, msg)
	sig, err := schnorr.Sign(sk, digest)
	require.NoError(t, err)
	var out [SigLen]byte
	copy(out[:], sig.Serialize())
	return out
}

func TestFxInitialize(t *testing.T) {
	vm := TestVM{
		Codec: linearcodec.NewDefault(),
		Log:   log.NewNoOpLogger(),
	}
	fx := Fx{}
	require.NoError(t, fx.Initialize(&vm))
}

func TestFxInitializeInvalid(t *testing.T) {
	fx := Fx{}
	err := fx.Initialize(nil)
	require.ErrorIs(t, err, ErrWrongVMType)
}

func TestFxVerifyTransfer(t *testing.T) {
	require := require.New(t)
	fx, sk, pkBytes, addr := newTestFx(t)

	txBytes := []byte("test transaction bytes")
	sig := signSchnorr(t, sk, txBytes)

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
		Sigs:    [][SigLen]byte{sig},
		PubKeys: [][]byte{pkBytes},
	}
	require.NoError(fx.VerifyTransfer(utx, in, cred, out))
}

func TestFxVerifyTransferWrongSig(t *testing.T) {
	require := require.New(t)
	fx, _, pkBytes, addr := newTestFx(t)

	txBytes := []byte("test transaction bytes")

	// Sign DIFFERENT bytes — should fail
	badSk, err := btcec.NewPrivateKey()
	require.NoError(err)
	badSig := signSchnorr(t, badSk, txBytes)

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
		Sigs:    [][SigLen]byte{badSig},
		PubKeys: [][]byte{pkBytes}, // right pubkey, wrong sig (signed by different key)
	}
	err = fx.VerifyTransfer(utx, in, cred, out)
	require.ErrorIs(err, ErrWrongSig)
}

func TestFxVerifyTransferMismatchedPubkey(t *testing.T) {
	require := require.New(t)
	fx, sk, _, addr := newTestFx(t)

	txBytes := []byte("test transaction bytes")
	sig := signSchnorr(t, sk, txBytes)

	// Use DIFFERENT pubkey in credential than the one that signed
	otherSk, err := btcec.NewPrivateKey()
	require.NoError(err)
	otherPkBytes := schnorr.SerializePubKey(otherSk.PubKey())

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
		Sigs:    [][SigLen]byte{sig},
		PubKeys: [][]byte{otherPkBytes},
	}
	err = fx.VerifyTransfer(utx, in, cred, out)
	require.ErrorIs(err, ErrWrongSig)
}

func TestFxVerifyCache(t *testing.T) {
	require := require.New(t)
	fx, sk, pkBytes, addr := newTestFx(t)

	txBytes := []byte("test transaction bytes")
	sig := signSchnorr(t, sk, txBytes)

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
		Sigs:    [][SigLen]byte{sig},
		PubKeys: [][]byte{pkBytes},
	}
	// First verify — populates cache.
	require.NoError(fx.VerifyTransfer(utx, in, cred, out))
	// Second verify — cache hit.
	require.NoError(fx.VerifyTransfer(utx, in, cred, out))
}

func TestFxVerifyTimelocked(t *testing.T) {
	require := require.New(t)
	fx, sk, pkBytes, addr := newTestFx(t)

	txBytes := []byte("test transaction bytes")
	sig := signSchnorr(t, sk, txBytes)

	future := uint64(fx.VM.Clock().Unix()) + 1000

	utx := &TestTx{UnsignedBytes: txBytes}
	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Locktime:  future,
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	in := &TransferInput{
		Amt:   1,
		Input: Input{SigIndices: []uint32{0}},
	}
	cred := &Credential{
		Sigs:    [][SigLen]byte{sig},
		PubKeys: [][]byte{pkBytes},
	}
	require.ErrorIs(fx.VerifyTransfer(utx, in, cred, out), ErrTimelocked)
}

func TestOutputOwners_RejectThresholdZeroWithAddrs(t *testing.T) {
	addr := ids.ShortID{0xaa}
	out := &OutputOwners{
		Threshold: 0,
		Addrs:     []ids.ShortID{addr},
	}
	require.ErrorIs(t, out.Verify(), ErrOutputUnoptimized)
}

func TestOutputOwners_RejectUnsorted(t *testing.T) {
	a := ids.ShortID{0xbb}
	b := ids.ShortID{0xaa}
	out := &OutputOwners{
		Threshold: 1,
		Addrs:     []ids.ShortID{a, b},
	}
	require.ErrorIs(t, out.Verify(), ErrAddrsNotSortedUnique)
}

func TestKeychainSpend(t *testing.T) {
	require := require.New(t)
	kc := NewKeychain()
	sk, err := kc.New()
	require.NoError(err)
	pkBytes := schnorr.SerializePubKey(sk.PubKey())
	addrBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, err := ids.ToShortID(addrBytes)
	require.NoError(err)

	out := &TransferOutput{
		Amt: 42,
		OutputOwners: OutputOwners{
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	inIntf, keys, err := kc.Spend(out, 0)
	require.NoError(err)
	require.Len(keys, 1)
	in, ok := inIntf.(*TransferInput)
	require.True(ok)
	require.Equal(uint64(42), in.Amt)
	require.Equal([]uint32{0}, in.SigIndices)
}
