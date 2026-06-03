// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519fx

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
)

func newTestFx(t *testing.T) (*Fx, ed25519.PrivateKey, ed25519.PublicKey, ids.ShortID) {
	t.Helper()
	require := require.New(t)

	pub, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err)

	vm := &TestVM{
		Log:   log.NewNoOpLogger(),
	}
	vm.Clk.Set(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))

	fx := &Fx{}
	require.NoError(fx.Initialize(vm))
	require.NoError(fx.Bootstrapping())
	require.NoError(fx.Bootstrapped())

	addressBytes := hash.PubkeyBytesToAddress(pub)
	addr, err := ids.ToShortID(addressBytes)
	require.NoError(err)

	return fx, sk, pub, addr
}

func TestFxInitialize(t *testing.T) {
	vm := TestVM{
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
	fx, sk, pub, addr := newTestFx(t)

	txBytes := []byte{0, 1, 2, 3, 4, 5}
	tx := &TestTx{UnsignedBytes: txBytes}

	sig := ed25519.Sign(sk, txBytes)
	var sigArr [SigLen]byte
	copy(sigArr[:], sig)

	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Locktime:  0,
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	in := &TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	cred := &Credential{
		Sigs:    [][SigLen]byte{sigArr},
		PubKeys: [][]byte{pub},
	}

	require.NoError(fx.VerifyTransfer(tx, in, cred, out))
}

func TestFxVerifyTransferWrongSig(t *testing.T) {
	require := require.New(t)
	fx, _, pub, addr := newTestFx(t)

	txBytes := []byte{0, 1, 2, 3, 4, 5}
	tx := &TestTx{UnsignedBytes: txBytes}

	var badSig [SigLen]byte

	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Locktime:  0,
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	in := &TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	cred := &Credential{
		Sigs:    [][SigLen]byte{badSig},
		PubKeys: [][]byte{pub},
	}

	err := fx.VerifyTransfer(tx, in, cred, out)
	require.ErrorIs(err, ErrWrongSig)
}

func TestFxVerifyTransferMismatchedAmounts(t *testing.T) {
	require := require.New(t)
	fx, sk, pub, addr := newTestFx(t)

	txBytes := []byte{0, 1, 2, 3, 4, 5}
	tx := &TestTx{UnsignedBytes: txBytes}

	sig := ed25519.Sign(sk, txBytes)
	var sigArr [SigLen]byte
	copy(sigArr[:], sig)

	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Locktime:  0,
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	in := &TransferInput{
		Amt: 2,
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	cred := &Credential{
		Sigs:    [][SigLen]byte{sigArr},
		PubKeys: [][]byte{pub},
	}

	err := fx.VerifyTransfer(tx, in, cred, out)
	require.ErrorIs(err, ErrMismatchedAmounts)
}

func TestFxVerifyTransferTimelocked(t *testing.T) {
	require := require.New(t)
	fx, sk, pub, addr := newTestFx(t)

	txBytes := []byte{0, 1, 2, 3, 4, 5}
	tx := &TestTx{UnsignedBytes: txBytes}

	sig := ed25519.Sign(sk, txBytes)
	var sigArr [SigLen]byte
	copy(sigArr[:], sig)

	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Locktime:  uint64(time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()),
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	in := &TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	cred := &Credential{
		Sigs:    [][SigLen]byte{sigArr},
		PubKeys: [][]byte{pub},
	}

	err := fx.VerifyTransfer(tx, in, cred, out)
	require.ErrorIs(err, ErrTimelocked)
}

func TestFxVerifyPermission(t *testing.T) {
	require := require.New(t)
	fx, sk, pub, addr := newTestFx(t)

	txBytes := []byte("permission tx")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig := ed25519.Sign(sk, txBytes)
	var sigArr [SigLen]byte
	copy(sigArr[:], sig)

	owner := &OutputOwners{
		Locktime:  0,
		Threshold: 1,
		Addrs:     []ids.ShortID{addr},
	}
	in := &Input{
		SigIndices: []uint32{0},
	}
	cred := &Credential{
		Sigs:    [][SigLen]byte{sigArr},
		PubKeys: [][]byte{pub},
	}

	require.NoError(fx.VerifyPermission(tx, in, cred, owner))
}

func TestFxVerifyPermissionWrongTypes(t *testing.T) {
	fx, _, _, _ := newTestFx(t)

	require.ErrorIs(t, fx.VerifyPermission("bad", nil, nil, nil), ErrWrongTxType)
	tx := &TestTx{}
	require.ErrorIs(t, fx.VerifyPermission(tx, "bad", nil, nil), ErrWrongInputType)
	require.ErrorIs(t, fx.VerifyPermission(tx, &Input{}, "bad", nil), ErrWrongCredentialType)
	require.ErrorIs(t, fx.VerifyPermission(tx, &Input{}, &Credential{}, "bad"), ErrWrongOwnerType)
}

func TestFxVerifyTransferBootstrapping(t *testing.T) {
	require := require.New(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err)

	addressBytes := hash.PubkeyBytesToAddress(pub)
	addr, err := ids.ToShortID(addressBytes)
	require.NoError(err)

	vm := &TestVM{
		Log:   log.NewNoOpLogger(),
	}
	vm.Clk.Set(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))

	fx := &Fx{}
	require.NoError(fx.Initialize(vm))
	require.NoError(fx.Bootstrapping())

	txBytes := []byte{0, 1, 2, 3, 4, 5}
	tx := &TestTx{UnsignedBytes: txBytes}

	var badSig [SigLen]byte

	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Locktime:  0,
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	in := &TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	cred := &Credential{
		Sigs: [][SigLen]byte{badSig},
	}

	require.NoError(fx.VerifyTransfer(tx, in, cred, out))
}

func TestFxCreateOutput(t *testing.T) {
	require := require.New(t)
	fx, _, _, addr := newTestFx(t)

	owner := &OutputOwners{
		Locktime:  0,
		Threshold: 1,
		Addrs:     []ids.ShortID{addr},
	}

	result, err := fx.CreateOutput(100, owner)
	require.NoError(err)

	out, ok := result.(*TransferOutput)
	require.True(ok)
	require.Equal(uint64(100), out.Amt)
}

func TestFxVerifyOperation(t *testing.T) {
	require := require.New(t)
	fx, sk, pub, addr := newTestFx(t)

	txBytes := []byte("mint operation tx")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig := ed25519.Sign(sk, txBytes)
	var sigArr [SigLen]byte
	copy(sigArr[:], sig)

	owners := OutputOwners{
		Locktime:  0,
		Threshold: 1,
		Addrs:     []ids.ShortID{addr},
	}

	utxo := &MintOutput{OutputOwners: owners}
	op := &MintOperation{
		MintInput: Input{SigIndices: []uint32{0}},
		MintOutput: MintOutput{
			OutputOwners: owners,
		},
		TransferOutput: TransferOutput{
			Amt:          1,
			OutputOwners: owners,
		},
	}
	cred := &Credential{
		Sigs:    [][SigLen]byte{sigArr},
		PubKeys: [][]byte{pub},
	}

	require.NoError(fx.VerifyOperation(tx, op, cred, []interface{}{utxo}))
}

func TestFxAddressDerivation(t *testing.T) {
	require := require.New(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err)

	addressBytes := hash.PubkeyBytesToAddress(pub)
	addr, err := ids.ToShortID(addressBytes)
	require.NoError(err)
	require.NotEqual(ids.ShortEmpty, addr)
}
