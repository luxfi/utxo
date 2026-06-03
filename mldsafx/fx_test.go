// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsafx

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
)

func newTestFx(t *testing.T) (*Fx, *mldsa.PrivateKey, []byte) {
	t.Helper()
	require := require.New(t)

	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(err)

	vm := &TestVM{
		Log:   log.NewNoOpLogger(),
	}
	vm.Clk.Set(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))

	fx := &Fx{}
	require.NoError(fx.Initialize(vm))
	require.NoError(fx.Bootstrapping())
	require.NoError(fx.Bootstrapped())

	pkBytes := sk.PublicKey.Bytes()
	return fx, sk, pkBytes
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
	fx, sk, pkBytes := newTestFx(t)

	txBytes := []byte{0, 1, 2, 3, 4, 5}
	tx := &TestTx{UnsignedBytes: txBytes}

	sig, err := sk.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	require.NoError(err)

	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Level:     SecLevelMLDSA65,
			Locktime:  0,
			Threshold: 1,
			Addrs:     [][]byte{pkBytes},
		},
	}
	in := &TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	cred := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{sig},
	}

	require.NoError(fx.VerifyTransfer(tx, in, cred, out))
}

func TestFxVerifyTransferWrongSig(t *testing.T) {
	require := require.New(t)
	fx, _, pkBytes := newTestFx(t)

	txBytes := []byte{0, 1, 2, 3, 4, 5}
	tx := &TestTx{UnsignedBytes: txBytes}

	// Create a bad signature
	badSig := make([]byte, mldsa.MLDSA65SignatureSize)

	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Level:     SecLevelMLDSA65,
			Locktime:  0,
			Threshold: 1,
			Addrs:     [][]byte{pkBytes},
		},
	}
	in := &TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	cred := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{badSig},
	}

	err := fx.VerifyTransfer(tx, in, cred, out)
	require.ErrorIs(err, ErrWrongSig)
}

func TestFxVerifyTransferMismatchedAmounts(t *testing.T) {
	require := require.New(t)
	fx, sk, pkBytes := newTestFx(t)

	txBytes := []byte{0, 1, 2, 3, 4, 5}
	tx := &TestTx{UnsignedBytes: txBytes}

	sig, err := sk.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	require.NoError(err)

	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Level:     SecLevelMLDSA65,
			Locktime:  0,
			Threshold: 1,
			Addrs:     [][]byte{pkBytes},
		},
	}
	in := &TransferInput{
		Amt: 2, // mismatched
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	cred := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{sig},
	}

	err = fx.VerifyTransfer(tx, in, cred, out)
	require.ErrorIs(err, ErrMismatchedAmounts)
}

func TestFxVerifyTransferTimelocked(t *testing.T) {
	require := require.New(t)
	fx, sk, pkBytes := newTestFx(t)

	txBytes := []byte{0, 1, 2, 3, 4, 5}
	tx := &TestTx{UnsignedBytes: txBytes}

	sig, err := sk.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	require.NoError(err)

	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Level:     SecLevelMLDSA65,
			Locktime:  uint64(time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()),
			Threshold: 1,
			Addrs:     [][]byte{pkBytes},
		},
	}
	in := &TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	cred := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{sig},
	}

	err = fx.VerifyTransfer(tx, in, cred, out)
	require.ErrorIs(err, ErrTimelocked)
}

func TestFxVerifyCredentials(t *testing.T) {
	require := require.New(t)
	fx, sk, pkBytes := newTestFx(t)

	txBytes := []byte("test transaction")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig, err := sk.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	require.NoError(err)

	out := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pkBytes},
	}
	in := &Input{
		SigIndices: []uint32{0},
	}
	cred := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{sig},
	}

	require.NoError(fx.VerifyCredentials(tx, in, cred, out))
}

func TestFxVerifyCredentialsMultiSig(t *testing.T) {
	require := require.New(t)
	fx, _, _ := newTestFx(t)

	sk1, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(err)
	sk2, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(err)

	pk1 := sk1.PublicKey.Bytes()
	pk2 := sk2.PublicKey.Bytes()

	// Sort keys lexicographically
	if string(pk1) > string(pk2) {
		pk1, pk2 = pk2, pk1
		sk1, sk2 = sk2, sk1
	}

	txBytes := []byte("multi-sig tx")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig1, err := sk1.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	require.NoError(err)
	sig2, err := sk2.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	require.NoError(err)

	out := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 2,
		Addrs:     [][]byte{pk1, pk2},
	}
	in := &Input{
		SigIndices: []uint32{0, 1},
	}
	cred := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{sig1, sig2},
	}

	require.NoError(fx.VerifyCredentials(tx, in, cred, out))
}

func TestFxVerifyPermission(t *testing.T) {
	require := require.New(t)
	fx, sk, pkBytes := newTestFx(t)

	txBytes := []byte("permission tx")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig, err := sk.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	require.NoError(err)

	owner := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pkBytes},
	}
	in := &Input{
		SigIndices: []uint32{0},
	}
	cred := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{sig},
	}

	require.NoError(fx.VerifyPermission(tx, in, cred, owner))
}

func TestFxVerifyPermissionWrongTypes(t *testing.T) {
	fx, _, _ := newTestFx(t)

	require.ErrorIs(t, fx.VerifyPermission("bad", nil, nil, nil), ErrWrongTxType)
	tx := &TestTx{}
	require.ErrorIs(t, fx.VerifyPermission(tx, "bad", nil, nil), ErrWrongInputType)
	require.ErrorIs(t, fx.VerifyPermission(tx, &Input{}, "bad", nil), ErrWrongCredentialType)
	require.ErrorIs(t, fx.VerifyPermission(tx, &Input{}, &Credential{Level: SecLevelMLDSA65}, "bad"), ErrWrongOwnerType)
}

func TestFxVerifyTransferBootstrapping(t *testing.T) {
	require := require.New(t)

	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(err)
	pkBytes := sk.PublicKey.Bytes()

	vm := &TestVM{
		Log:   log.NewNoOpLogger(),
	}
	vm.Clk.Set(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))

	fx := &Fx{}
	require.NoError(fx.Initialize(vm))
	require.NoError(fx.Bootstrapping())
	// NOT calling Bootstrapped — should skip sig verification

	txBytes := []byte{0, 1, 2, 3, 4, 5}
	tx := &TestTx{UnsignedBytes: txBytes}

	// Use a bad signature — should still pass during bootstrap
	badSig := make([]byte, mldsa.MLDSA65SignatureSize)

	out := &TransferOutput{
		Amt: 1,
		OutputOwners: OutputOwners{
			Level:     SecLevelMLDSA65,
			Locktime:  0,
			Threshold: 1,
			Addrs:     [][]byte{pkBytes},
		},
	}
	in := &TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	cred := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{badSig},
	}

	require.NoError(fx.VerifyTransfer(tx, in, cred, out))
}

func TestFxCreateOutput(t *testing.T) {
	require := require.New(t)
	fx, _, pkBytes := newTestFx(t)

	owner := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pkBytes},
	}

	result, err := fx.CreateOutput(100, owner)
	require.NoError(err)

	out, ok := result.(*TransferOutput)
	require.True(ok)
	require.Equal(uint64(100), out.Amt)
}

func TestFxVerifyOperation(t *testing.T) {
	require := require.New(t)
	fx, sk, pkBytes := newTestFx(t)

	txBytes := []byte("mint operation tx")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig, err := sk.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	require.NoError(err)

	owners := OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pkBytes},
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
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{sig},
	}

	require.NoError(fx.VerifyOperation(tx, op, cred, []interface{}{utxo}))
}

func TestFxAddressDerivation(t *testing.T) {
	require := require.New(t)

	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(err)

	pkBytes := sk.PublicKey.Bytes()
	addressBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, err := ids.ToShortID(addressBytes)
	require.NoError(err)
	require.NotEqual(ids.ShortEmpty, addr)
}

// Regression: Finding 1 -- Threshold==0 with addresses must be rejected
func TestOutputOwners_RejectThresholdZero(t *testing.T) {
	require := require.New(t)

	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(err)

	out := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 0,
		Addrs:     [][]byte{sk.PublicKey.Bytes()},
	}
	require.ErrorIs(out.Verify(), ErrOutputUnoptimized)
}

// Regression: Finding 1 -- Threshold==0 with no addresses is valid (unspendable)
func TestOutputOwners_ThresholdZeroNoAddrs(t *testing.T) {
	out := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 0,
		Addrs:     nil,
	}
	require.NoError(t, out.Verify())
}

// Regression: Finding 3 -- Addresses() must return hashed ShortIDs, not zero
func TestOutputOwners_Addresses_UsesHash(t *testing.T) {
	require := require.New(t)

	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(err)
	pkBytes := sk.PublicKey.Bytes()

	out := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pkBytes},
	}

	addrs := out.Addresses()
	require.Len(addrs, 1)
	require.NotEqual(ids.ShortEmpty, addrs[0], "Addresses() returned zero ShortID -- must hash pubkey")

	// Verify it matches the expected derivation
	expectedBytes := hash.PubkeyBytesToAddress(pkBytes)
	expected, err := ids.ToShortID(expectedBytes)
	require.NoError(err)
	require.Equal(expected, addrs[0])
}

// Regression: Finding 6 -- Empty Sigs slice must be rejected
func TestCredential_RejectEmptySigs(t *testing.T) {
	cred := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{},
	}
	require.ErrorIs(t, cred.Verify(), ErrEmptyCredential)
}

// Regression: Finding 5 -- Verify cache hit/miss
func TestFxVerifyCache(t *testing.T) {
	require := require.New(t)
	fx, sk, pkBytes := newTestFx(t)

	txBytes := []byte("cache test tx")
	tx := &TestTx{UnsignedBytes: txBytes}

	sig, err := sk.SignCtx(rand.Reader, txBytes, utxoSignCtx)
	require.NoError(err)

	out := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pkBytes},
	}
	in := &Input{SigIndices: []uint32{0}}
	cred := &Credential{Level: SecLevelMLDSA65, Sigs: [][]byte{sig}}

	// First call: cache miss, verify succeeds
	require.NoError(fx.VerifyCredentials(tx, in, cred, out))
	require.Equal(1, fx.verifyCache.Len())

	// Second call: cache hit, should still succeed
	require.NoError(fx.VerifyCredentials(tx, in, cred, out))
	require.Equal(1, fx.verifyCache.Len())
}

// Regression: Finding 2 -- Domain separation: nil-context sig rejected by UTXO verify
func TestFxVerifyCredentials_RejectNilContext(t *testing.T) {
	require := require.New(t)
	fx, sk, pkBytes := newTestFx(t)

	txBytes := []byte("domain sep test")
	tx := &TestTx{UnsignedBytes: txBytes}

	// Sign WITHOUT context (as if for a different protocol)
	sig, err := sk.Sign(rand.Reader, txBytes, nil)
	require.NoError(err)

	out := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pkBytes},
	}
	in := &Input{SigIndices: []uint32{0}}
	cred := &Credential{Level: SecLevelMLDSA65, Sigs: [][]byte{sig}}

	// Must fail: the fx verifier expects utxoSignCtx
	err = fx.VerifyCredentials(tx, in, cred, out)
	require.ErrorIs(err, ErrWrongSig)
}
