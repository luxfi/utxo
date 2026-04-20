// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381fx

import (
	"bytes"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/codec/linearcodec"
	"github.com/luxfi/crypto/bls"
	log "github.com/luxfi/log"
)

// testTx implements UnsignedTx
type testTx struct{ b []byte }

func (t *testTx) Bytes() []byte { return t.b }

func newTestFx(t *testing.T) *Fx {
	t.Helper()
	vm := &TestVM{
		Codec: linearcodec.NewDefault(),
		Log:   log.NewNoOpLogger(),
	}
	vm.Clk.Set(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))
	fx := &Fx{}
	require.NoError(t, fx.Initialize(vm))
	require.NoError(t, fx.Bootstrapping())
	require.NoError(t, fx.Bootstrapped())
	return fx
}

// newCommittee creates `n` BLS keypairs and returns the sorted pubkey bytes.
func newCommittee(t *testing.T, n int) ([]*bls.SecretKey, [][]byte) {
	t.Helper()
	sks := make([]*bls.SecretKey, n)
	pkBytes := make([][]byte, n)
	for i := 0; i < n; i++ {
		sk, err := bls.NewSecretKey()
		require.NoError(t, err)
		sks[i] = sk
		pkBytes[i] = bls.PublicKeyToCompressedBytes(bls.PublicFromSecretKey(sk))
	}
	// Sort pubkeys and reorder sks to match.
	type pair struct {
		pk []byte
		sk *bls.SecretKey
	}
	pairs := make([]pair, n)
	for i := range pairs {
		pairs[i] = pair{pk: pkBytes[i], sk: sks[i]}
	}
	sort.Slice(pairs, func(i, j int) bool {
		return bytes.Compare(pairs[i].pk, pairs[j].pk) < 0
	})
	for i, p := range pairs {
		sks[i] = p.sk
		pkBytes[i] = p.pk
	}
	return sks, pkBytes
}

func signAttestation(t *testing.T, signers []*bls.SecretKey, attestedHash [AttestedHashLen]byte) [SigLen]byte {
	t.Helper()
	msg := make([]byte, 0, len(attestationSignCtx)+len(attestedHash))
	msg = append(msg, attestationSignCtx...)
	msg = append(msg, attestedHash[:]...)
	sigs := make([]*bls.Signature, len(signers))
	for i, sk := range signers {
		sigs[i] = bls.Sign(sk, msg)
	}
	agg, err := bls.AggregateSignatures(sigs)
	require.NoError(t, err)
	var out [SigLen]byte
	copy(out[:], bls.SignatureToBytes(agg))
	return out
}

func TestFxInitialize(t *testing.T) {
	vm := &TestVM{Codec: linearcodec.NewDefault(), Log: log.NewNoOpLogger()}
	fx := &Fx{}
	require.NoError(t, fx.Initialize(vm))
}

func TestFxInitializeBadVM(t *testing.T) {
	fx := &Fx{}
	require.ErrorIs(t, fx.Initialize(nil), ErrWrongVMType)
}

func TestFxTransferRejected(t *testing.T) {
	fx := newTestFx(t)
	err := fx.VerifyTransfer(nil, nil, nil, nil)
	require.ErrorIs(t, err, ErrNotTransferable)
}

func TestAttestationOutputVerify(t *testing.T) {
	_, pks := newCommittee(t, 3)
	out := &AttestationOutput{
		AttestedHash: [AttestedHashLen]byte{0x01},
		Threshold:    2,
		PubKeys:      pks,
	}
	require.NoError(t, out.Verify())
}

func TestAttestationOutputNil(t *testing.T) {
	var out *AttestationOutput
	require.ErrorIs(t, out.Verify(), ErrNilOutput)
}

func TestAttestationOutputEmptyPubKeys(t *testing.T) {
	out := &AttestationOutput{Threshold: 1}
	require.ErrorIs(t, out.Verify(), ErrEmptyPubKeys)
}

func TestAttestationOutputThresholdZero(t *testing.T) {
	_, pks := newCommittee(t, 3)
	out := &AttestationOutput{Threshold: 0, PubKeys: pks}
	require.ErrorIs(t, out.Verify(), ErrThresholdZero)
}

func TestAttestationOutputThresholdTooHigh(t *testing.T) {
	_, pks := newCommittee(t, 3)
	out := &AttestationOutput{Threshold: 4, PubKeys: pks}
	require.ErrorIs(t, out.Verify(), ErrThresholdExceedsPubKeys)
}

func TestAttestationOutputBadPubKeyLen(t *testing.T) {
	out := &AttestationOutput{Threshold: 1, PubKeys: [][]byte{make([]byte, 10)}}
	require.ErrorIs(t, out.Verify(), ErrInvalidPubKeyLen)
}

func TestAttestationOutputUnsorted(t *testing.T) {
	_, pks := newCommittee(t, 3)
	// Swap to break sort order.
	pks[0], pks[1] = pks[1], pks[0]
	out := &AttestationOutput{Threshold: 2, PubKeys: pks}
	require.ErrorIs(t, out.Verify(), ErrPubKeysNotSortedUnique)
}

func TestAttestationInputVerify(t *testing.T) {
	in := &AttestationInput{Signers: []byte{0b00000111}}
	require.NoError(t, in.Verify())
}

func TestAttestationInputEmptyBitmap(t *testing.T) {
	in := &AttestationInput{Signers: []byte{}}
	require.ErrorIs(t, in.Verify(), ErrSignerBitmapEmpty)
	in2 := &AttestationInput{Signers: []byte{0, 0, 0}}
	require.ErrorIs(t, in2.Verify(), ErrSignerBitmapEmpty)
}

func TestAttestationFullFlow(t *testing.T) {
	require := require.New(t)
	fx := newTestFx(t)
	sks, pks := newCommittee(t, 5)

	attestedHash := [AttestedHashLen]byte{0xde, 0xad, 0xbe, 0xef}
	// First 3 sign.
	signers := sks[:3]
	aggSig := signAttestation(t, signers, attestedHash)

	out := &AttestationOutput{
		AttestedHash: attestedHash,
		Threshold:    3,
		PubKeys:      pks,
	}
	in := &AttestationInput{Signers: []byte{0b00000111}} // bits 0,1,2 = pubkeys[0..2]
	cred := &Credential{AggSig: aggSig}

	require.NoError(fx.VerifyOperation(
		&testTx{b: []byte("tx")},
		in,
		cred,
		[]interface{}{out},
	))
}

func TestAttestationCached(t *testing.T) {
	require := require.New(t)
	fx := newTestFx(t)
	sks, pks := newCommittee(t, 3)

	attestedHash := [AttestedHashLen]byte{0x12, 0x34}
	aggSig := signAttestation(t, sks[:2], attestedHash)

	out := &AttestationOutput{
		AttestedHash: attestedHash,
		Threshold:    2,
		PubKeys:      pks,
	}
	in := &AttestationInput{Signers: []byte{0b00000011}}
	cred := &Credential{AggSig: aggSig}

	require.NoError(fx.VerifyOperation(&testTx{b: []byte{}}, in, cred, []interface{}{out}))
	// Second call — cache hit path.
	require.NoError(fx.VerifyOperation(&testTx{b: []byte{}}, in, cred, []interface{}{out}))
}

func TestAttestationBelowThreshold(t *testing.T) {
	fx := newTestFx(t)
	sks, pks := newCommittee(t, 5)

	attestedHash := [AttestedHashLen]byte{0x99}
	aggSig := signAttestation(t, sks[:2], attestedHash)

	out := &AttestationOutput{
		AttestedHash: attestedHash,
		Threshold:    3, // quorum of 3, only 2 signed
		PubKeys:      pks,
	}
	in := &AttestationInput{Signers: []byte{0b00000011}}
	cred := &Credential{AggSig: aggSig}

	err := fx.VerifyOperation(&testTx{}, in, cred, []interface{}{out})
	require.ErrorIs(t, err, ErrSignerBitmapPopcount)
}

func TestAttestationWrongSig(t *testing.T) {
	fx := newTestFx(t)
	_, pks := newCommittee(t, 3)
	otherSks, _ := newCommittee(t, 3)

	attestedHash := [AttestedHashLen]byte{0xab}
	// Sign with OTHER keys, claim the first committee.
	aggSig := signAttestation(t, otherSks[:2], attestedHash)

	out := &AttestationOutput{
		AttestedHash: attestedHash,
		Threshold:    2,
		PubKeys:      pks,
	}
	in := &AttestationInput{Signers: []byte{0b00000011}}
	cred := &Credential{AggSig: aggSig}

	err := fx.VerifyOperation(&testTx{}, in, cred, []interface{}{out})
	require.ErrorIs(t, err, ErrInvalidAggSig)
}

func TestAttestationWrongHash(t *testing.T) {
	fx := newTestFx(t)
	sks, pks := newCommittee(t, 3)

	// Sign hash A, but the output commits to hash B.
	attestedHashA := [AttestedHashLen]byte{0xaa}
	attestedHashB := [AttestedHashLen]byte{0xbb}
	aggSig := signAttestation(t, sks[:2], attestedHashA)

	out := &AttestationOutput{
		AttestedHash: attestedHashB,
		Threshold:    2,
		PubKeys:      pks,
	}
	in := &AttestationInput{Signers: []byte{0b00000011}}
	cred := &Credential{AggSig: aggSig}

	err := fx.VerifyOperation(&testTx{}, in, cred, []interface{}{out})
	require.ErrorIs(t, err, ErrInvalidAggSig)
}

func TestAttestationBitmapOutOfRange(t *testing.T) {
	fx := newTestFx(t)
	sks, pks := newCommittee(t, 3)
	attestedHash := [AttestedHashLen]byte{0x01}
	aggSig := signAttestation(t, sks[:2], attestedHash)

	out := &AttestationOutput{
		AttestedHash: attestedHash,
		Threshold:    2,
		PubKeys:      pks, // only 3 pubkeys
	}
	// bit 7 set (idx 7) but only 3 pubkeys — out of range.
	in := &AttestationInput{Signers: []byte{0b10000011}}
	cred := &Credential{AggSig: aggSig}

	err := fx.VerifyOperation(&testTx{}, in, cred, []interface{}{out})
	require.ErrorIs(t, err, ErrSignerBitmapOutOfRange)
}

func TestPopcount(t *testing.T) {
	require.Equal(t, uint32(0), popcountBitmap([]byte{0}))
	require.Equal(t, uint32(1), popcountBitmap([]byte{1}))
	require.Equal(t, uint32(8), popcountBitmap([]byte{0xff}))
	require.Equal(t, uint32(16), popcountBitmap([]byte{0xff, 0xff}))
	require.Equal(t, uint32(3), popcountBitmap([]byte{0b00000111}))
}
