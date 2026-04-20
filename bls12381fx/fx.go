// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381fx

import (
	"errors"
	"fmt"
	"strings"

	"github.com/luxfi/cache/lru"
	"github.com/luxfi/codec"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
	"github.com/luxfi/timer/mockable"
	"github.com/luxfi/vm/components/verify"
)

const verifyCacheSize = 256

// attestationSignCtx is the domain-separation tag for attestation aggregate
// signatures, per FIPS-style domain separation.
var attestationSignCtx = []byte("lux-x-chain-attestation-bls12381-v1")

var (
	ErrWrongVMType               = errors.New("wrong vm type")
	ErrNotTransferable           = errors.New("bls12381fx outputs are not transferable (attestation-only)")
	ErrWrongOpType               = errors.New("wrong operation type")
	ErrWrongUTXOType             = errors.New("wrong utxo type")
	ErrWrongInputType            = errors.New("wrong input type")
	ErrWrongCredentialType       = errors.New("wrong credential type")
	ErrWrongNumberOfUTXOs        = errors.New("wrong number of utxos for the operation")
	ErrSignerBitmapPopcount      = errors.New("signer bitmap popcount does not meet threshold")
	ErrSignerBitmapOutOfRange    = errors.New("signer bitmap references pubkey out of range")
)

// VM is the interface this Fx requires.
type VM interface {
	CodecRegistry() codec.Registry
	Clock() *mockable.Clock
	Logger() log.Logger
}

var _ VM = (*TestVM)(nil)

// TestVM is a minimal VM for tests.
type TestVM struct {
	Clk   mockable.Clock
	Codec codec.Registry
	Log   log.Logger
}

func (vm *TestVM) Clock() *mockable.Clock     { return &vm.Clk }
func (vm *TestVM) CodecRegistry() codec.Registry { return vm.Codec }
func (vm *TestVM) Logger() log.Logger          { return vm.Log }

// UnsignedTx is what this Fx is signing over.
type UnsignedTx interface{ Bytes() []byte }

type verifyKey = ids.ID

// Fx implements the BLS12-381 attestation-only feature extension.
type Fx struct {
	VM           VM
	bootstrapped bool
	verifyCache  *lru.Cache[verifyKey, bool]
}

func (fx *Fx) Initialize(vmIntf interface{}) error {
	vm, ok := vmIntf.(VM)
	if !ok {
		return ErrWrongVMType
	}
	fx.VM = vm
	fx.verifyCache = lru.NewCache[verifyKey, bool](verifyCacheSize)

	logr := fx.VM.Logger()
	if !logr.IsZero() {
		logr.Debug("initializing bls12381fx (attestation-only)")
	}
	if fx.VM == nil {
		return nil
	}
	c := fx.VM.CodecRegistry()
	if c == nil {
		return nil
	}
	errs := []error{}
	if err := c.RegisterType(&AttestationOutput{}); err != nil && !strings.Contains(err.Error(), "duplicate type registration") {
		errs = append(errs, err)
	}
	if err := c.RegisterType(&AttestationInput{}); err != nil && !strings.Contains(err.Error(), "duplicate type registration") {
		errs = append(errs, err)
	}
	if err := c.RegisterType(&Credential{}); err != nil && !strings.Contains(err.Error(), "duplicate type registration") {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (*Fx) Bootstrapping() error { return nil }

func (fx *Fx) Bootstrapped() error {
	fx.bootstrapped = true
	return nil
}

// VerifyTransfer is intentionally unsupported. bls12381fx outputs are
// attestation records and cannot be spent as values. Use secp256k1fx,
// ed25519fx, secp256r1fx, mldsafx, slhdsafx, or schnorrfx for retail spends.
func (*Fx) VerifyTransfer(_, _, _, _ interface{}) error {
	return ErrNotTransferable
}

// VerifyOperation verifies an AttestationInput + Credential against an
// AttestationOutput UTXO: the aggregate signature must validate under the
// aggregate of the pubkeys referenced by the signer bitmap, and the bitmap
// must reference at least Threshold pubkeys.
func (fx *Fx) VerifyOperation(txIntf, opIntf, credIntf interface{}, utxosIntf []interface{}) error {
	_, ok := txIntf.(UnsignedTx)
	if !ok {
		return fmt.Errorf("%w: expected UnsignedTx, got %T", ErrWrongOpType, txIntf)
	}
	in, ok := opIntf.(*AttestationInput)
	if !ok {
		return ErrWrongInputType
	}
	cred, ok := credIntf.(*Credential)
	if !ok {
		return ErrWrongCredentialType
	}
	if len(utxosIntf) != 1 {
		return ErrWrongNumberOfUTXOs
	}
	out, ok := utxosIntf[0].(*AttestationOutput)
	if !ok {
		return ErrWrongUTXOType
	}
	if err := verify.All(out, in, cred); err != nil {
		return err
	}
	if !fx.bootstrapped {
		return nil
	}
	return fx.verifyAttestation(in, cred, out)
}

// verifyAttestation performs the actual BLS aggregate signature check.
func (fx *Fx) verifyAttestation(in *AttestationInput, cred *Credential, out *AttestationOutput) error {
	setBits := bitmapSetBits(in.Signers, len(out.PubKeys))
	if uint32(len(setBits)) < out.Threshold {
		return fmt.Errorf("%w: popcount %d < threshold %d",
			ErrSignerBitmapPopcount, len(setBits), out.Threshold)
	}
	// Reject bits set beyond the pubkey slice.
	totalSet := int(popcountBitmap(in.Signers))
	if totalSet != len(setBits) {
		return fmt.Errorf("%w: bitmap references bits beyond %d pubkeys",
			ErrSignerBitmapOutOfRange, len(out.PubKeys))
	}

	// Cache lookup keyed on (bitmap, AttestedHash, AggSig) — distinct attestations get distinct keys.
	cacheKey := verifyCacheKey(in.Signers, out.AttestedHash[:], cred.AggSig[:])
	if valid, ok := fx.verifyCache.Get(cacheKey); ok {
		if !valid {
			return ErrInvalidAggSig
		}
		return nil
	}

	pks := make([]*bls.PublicKey, 0, len(setBits))
	for _, i := range setBits {
		pk, err := bls.PublicKeyFromCompressedBytes(out.PubKeys[i])
		if err != nil {
			fx.verifyCache.Put(cacheKey, false)
			return fmt.Errorf("%w: pubkey %d: %v", ErrInvalidPubKeyLen, i, err)
		}
		pks = append(pks, pk)
	}
	aggPk, err := bls.AggregatePublicKeys(pks)
	if err != nil {
		fx.verifyCache.Put(cacheKey, false)
		return fmt.Errorf("%w: %v", ErrAggregatePubKeys, err)
	}
	sig, err := bls.SignatureFromBytes(cred.AggSig[:])
	if err != nil {
		fx.verifyCache.Put(cacheKey, false)
		return fmt.Errorf("%w: %v", ErrWrongAggSigLen, err)
	}

	msg := make([]byte, 0, len(attestationSignCtx)+len(out.AttestedHash))
	msg = append(msg, attestationSignCtx...)
	msg = append(msg, out.AttestedHash[:]...)
	valid := bls.Verify(aggPk, sig, msg)
	fx.verifyCache.Put(cacheKey, valid)
	if !valid {
		return ErrInvalidAggSig
	}
	return nil
}

func verifyCacheKey(bitmap, attestedHash, sig []byte) verifyKey {
	a := hash.ComputeHash256(bitmap)
	b := hash.ComputeHash256(attestedHash)
	c := hash.ComputeHash256(sig)
	combined := make([]byte, 0, len(a)+len(b)+len(c))
	combined = append(combined, a...)
	combined = append(combined, b...)
	combined = append(combined, c...)
	h := hash.ComputeHash256(combined)
	var id ids.ID
	copy(id[:], h)
	return id
}
