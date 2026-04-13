// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519fx

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/luxfi/cache/lru"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/components/verify"
)

const verifyCacheSize = 256

var (
	ErrWrongVMType                    = errors.New("wrong vm type")
	ErrWrongTxType                    = errors.New("wrong tx type")
	ErrWrongOpType                    = errors.New("wrong operation type")
	ErrWrongUTXOType                  = errors.New("wrong utxo type")
	ErrWrongInputType                 = errors.New("wrong input type")
	ErrWrongCredentialType            = errors.New("wrong credential type")
	ErrWrongOwnerType                 = errors.New("wrong owner type")
	ErrMismatchedAmounts              = errors.New("utxo amount and input amount are not equal")
	ErrWrongNumberOfUTXOs             = errors.New("wrong number of utxos for the operation")
	ErrWrongMintCreated               = errors.New("wrong mint output created from the operation")
	ErrTimelocked                     = errors.New("output is time locked")
	ErrTooManySigners                 = errors.New("input has more signers than expected")
	ErrTooFewSigners                  = errors.New("input has less signers than expected")
	ErrInputOutputIndexOutOfBounds    = errors.New("input referenced a nonexistent address in the output")
	ErrInputCredentialSignersMismatch = errors.New("input expected a different number of signers than provided in the credential")
	ErrWrongSig                       = errors.New("wrong signature")
)

type verifyKey = ids.ID

// Fx describes the Ed25519 feature extension for UTXO spending
type Fx struct {
	VM           VM
	bootstrapped bool
	verifyCache  *lru.Cache[verifyKey, bool]
}

func (fx *Fx) Initialize(vmIntf interface{}) error {
	if err := fx.InitializeVM(vmIntf); err != nil {
		return err
	}

	fx.verifyCache = lru.NewCache[verifyKey, bool](verifyCacheSize)

	log := fx.VM.Logger()
	if !log.IsZero() {
		log.Debug("initializing ed25519fx")
	}

	if fx.VM == nil {
		return nil
	}

	c := fx.VM.CodecRegistry()
	if c == nil {
		return nil
	}

	errs := []error{}
	if err := c.RegisterType(&TransferInput{}); err != nil && !strings.Contains(err.Error(), "duplicate type registration") {
		errs = append(errs, err)
	}
	if err := c.RegisterType(&MintOutput{}); err != nil && !strings.Contains(err.Error(), "duplicate type registration") {
		errs = append(errs, err)
	}
	if err := c.RegisterType(&TransferOutput{}); err != nil && !strings.Contains(err.Error(), "duplicate type registration") {
		errs = append(errs, err)
	}
	if err := c.RegisterType(&MintOperation{}); err != nil && !strings.Contains(err.Error(), "duplicate type registration") {
		errs = append(errs, err)
	}
	if err := c.RegisterType(&Credential{}); err != nil && !strings.Contains(err.Error(), "duplicate type registration") {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (fx *Fx) InitializeVM(vmIntf interface{}) error {
	vm, ok := vmIntf.(VM)
	if !ok {
		return ErrWrongVMType
	}
	fx.VM = vm
	return nil
}

func (*Fx) Bootstrapping() error {
	return nil
}

func (fx *Fx) Bootstrapped() error {
	fx.bootstrapped = true
	return nil
}

// VerifyPermission returns nil iff [credIntf] proves that [ownerIntf] assents to [txIntf]
func (fx *Fx) VerifyPermission(txIntf, inIntf, credIntf, ownerIntf interface{}) error {
	tx, ok := txIntf.(UnsignedTx)
	if !ok {
		return ErrWrongTxType
	}
	in, ok := inIntf.(*Input)
	if !ok {
		return ErrWrongInputType
	}
	cred, ok := credIntf.(*Credential)
	if !ok {
		return ErrWrongCredentialType
	}
	owner, ok := ownerIntf.(*OutputOwners)
	if !ok {
		return ErrWrongOwnerType
	}
	if err := verify.All(in, cred, owner); err != nil {
		return err
	}
	return fx.VerifyCredentials(tx, in, cred, owner)
}

func (fx *Fx) VerifyOperation(txIntf, opIntf, credIntf interface{}, utxosIntf []interface{}) error {
	tx, ok := txIntf.(UnsignedTx)
	if !ok {
		return ErrWrongTxType
	}
	op, ok := opIntf.(*MintOperation)
	if !ok {
		return ErrWrongOpType
	}
	cred, ok := credIntf.(*Credential)
	if !ok {
		return ErrWrongCredentialType
	}
	if len(utxosIntf) != 1 {
		return ErrWrongNumberOfUTXOs
	}
	out, ok := utxosIntf[0].(*MintOutput)
	if !ok {
		return ErrWrongUTXOType
	}
	return fx.verifyOperation(tx, op, cred, out)
}

func (fx *Fx) verifyOperation(tx UnsignedTx, op *MintOperation, cred *Credential, utxo *MintOutput) error {
	if err := verify.All(op, cred, utxo); err != nil {
		return err
	}
	if !utxo.OutputOwners.Equals(&op.MintOutput.OutputOwners) {
		return ErrWrongMintCreated
	}
	return fx.VerifyCredentials(tx, &op.MintInput, cred, &utxo.OutputOwners)
}

func (fx *Fx) VerifyTransfer(txIntf, inIntf, credIntf, utxoIntf interface{}) error {
	tx, ok := txIntf.(UnsignedTx)
	if !ok {
		return ErrWrongTxType
	}
	in, ok := inIntf.(*TransferInput)
	if !ok {
		return ErrWrongInputType
	}
	cred, ok := credIntf.(*Credential)
	if !ok {
		return ErrWrongCredentialType
	}
	out, ok := utxoIntf.(*TransferOutput)
	if !ok {
		return ErrWrongUTXOType
	}
	return fx.VerifySpend(tx, in, cred, out)
}

// VerifySpend ensures that the utxo can be sent to any address
func (fx *Fx) VerifySpend(utx UnsignedTx, in *TransferInput, cred *Credential, utxo *TransferOutput) error {
	if err := verify.All(utxo, in, cred); err != nil {
		return err
	}
	if utxo.Amt != in.Amt {
		return fmt.Errorf("%w: %d != %d", ErrMismatchedAmounts, utxo.Amt, in.Amt)
	}
	return fx.VerifyCredentials(utx, &in.Input, cred, &utxo.OutputOwners)
}

// VerifyCredentials ensures that the output can be spent by the input with the
// credential. Ed25519 signatures are verified by recovering the public key from
// the stored address is not possible (unlike secp256k1), so we must store the
// full 32-byte public key in the credential alongside the signature.
//
// However, to match the secp256k1fx pattern (addresses in OutputOwners, sigs in
// Credential), we verify by:
// 1. The Credential stores [SigLen]byte signatures.
// 2. We need the public key to verify — so for Ed25519, OutputOwners.Addrs are
//    20-byte hashes. The wallet must provide the pubkey→address mapping.
//
// For Ed25519, we use a different approach than secp256k1: the tx bytes are
// signed directly, and verification requires the public key. Since we only store
// 20-byte address hashes in OutputOwners, the Credential carries fixed-size
// 64-byte Ed25519 signatures. The wallet must ensure the pubkey maps to the
// address via hash.PubkeyBytesToAddress.
//
// NOTE: Ed25519 cannot recover the public key from a signature (unlike secp256k1).
// So we verify by having the signer provide the pubkey alongside the signature.
// The Credential carries (sig, pubkey) pairs encoded as [SigLen]byte for the sig,
// and we keep a pubkey cache. For simplicity in Phase 1, we extend Credential to
// carry pubkeys.
func (fx *Fx) VerifyCredentials(utx UnsignedTx, in *Input, cred *Credential, out *OutputOwners) error {
	numSigs := len(in.SigIndices)
	switch {
	case out.Locktime > fx.VM.Clock().Unix():
		return ErrTimelocked
	case out.Threshold < uint32(numSigs):
		return ErrTooManySigners
	case out.Threshold > uint32(numSigs):
		return ErrTooFewSigners
	case numSigs != len(cred.Sigs):
		return ErrInputCredentialSignersMismatch
	case !fx.bootstrapped:
		return nil
	}

	txBytes := utx.Bytes()
	txHash := hash.ComputeHash256(txBytes)
	for i, index := range in.SigIndices {
		if index >= uint32(len(out.Addrs)) {
			return ErrInputOutputIndexOutOfBounds
		}

		sig := cred.Sigs[i]

		if i >= len(cred.PubKeys) {
			return fmt.Errorf("%w: missing public key for signature %d", ErrWrongSig, i)
		}
		pk := cred.PubKeys[i]
		if len(pk) != PubKeyLen {
			return fmt.Errorf("%w: public key %d has wrong length %d", ErrWrongSig, i, len(pk))
		}

		// Verify the pubkey maps to the expected address
		addressBytes := hash.PubkeyBytesToAddress(pk)
		expectedAddr, err := ids.ToShortID(addressBytes)
		if err != nil {
			return fmt.Errorf("%w: invalid address derivation: %v", ErrWrongSig, err)
		}
		if expectedAddr != out.Addrs[index] {
			return fmt.Errorf("%w: public key does not match address at index %d", ErrWrongSig, index)
		}

		cacheKey := verifyCacheKey(pk, txHash, sig[:])
		if valid, ok := fx.verifyCache.Get(cacheKey); ok {
			if !valid {
				return fmt.Errorf("%w: Ed25519 verification failed for address %s (cached)",
					ErrWrongSig, out.Addrs[index])
			}
			continue
		}

		valid := ed25519.Verify(ed25519.PublicKey(pk), txBytes, sig[:])
		fx.verifyCache.Put(cacheKey, valid)
		if !valid {
			return fmt.Errorf("%w: Ed25519 verification failed for address %s",
				ErrWrongSig, out.Addrs[index])
		}
	}

	return nil
}

func verifyCacheKey(pk, txHash, sig []byte) verifyKey {
	pkHash := hash.ComputeHash256(pk)
	sigHash := hash.ComputeHash256(sig)
	combined := make([]byte, 0, len(pkHash)+len(txHash)+len(sigHash))
	combined = append(combined, pkHash...)
	combined = append(combined, txHash...)
	combined = append(combined, sigHash...)
	h := hash.ComputeHash256(combined)
	var id ids.ID
	copy(id[:], h)
	return id
}

// CreateOutput creates a new output with the provided control group worth
// the specified amount
func (*Fx) CreateOutput(amount uint64, ownerIntf interface{}) (interface{}, error) {
	owner, ok := ownerIntf.(*OutputOwners)
	if !ok {
		return nil, ErrWrongOwnerType
	}
	if err := owner.Verify(); err != nil {
		return nil, err
	}
	return &TransferOutput{
		Amt:          amount,
		OutputOwners: *owner,
	}, nil
}
