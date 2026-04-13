// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsafx

import (
	"errors"
	"fmt"
	"strings"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/vm/components/verify"
)

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

// Fx describes the ML-DSA feature extension for post-quantum secure UTXO spending
type Fx struct {
	VM           VM
	bootstrapped bool
}

func (fx *Fx) Initialize(vmIntf interface{}) error {
	if err := fx.InitializeVM(vmIntf); err != nil {
		return err
	}

	log := fx.VM.Logger()
	if !log.IsZero() {
		log.Debug("initializing mldsafx")
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
// credential. ML-DSA-65 signatures are verified directly against the public key
// stored in OutputOwners.Addrs.
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
	case !fx.bootstrapped: // disable signature verification during bootstrapping
		return nil
	}

	txBytes := utx.Bytes()
	for i, index := range in.SigIndices {
		if index >= uint32(len(out.Addrs)) {
			return ErrInputOutputIndexOutOfBounds
		}

		sig := cred.Sigs[i]
		pkBytes := out.Addrs[index]

		// Reconstruct public key and verify ML-DSA-65 signature
		pk, err := mldsa.PublicKeyFromBytes(pkBytes, mldsaMode(out.Level))
		if err != nil {
			return fmt.Errorf("%w: invalid public key at index %d: %v", ErrWrongSig, index, err)
		}

		if !pk.VerifySignature(txBytes, sig) {
			// Derive address for error message
			addressBytes := hash.PubkeyBytesToAddress(pkBytes)
			return fmt.Errorf("%w: ML-DSA-65 verification failed for address %x",
				ErrWrongSig, addressBytes)
		}
	}

	return nil
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

// mldsaMode converts SecurityLevel to mldsa.Mode
func mldsaMode(level SecurityLevel) mldsa.Mode {
	switch level {
	case SecLevelMLDSA44:
		return mldsa.MLDSA44
	case SecLevelMLDSA65:
		return mldsa.MLDSA65
	case SecLevelMLDSA87:
		return mldsa.MLDSA87
	default:
		return mldsa.MLDSA65
	}
}
