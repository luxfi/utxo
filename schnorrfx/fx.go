// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schnorrfx

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/luxfi/cache/lru"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/components/verify"
)

const verifyCacheSize = 256

// utxoSignCtx is the BIP-340 tagged-hash tag for domain-separating UTXO
// spending signatures from other Schnorr uses (Warp, precompile, MPC).
var utxoSignCtx = []byte("lux-x-chain-utxo-schnorr-v1")

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

// Fx describes the BIP-340 Schnorr feature extension for UTXO spending
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
		log.Debug("initializing schnorrfx")
	}

	if fx.VM == nil {
		return nil
	}

	// ZAP-native: wire schemas are compile-time static in the per-fx
	// wire.go bridge. No runtime codec registration needed.
	return nil
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

// taggedDigest computes BIP-340 tagged hash = SHA256(SHA256(tag) || SHA256(tag) || msg).
// This binds the signed message to the domain-separation tag, preventing
// cross-protocol signature replay.
func taggedDigest(tag, msg []byte) []byte {
	th := sha256.Sum256(tag)
	h := sha256.New()
	h.Write(th[:])
	h.Write(th[:])
	h.Write(msg)
	return h.Sum(nil)
}

// VerifyCredentials checks that (sig, pubkey) pairs in the credential are
// valid BIP-340 Schnorr signatures over the tagged-hash of the tx bytes, and
// that each pubkey maps to an address in the owners.
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
	digest := taggedDigest(utxoSignCtx, txBytes)
	for i, index := range in.SigIndices {
		if index >= uint32(len(out.Addrs)) {
			return ErrInputOutputIndexOutOfBounds
		}

		sig := cred.Sigs[i]

		if i >= len(cred.PubKeys) {
			return fmt.Errorf("%w: missing public key for signature %d", ErrWrongSig, i)
		}
		pkBytes := cred.PubKeys[i]
		if len(pkBytes) != PubKeyLen {
			return fmt.Errorf("%w: public key %d has wrong length %d", ErrWrongSig, i, len(pkBytes))
		}

		// Verify the pubkey maps to the expected address.
		addressBytes := hash.PubkeyBytesToAddress(pkBytes)
		expectedAddr, err := ids.ToShortID(addressBytes)
		if err != nil {
			return fmt.Errorf("%w: invalid address derivation: %v", ErrWrongSig, err)
		}
		if expectedAddr != out.Addrs[index] {
			return fmt.Errorf("%w: public key does not match address at index %d", ErrWrongSig, index)
		}

		cacheKey := verifyCacheKey(pkBytes, digest, sig[:])
		if valid, ok := fx.verifyCache.Get(cacheKey); ok {
			if !valid {
				return fmt.Errorf("%w: Schnorr verification failed for address %s (cached)",
					ErrWrongSig, out.Addrs[index])
			}
			continue
		}

		// Parse x-only pubkey and signature per BIP-340.
		pk, err := schnorr.ParsePubKey(pkBytes)
		if err != nil {
			fx.verifyCache.Put(cacheKey, false)
			return fmt.Errorf("%w: invalid x-only pubkey: %v", ErrWrongSig, err)
		}
		parsedSig, err := schnorr.ParseSignature(sig[:])
		if err != nil {
			fx.verifyCache.Put(cacheKey, false)
			return fmt.Errorf("%w: invalid Schnorr signature encoding: %v", ErrWrongSig, err)
		}

		valid := parsedSig.Verify(digest, pk)
		fx.verifyCache.Put(cacheKey, valid)
		if !valid {
			return fmt.Errorf("%w: Schnorr verification failed for address %s",
				ErrWrongSig, out.Addrs[index])
		}
	}

	return nil
}

func verifyCacheKey(pk, msgHash, sig []byte) verifyKey {
	pkHash := hash.ComputeHash256(pk)
	sigHash := hash.ComputeHash256(sig)
	combined := make([]byte, 0, len(pkHash)+len(msgHash)+len(sigHash))
	combined = append(combined, pkHash...)
	combined = append(combined, msgHash...)
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
