// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package propertyfx

import (
	"github.com/luxfi/crypto/secp256k1"

	"github.com/luxfi/utxo/secp256k1fx"
	"github.com/luxfi/utxo/wire"
)

// TypeKind is the wire-level discriminator for every propertyfx
// primitive's wire envelope. propertyfx is an application fx built on
// secp256k1 credentials; the TypeKind names the fx family.
const TypeKind = wire.TypeKindProperty

// Bytes returns the ZAP-native wire envelope for this MintOutput.
// Envelope = (TypeKindProperty, ShapeKindMintOutput, ZAP message) — a
// bare owners group; the shared MintOutput shape fits exactly.
func (out *MintOutput) Bytes() []byte {
	return wire.NewMintOutput(wire.MintOutputInput{
		TypeKind:  TypeKind,
		Locktime:  out.Locktime,
		Threshold: out.Threshold,
		Addresses: out.Addrs,
	})
}

// WrapMintOutput parses a wire envelope into a fresh MintOutput.
// Envelope TypeKind must be TypeKindProperty.
func WrapMintOutput(b []byte) (*MintOutput, error) {
	v, err := wire.WrapMintOutput(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	return &MintOutput{
		OutputOwners: secp256k1fx.OutputOwners{
			Locktime:  v.Locktime(),
			Threshold: v.Threshold(),
			Addrs:     v.AddressList().All(),
		},
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this OwnedOutput.
// Envelope = (TypeKindProperty, ShapeKindOwnedOutput, ZAP message) —
// same payload as MintOutput; the distinct ShapeKind separates the
// property state output from the mint authority.
func (out *OwnedOutput) Bytes() []byte {
	return wire.NewOwnedOutput(wire.OwnedOutputInput{
		TypeKind:  TypeKind,
		Locktime:  out.Locktime,
		Threshold: out.Threshold,
		Addresses: out.Addrs,
	})
}

// WrapOwnedOutput parses a wire envelope into a fresh OwnedOutput.
// Envelope TypeKind must be TypeKindProperty.
func WrapOwnedOutput(b []byte) (*OwnedOutput, error) {
	v, err := wire.WrapOwnedOutput(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	return &OwnedOutput{
		OutputOwners: secp256k1fx.OutputOwners{
			Locktime:  v.Locktime(),
			Threshold: v.Threshold(),
			Addrs:     v.AddressList().All(),
		},
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this MintOperation.
// The shared MintOperation shape carries SigIndices + two nested output
// envelopes; the nested blobs self-discriminate (MintOutput slot carries
// the property MintOutput, TransferOutput slot carries the OwnedOutput).
func (op *MintOperation) Bytes() []byte {
	return wire.NewMintOperation(wire.MintOperationInput{
		TypeKind:       TypeKind,
		SigIndices:     op.MintInput.SigIndices,
		MintOutput:     op.MintOutput.Bytes(),
		TransferOutput: op.OwnedOutput.Bytes(),
	})
}

// WrapMintOperation parses a wire envelope into a fresh MintOperation.
// Envelope TypeKind must be TypeKindProperty.
func WrapMintOperation(b []byte) (*MintOperation, error) {
	v, err := wire.WrapMintOperation(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	mintOutput, err := WrapMintOutput(v.MintOutputBytes())
	if err != nil {
		return nil, err
	}
	ownedOutput, err := WrapOwnedOutput(v.TransferOutputBytes())
	if err != nil {
		return nil, err
	}
	return &MintOperation{
		MintInput:   secp256k1fx.Input{SigIndices: v.SigIndices()},
		MintOutput:  *mintOutput,
		OwnedOutput: *ownedOutput,
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this BurnOperation.
func (op *BurnOperation) Bytes() []byte {
	return wire.NewBurnOperation(wire.BurnOperationInput{
		TypeKind:   TypeKind,
		SigIndices: op.SigIndices,
	})
}

// WrapBurnOperation parses a wire envelope into a fresh BurnOperation.
// Envelope TypeKind must be TypeKindProperty.
func WrapBurnOperation(b []byte) (*BurnOperation, error) {
	v, err := wire.WrapBurnOperation(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	return &BurnOperation{
		Input: secp256k1fx.Input{SigIndices: v.SigIndices()},
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this Credential.
func (cr *Credential) Bytes() []byte {
	sigsConcat := make([]byte, 0, len(cr.Sigs)*secp256k1.SignatureLen)
	for _, sig := range cr.Sigs {
		sigsConcat = append(sigsConcat, sig[:]...)
	}
	return wire.NewCredential(wire.CredentialInput{
		TypeKind:      TypeKind,
		SecurityLevel: 0,
		Signatures:    sigsConcat,
	})
}

// WrapCredential parses a wire envelope into a fresh Credential.
// Envelope TypeKind must be TypeKindProperty.
func WrapCredential(b []byte) (*Credential, error) {
	v, err := wire.WrapCredential(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	n := v.SignatureCount(secp256k1.SignatureLen)
	sigs := make([][secp256k1.SignatureLen]byte, n)
	for i := 0; i < n; i++ {
		copy(sigs[i][:], v.SignatureAt(i, secp256k1.SignatureLen))
	}
	return &Credential{Credential: secp256k1fx.Credential{Sigs: sigs}}, nil
}
