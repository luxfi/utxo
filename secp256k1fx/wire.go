// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1fx

import (
	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/ids"

	"github.com/luxfi/utxo/wire"
)

// TypeKind is the wire-level discriminator for every secp256k1fx
// primitive's wire envelope. Mirrors the codec.Manager slot the legacy
// linearcodec assigned to this fx — but as a single 1-byte tag, not a
// dense uint32 slot id.
const TypeKind = wire.TypeKindSecp256k1

// Bytes returns the ZAP-native wire envelope for this OutputOwners.
// Envelope = (TypeKindReserved, ShapeKindOutputOwners, ZAP message) —
// owners are not fx-owned (same wire payload is shared across every fx
// that has a multi-address ownership group).
func (out *OutputOwners) Bytes() []byte {
	return wire.NewOutputOwners(wire.OutputOwnersInput{
		Locktime:  out.Locktime,
		Threshold: out.Threshold,
		Addresses: out.Addrs,
	})
}

// WrapOutputOwners parses a wire envelope into a fresh OutputOwners.
// Envelope must carry ShapeKindOutputOwners.
func WrapOutputOwners(b []byte) (*OutputOwners, error) {
	v, err := wire.WrapOutputOwners(b)
	if err != nil {
		return nil, err
	}
	return &OutputOwners{
		Locktime:  v.Locktime(),
		Threshold: v.Threshold(),
		Addrs:     v.AddressList().All(),
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this TransferOutput.
// Envelope = (TypeKindSecp256k1, ShapeKindTransferOutput, ZAP message).
func (out *TransferOutput) Bytes() []byte {
	return wire.NewTransferOutput(wire.TransferOutputInput{
		TypeKind:  TypeKind,
		Amount:    out.Amt,
		Locktime:  out.Locktime,
		Threshold: out.Threshold,
		Addresses: out.Addrs,
	})
}

// WrapTransferOutput parses a wire envelope into a fresh TransferOutput.
// Envelope TypeKind must be TypeKindSecp256k1.
func WrapTransferOutput(b []byte) (*TransferOutput, error) {
	v, err := wire.WrapTransferOutput(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	return &TransferOutput{
		Amt: v.Amount(),
		OutputOwners: OutputOwners{
			Locktime:  v.Locktime(),
			Threshold: v.Threshold(),
			Addrs:     v.AddressList().All(),
		},
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this TransferInput.
// Envelope = (TypeKindSecp256k1, ShapeKindTransferInput, ZAP message).
func (in *TransferInput) Bytes() []byte {
	return wire.NewTransferInput(wire.TransferInputInput{
		TypeKind:   TypeKind,
		Amount:     in.Amt,
		SigIndices: in.SigIndices,
	})
}

// WrapTransferInput parses a wire envelope into a fresh TransferInput.
// Envelope TypeKind must be TypeKindSecp256k1.
func WrapTransferInput(b []byte) (*TransferInput, error) {
	v, err := wire.WrapTransferInput(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	return &TransferInput{
		Amt:   v.Amount(),
		Input: Input{SigIndices: v.SigIndices()},
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this MintOutput.
// Envelope = (TypeKindSecp256k1, ShapeKindMintOutput, ZAP message).
// Same payload as a TransferOutput's owner section but with
// ShapeKindMintOutput instead of ShapeKindTransferOutput.
func (out *MintOutput) Bytes() []byte {
	return wire.NewMintOutput(wire.MintOutputInput{
		TypeKind:  TypeKind,
		Locktime:  out.Locktime,
		Threshold: out.Threshold,
		Addresses: out.Addrs,
	})
}

// WrapMintOutput parses a wire envelope into a fresh MintOutput.
// Envelope TypeKind must be TypeKindSecp256k1.
func WrapMintOutput(b []byte) (*MintOutput, error) {
	v, err := wire.WrapMintOutput(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	return &MintOutput{
		OutputOwners: OutputOwners{
			Locktime:  v.Locktime(),
			Threshold: v.Threshold(),
			Addrs:     v.AddressList().All(),
		},
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this MintOperation.
// Envelope carries the operation's SigIndices + nested MintOutput +
// nested TransferOutput, each as length-prefixed bytes fields.
func (op *MintOperation) Bytes() []byte {
	return wire.NewMintOperation(wire.MintOperationInput{
		TypeKind:       TypeKind,
		SigIndices:     op.MintInput.SigIndices,
		MintOutput:     op.MintOutput.Bytes(),
		TransferOutput: op.TransferOutput.Bytes(),
	})
}

// WrapMintOperation parses a wire envelope into a fresh MintOperation.
// Envelope TypeKind must be TypeKindSecp256k1.
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
	transferOutput, err := WrapTransferOutput(v.TransferOutputBytes())
	if err != nil {
		return nil, err
	}
	return &MintOperation{
		MintInput:      Input{SigIndices: v.SigIndices()},
		MintOutput:     *mintOutput,
		TransferOutput: *transferOutput,
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this Credential.
// Envelope = (TypeKindSecp256k1, ShapeKindCredential, ZAP message).
// Signatures are concatenated into a single byte run (stride is
// secp256k1.SignatureLen = 65 bytes).
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

// WrapCredential parses a wire envelope into a fresh Credential. Each
// signature is exactly secp256k1.SignatureLen bytes; ErrShortEnvelope
// is returned when the byte run doesn't divide cleanly.
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
		raw := v.SignatureAt(i, secp256k1.SignatureLen)
		copy(sigs[i][:], raw)
	}
	return &Credential{Sigs: sigs}, nil
}

// ensure ids import is used (wire envelope tests + cross-fx assert helpers).
var _ ids.ShortID
