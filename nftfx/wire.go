// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package nftfx

import (
	"github.com/luxfi/crypto/secp256k1"

	"github.com/luxfi/utxo/secp256k1fx"
	"github.com/luxfi/utxo/wire"
)

// TypeKind is the wire-level discriminator for every nftfx primitive's
// wire envelope. nftfx is an application fx built on secp256k1
// credentials; the TypeKind names the fx family, not the curve.
const TypeKind = wire.TypeKindNFT

// Bytes returns the ZAP-native wire envelope for this MintOutput.
// Envelope = (TypeKindNFT, ShapeKindNFTMintOutput, ZAP message).
func (out *MintOutput) Bytes() []byte {
	return wire.NewNFTMintOutput(wire.NFTMintOutputInput{
		TypeKind:  TypeKind,
		GroupID:   out.GroupID,
		Locktime:  out.Locktime,
		Threshold: out.Threshold,
		Addresses: out.Addrs,
	})
}

// WrapMintOutput parses a wire envelope into a fresh MintOutput.
// Envelope TypeKind must be TypeKindNFT.
func WrapMintOutput(b []byte) (*MintOutput, error) {
	v, err := wire.WrapNFTMintOutput(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	return &MintOutput{
		GroupID: v.GroupID(),
		OutputOwners: secp256k1fx.OutputOwners{
			Locktime:  v.Locktime(),
			Threshold: v.Threshold(),
			Addrs:     v.AddressList().All(),
		},
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this TransferOutput.
// Envelope = (TypeKindNFT, ShapeKindNFTTransferOutput, ZAP message).
func (out *TransferOutput) Bytes() []byte {
	return wire.NewNFTTransferOutput(wire.NFTTransferOutputInput{
		TypeKind:  TypeKind,
		GroupID:   out.GroupID,
		Payload:   out.Payload,
		Locktime:  out.Locktime,
		Threshold: out.Threshold,
		Addresses: out.Addrs,
	})
}

// WrapTransferOutput parses a wire envelope into a fresh TransferOutput.
// Envelope TypeKind must be TypeKindNFT.
func WrapTransferOutput(b []byte) (*TransferOutput, error) {
	v, err := wire.WrapNFTTransferOutput(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	return &TransferOutput{
		GroupID: v.GroupID(),
		Payload: append([]byte(nil), v.Payload()...),
		OutputOwners: secp256k1fx.OutputOwners{
			Locktime:  v.Locktime(),
			Threshold: v.Threshold(),
			Addrs:     v.AddressList().All(),
		},
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this MintOperation.
// Each minted-to owner group is a nested OutputOwners envelope.
func (op *MintOperation) Bytes() []byte {
	owners := make([][]byte, len(op.Outputs))
	for i, o := range op.Outputs {
		owners[i] = o.Bytes()
	}
	return wire.NewNFTMintOperation(wire.NFTMintOperationInput{
		TypeKind:   TypeKind,
		SigIndices: op.MintInput.SigIndices,
		GroupID:    op.GroupID,
		Payload:    op.Payload,
		Owners:     owners,
	})
}

// WrapMintOperation parses a wire envelope into a fresh MintOperation.
// Envelope TypeKind must be TypeKindNFT.
func WrapMintOperation(b []byte) (*MintOperation, error) {
	v, err := wire.WrapNFTMintOperation(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	n := int(v.OwnersCount())
	outputs := make([]*secp256k1fx.OutputOwners, 0, n)
	blob := v.OwnersBytes()
	for i := 0; i < n; i++ {
		env, rest, err := wire.NextEnvelope(blob)
		if err != nil {
			return nil, err
		}
		owner, err := secp256k1fx.WrapOutputOwners(env)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, owner)
		blob = rest
	}
	return &MintOperation{
		MintInput: secp256k1fx.Input{SigIndices: v.SigIndices()},
		GroupID:   v.GroupID(),
		Payload:   append([]byte(nil), v.Payload()...),
		Outputs:   outputs,
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this TransferOperation.
func (op *TransferOperation) Bytes() []byte {
	return wire.NewNFTTransferOperation(wire.NFTTransferOperationInput{
		TypeKind:   TypeKind,
		SigIndices: op.Input.SigIndices,
		Output:     op.Output.Bytes(),
	})
}

// WrapTransferOperation parses a wire envelope into a fresh
// TransferOperation. Envelope TypeKind must be TypeKindNFT.
func WrapTransferOperation(b []byte) (*TransferOperation, error) {
	v, err := wire.WrapNFTTransferOperation(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	out, err := WrapTransferOutput(v.OutputBytes())
	if err != nil {
		return nil, err
	}
	return &TransferOperation{
		Input:  secp256k1fx.Input{SigIndices: v.SigIndices()},
		Output: *out,
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this Credential.
// Envelope = (TypeKindNFT, ShapeKindCredential, ZAP message) — the
// signatures are secp256k1 (nftfx is built on secp256k1 credentials);
// the TypeKind names the owning fx.
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
// Envelope TypeKind must be TypeKindNFT.
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
