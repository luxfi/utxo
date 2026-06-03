// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519fx

import (
	"github.com/luxfi/utxo/wire"
)

// TypeKind is the wire-level discriminator for every ed25519fx
// primitive's wire envelope.
const TypeKind = wire.TypeKindEd25519

// Bytes returns the ZAP-native wire envelope for this OutputOwners.
// Envelope = (TypeKindReserved, ShapeKindOutputOwners, ZAP message) —
// owners are not fx-owned (same wire payload across every fx with a
// multi-ShortID ownership group).
func (out *OutputOwners) Bytes() []byte {
	return wire.NewOutputOwners(wire.OutputOwnersInput{
		Locktime:  out.Locktime,
		Threshold: out.Threshold,
		Addresses: out.Addrs,
	})
}

// WrapOutputOwners parses a wire envelope into a fresh OutputOwners.
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
func (in *TransferInput) Bytes() []byte {
	return wire.NewTransferInput(wire.TransferInputInput{
		TypeKind:   TypeKind,
		Amount:     in.Amt,
		SigIndices: in.SigIndices,
	})
}

// WrapTransferInput parses a wire envelope into a fresh TransferInput.
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
func (out *MintOutput) Bytes() []byte {
	return wire.NewMintOutput(wire.MintOutputInput{
		TypeKind:  TypeKind,
		Locktime:  out.Locktime,
		Threshold: out.Threshold,
		Addresses: out.Addrs,
	})
}

// WrapMintOutput parses a wire envelope into a fresh MintOutput.
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
func (op *MintOperation) Bytes() []byte {
	return wire.NewMintOperation(wire.MintOperationInput{
		TypeKind:       TypeKind,
		SigIndices:     op.MintInput.SigIndices,
		MintOutput:     op.MintOutput.Bytes(),
		TransferOutput: op.TransferOutput.Bytes(),
	})
}

// WrapMintOperation parses a wire envelope into a fresh MintOperation.
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

// Bytes returns the ZAP-native wire envelope for this Credential. Ed25519
// is not pubkey-recoverable from a signature, so the credential carries
// pubkeys alongside signatures. Both are concatenated into a single byte
// run with fixed per-element strides (SigLen / PubKeyLen).
func (cr *Credential) Bytes() []byte {
	sigsConcat := make([]byte, 0, len(cr.Sigs)*SigLen)
	for _, sig := range cr.Sigs {
		sigsConcat = append(sigsConcat, sig[:]...)
	}
	pksConcat := make([]byte, 0, len(cr.PubKeys)*PubKeyLen)
	for _, pk := range cr.PubKeys {
		pksConcat = append(pksConcat, pk...)
	}
	return wire.NewCredential(wire.CredentialInput{
		TypeKind:      TypeKind,
		SecurityLevel: 0,
		Signatures:    sigsConcat,
		PubKeys:       pksConcat,
	})
}

// WrapCredential parses a wire envelope into a fresh Credential. Each
// signature is exactly SigLen bytes; each pubkey is exactly PubKeyLen
// bytes.
func WrapCredential(b []byte) (*Credential, error) {
	v, err := wire.WrapCredential(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	n := v.SignatureCount(SigLen)
	sigs := make([][SigLen]byte, n)
	for i := 0; i < n; i++ {
		raw := v.SignatureAt(i, SigLen)
		copy(sigs[i][:], raw)
	}
	pkBytes := v.PubKeyBytes()
	pks := make([][]byte, 0, len(pkBytes)/PubKeyLen)
	for i := 0; i+PubKeyLen <= len(pkBytes); i += PubKeyLen {
		entry := make([]byte, PubKeyLen)
		copy(entry, pkBytes[i:i+PubKeyLen])
		pks = append(pks, entry)
	}
	return &Credential{Sigs: sigs, PubKeys: pks}, nil
}
