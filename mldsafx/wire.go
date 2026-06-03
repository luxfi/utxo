// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsafx

import (
	"errors"
	"fmt"

	"github.com/luxfi/utxo/wire"
)

// TypeKind is the wire-level discriminator for every mldsafx primitive's
// wire envelope.
const TypeKind = wire.TypeKindMLDSA

// ErrUnknownSecurityLevel is returned when a wire envelope carries a
// SecurityLevel byte the fx package does not recognize. Re-exposes the
// fx-package ErrInvalidSecLevel for callers that switch on the wire
// error.
var ErrUnknownSecurityLevel = errors.New("mldsafx: wire envelope carries unrecognized SecurityLevel")

// strideForLevel resolves the wire-level uint8 SecurityLevel byte into a
// per-pubkey stride (in bytes). The wire layer is stride-agnostic; this
// mapping is the only place mldsafx-specific byte widths leak in.
func strideForLevel(level uint8) (int, error) {
	switch SecurityLevel(level) {
	case SecLevelMLDSA44:
		return MLDSA44PubKeyLen, nil
	case SecLevelMLDSA65:
		return MLDSA65PubKeyLen, nil
	case SecLevelMLDSA87:
		return MLDSA87PubKeyLen, nil
	default:
		return 0, fmt.Errorf("%w: %d", ErrUnknownSecurityLevel, level)
	}
}

// Bytes returns the ZAP-native wire envelope for this OutputOwners.
// Envelope = (TypeKindMLDSA, ShapeKindPQOutputOwners, ZAP message).
func (out *OutputOwners) Bytes() []byte {
	return wire.NewPQOutputOwners(wire.PQOutputOwnersInput{
		TypeKind:      TypeKind,
		SecurityLevel: uint8(out.Level),
		Locktime:      out.Locktime,
		Threshold:     out.Threshold,
		PubKeyStride:  out.Level.PubKeyLen(),
		PubKeys:       out.Addrs,
	})
}

// WrapOutputOwners parses a wire envelope into a fresh OutputOwners.
// Envelope TypeKind must be TypeKindMLDSA; the SecurityLevel byte
// selects the pubkey stride.
func WrapOutputOwners(b []byte) (*OutputOwners, error) {
	// Peek the SecurityLevel byte without parsing the message twice. The
	// SecurityLevel field is at wire offset 0 inside the ZAP message
	// body, so we read it by parsing once with stride=1 (which always
	// succeeds) and then re-parsing with the correct stride. The extra
	// parse is acceptable because PQOutputOwners messages are
	// medium-sized (a few kB) and verification is the bottleneck.
	tmp, err := wire.WrapPQOutputOwners(b, 1)
	if err != nil {
		return nil, err
	}
	if tmp.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	stride, err := strideForLevel(tmp.SecurityLevel())
	if err != nil {
		return nil, err
	}
	v, err := wire.WrapPQOutputOwners(b, stride)
	if err != nil {
		return nil, err
	}
	return &OutputOwners{
		Level:     SecurityLevel(v.SecurityLevel()),
		Locktime:  v.Locktime(),
		Threshold: v.Threshold(),
		Addrs:     v.PubKeys().All(),
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this TransferOutput.
// Envelope = (TypeKindMLDSA, ShapeKindPQTransferOutput, ZAP message).
func (out *TransferOutput) Bytes() []byte {
	return wire.NewPQTransferOutput(wire.PQTransferOutputInput{
		TypeKind:      TypeKind,
		SecurityLevel: uint8(out.Level),
		Amount:        out.Amt,
		Locktime:      out.Locktime,
		Threshold:     out.Threshold,
		PubKeyStride:  out.Level.PubKeyLen(),
		PubKeys:       out.Addrs,
	})
}

// WrapTransferOutput parses a wire envelope into a fresh TransferOutput.
func WrapTransferOutput(b []byte) (*TransferOutput, error) {
	tmp, err := wire.WrapPQTransferOutput(b, 1)
	if err != nil {
		return nil, err
	}
	if tmp.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	stride, err := strideForLevel(tmp.SecurityLevel())
	if err != nil {
		return nil, err
	}
	v, err := wire.WrapPQTransferOutput(b, stride)
	if err != nil {
		return nil, err
	}
	return &TransferOutput{
		Amt: v.Amount(),
		OutputOwners: OutputOwners{
			Level:     SecurityLevel(v.SecurityLevel()),
			Locktime:  v.Locktime(),
			Threshold: v.Threshold(),
			Addrs:     v.PubKeys().All(),
		},
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this TransferInput.
// Envelope = (TypeKindMLDSA, ShapeKindTransferInput, ZAP message).
// The TransferInput shape is shared across classical and PQ fxs — the
// per-fx variation lives only in the matching Credential's signature
// stride.
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
// Envelope = (TypeKindMLDSA, ShapeKindPQMintOutput, ZAP message).
func (out *MintOutput) Bytes() []byte {
	return wire.NewPQMintOutput(wire.PQMintOutputInput{
		TypeKind:      TypeKind,
		SecurityLevel: uint8(out.Level),
		Locktime:      out.Locktime,
		Threshold:     out.Threshold,
		PubKeyStride:  out.Level.PubKeyLen(),
		PubKeys:       out.Addrs,
	})
}

// WrapMintOutput parses a wire envelope into a fresh MintOutput.
func WrapMintOutput(b []byte) (*MintOutput, error) {
	tmp, err := wire.WrapPQMintOutput(b, 1)
	if err != nil {
		return nil, err
	}
	if tmp.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	stride, err := strideForLevel(tmp.SecurityLevel())
	if err != nil {
		return nil, err
	}
	v, err := wire.WrapPQMintOutput(b, stride)
	if err != nil {
		return nil, err
	}
	return &MintOutput{
		OutputOwners: OutputOwners{
			Level:     SecurityLevel(v.SecurityLevel()),
			Locktime:  v.Locktime(),
			Threshold: v.Threshold(),
			Addrs:     v.PubKeys().All(),
		},
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this MintOperation.
// Envelope carries SigIndices + nested MintOutput + nested TransferOutput
// wire bytes.
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

// Bytes returns the ZAP-native wire envelope for this Credential.
// Envelope = (TypeKindMLDSA, ShapeKindCredential, ZAP message). Signatures
// are concatenated into a single byte run; per-signature stride is
// resolved at parse time via the SecurityLevel byte.
func (cr *Credential) Bytes() []byte {
	sigsConcat := make([]byte, 0, len(cr.Sigs)*cr.Level.SignatureLen())
	for _, sig := range cr.Sigs {
		sigsConcat = append(sigsConcat, sig...)
	}
	return wire.NewCredential(wire.CredentialInput{
		TypeKind:      TypeKind,
		SecurityLevel: uint8(cr.Level),
		Signatures:    sigsConcat,
	})
}

// WrapCredential parses a wire envelope into a fresh Credential. The
// SecurityLevel byte selects the per-signature stride; the byte run
// is split into Sigs accordingly.
func WrapCredential(b []byte) (*Credential, error) {
	v, err := wire.WrapCredential(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	level := SecurityLevel(v.SecurityLevel())
	sigLen := level.SignatureLen()
	if sigLen == 0 {
		return nil, fmt.Errorf("%w: %d", ErrUnknownSecurityLevel, v.SecurityLevel())
	}
	n := v.SignatureCount(sigLen)
	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		sigs[i] = v.SignatureAt(i, sigLen)
	}
	return &Credential{Level: level, Sigs: sigs}, nil
}
