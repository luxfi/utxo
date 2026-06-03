// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381fx

import (
	"github.com/luxfi/utxo/wire"
)

// TypeKind is the wire-level discriminator for every bls12381fx primitive's
// wire envelope. bls12381fx is attestation-only: AttestationOutput,
// AttestationInput, Credential — no transfer or mint primitives.
const TypeKind = wire.TypeKindBLS12381

// Bytes returns the ZAP-native wire envelope for this AttestationOutput.
// Envelope = (TypeKindBLS12381, ShapeKindAttestationOut, ZAP message).
func (out *AttestationOutput) Bytes() []byte {
	return wire.NewAttestationOutput(wire.AttestationOutputInput{
		AttestedHash: out.AttestedHash,
		Threshold:    out.Threshold,
		PubKeys:      out.PubKeys,
	})
}

// WrapAttestationOutput parses a wire envelope into a fresh
// AttestationOutput.
func WrapAttestationOutput(b []byte) (*AttestationOutput, error) {
	v, err := wire.WrapAttestationOutput(b)
	if err != nil {
		return nil, err
	}
	return &AttestationOutput{
		AttestedHash: v.AttestedHash(),
		Threshold:    v.Threshold(),
		PubKeys:      v.PubKeys(),
	}, nil
}

// Bytes returns the ZAP-native wire envelope for this AttestationInput.
// Envelope = (TypeKindBLS12381, ShapeKindAttestationIn, ZAP message).
func (in *AttestationInput) Bytes() []byte {
	return wire.NewAttestationInput(wire.AttestationInputInput{
		SignerBitmap: in.Signers,
	})
}

// WrapAttestationInput parses a wire envelope into a fresh
// AttestationInput.
func WrapAttestationInput(b []byte) (*AttestationInput, error) {
	v, err := wire.WrapAttestationInput(b)
	if err != nil {
		return nil, err
	}
	bitmap := v.SignerBitmap()
	signers := make([]byte, len(bitmap))
	copy(signers, bitmap)
	return &AttestationInput{Signers: signers}, nil
}

// Bytes returns the ZAP-native wire envelope for this Credential.
// bls12381fx Credentials carry a single aggregate G2 signature (96 bytes);
// there is no notion of "per-signer signature" in BLS aggregate semantics.
func (cr *Credential) Bytes() []byte {
	return wire.NewCredential(wire.CredentialInput{
		TypeKind:      TypeKind,
		SecurityLevel: 0,
		Signatures:    cr.AggSig[:],
	})
}

// WrapCredential parses a wire envelope into a fresh Credential.
func WrapCredential(b []byte) (*Credential, error) {
	v, err := wire.WrapCredential(b)
	if err != nil {
		return nil, err
	}
	if v.TypeKind() != TypeKind {
		return nil, wire.ErrWrongTypeKind
	}
	out := &Credential{}
	sig := v.SignatureBytes()
	if len(sig) != SigLen {
		return nil, ErrWrongAggSigLen
	}
	copy(out.AggSig[:], sig)
	return out, nil
}
