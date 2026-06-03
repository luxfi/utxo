// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381fx

import (
	"bytes"
	"testing"
)

func TestWire_AttestationOutput_RoundTrip(t *testing.T) {
	pk1 := make([]byte, PubKeyLen)
	pk2 := make([]byte, PubKeyLen)
	for i := range pk1 {
		pk1[i] = byte(i)
	}
	for i := range pk2 {
		pk2[i] = byte(0xFF - i)
	}
	in := &AttestationOutput{
		AttestedHash: [AttestedHashLen]byte{1, 2, 3, 4, 5},
		Threshold:    2,
		PubKeys:      [][]byte{pk1, pk2},
	}
	got, err := WrapAttestationOutput(in.Bytes())
	if err != nil {
		t.Fatalf("WrapAttestationOutput: %v", err)
	}
	if got.AttestedHash != in.AttestedHash {
		t.Errorf("AttestedHash mismatch")
	}
	if got.Threshold != in.Threshold {
		t.Errorf("Threshold: got %d, want %d", got.Threshold, in.Threshold)
	}
	if len(got.PubKeys) != 2 {
		t.Fatalf("PubKeys.Len: got %d, want 2", len(got.PubKeys))
	}
	if !bytes.Equal(got.PubKeys[0], pk1) {
		t.Errorf("PubKeys[0] mismatch")
	}
	if !bytes.Equal(got.PubKeys[1], pk2) {
		t.Errorf("PubKeys[1] mismatch")
	}
}

func TestWire_AttestationInput_RoundTrip(t *testing.T) {
	bitmap := []byte{0x05, 0x80}
	in := &AttestationInput{Signers: bitmap}
	got, err := WrapAttestationInput(in.Bytes())
	if err != nil {
		t.Fatalf("WrapAttestationInput: %v", err)
	}
	if !bytes.Equal(got.Signers, bitmap) {
		t.Errorf("Signers: got %x, want %x", got.Signers, bitmap)
	}
}

func TestWire_Credential_RoundTrip(t *testing.T) {
	var aggSig [SigLen]byte
	for i := range aggSig {
		aggSig[i] = byte(i)
	}
	in := &Credential{AggSig: aggSig}
	got, err := WrapCredential(in.Bytes())
	if err != nil {
		t.Fatalf("WrapCredential: %v", err)
	}
	if !bytes.Equal(got.AggSig[:], aggSig[:]) {
		t.Errorf("AggSig mismatch")
	}
}
