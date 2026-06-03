// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsafx

import (
	"bytes"
	"testing"
)

func TestWire_OutputOwners_RoundTrip(t *testing.T) {
	// Two ML-DSA-65 pubkeys; build them so pk1 < pk2 lexicographically.
	pk1 := make([]byte, MLDSA65PubKeyLen)
	pk2 := make([]byte, MLDSA65PubKeyLen)
	for i := range pk1 {
		pk1[i] = byte(i)
	}
	for i := range pk2 {
		pk2[i] = byte(0xFF - i)
	}
	in := &OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  9999,
		Threshold: 1,
		Addrs:     [][]byte{pk1, pk2},
	}
	got, err := WrapOutputOwners(in.Bytes())
	if err != nil {
		t.Fatalf("WrapOutputOwners: %v", err)
	}
	if got.Level != SecLevelMLDSA65 {
		t.Errorf("Level: got %v, want %v", got.Level, SecLevelMLDSA65)
	}
	if got.Locktime != 9999 {
		t.Errorf("Locktime: got %d, want 9999", got.Locktime)
	}
	if got.Threshold != 1 {
		t.Errorf("Threshold: got %d, want 1", got.Threshold)
	}
	if len(got.Addrs) != 2 {
		t.Fatalf("Addrs.Len: got %d, want 2", len(got.Addrs))
	}
	if !bytes.Equal(got.Addrs[0], pk1) {
		t.Errorf("Addrs[0] mismatch")
	}
	if !bytes.Equal(got.Addrs[1], pk2) {
		t.Errorf("Addrs[1] mismatch")
	}
}

func TestWire_TransferOutput_RoundTrip(t *testing.T) {
	pk := make([]byte, MLDSA65PubKeyLen)
	for i := range pk {
		pk[i] = byte(i)
	}
	in := &TransferOutput{
		Amt: 7_777_777,
		OutputOwners: OutputOwners{
			Level:     SecLevelMLDSA65,
			Locktime:  42,
			Threshold: 1,
			Addrs:     [][]byte{pk},
		},
	}
	got, err := WrapTransferOutput(in.Bytes())
	if err != nil {
		t.Fatalf("WrapTransferOutput: %v", err)
	}
	if got.Amt != in.Amt {
		t.Errorf("Amt: got %d, want %d", got.Amt, in.Amt)
	}
	if !got.OutputOwners.Equals(&in.OutputOwners) {
		t.Errorf("OutputOwners mismatch")
	}
}

func TestWire_TransferInput_RoundTrip(t *testing.T) {
	in := &TransferInput{
		Amt:   500,
		Input: Input{SigIndices: []uint32{0, 2, 5, 7}},
	}
	got, err := WrapTransferInput(in.Bytes())
	if err != nil {
		t.Fatalf("WrapTransferInput: %v", err)
	}
	if got.Amt != in.Amt {
		t.Errorf("Amt: got %d, want %d", got.Amt, in.Amt)
	}
	if len(got.SigIndices) != len(in.SigIndices) {
		t.Fatalf("SigIndices.Len: got %d, want %d", len(got.SigIndices), len(in.SigIndices))
	}
	for i, v := range in.SigIndices {
		if got.SigIndices[i] != v {
			t.Errorf("SigIndices[%d]: got %d, want %d", i, got.SigIndices[i], v)
		}
	}
}

func TestWire_MintOutput_RoundTrip(t *testing.T) {
	pk := make([]byte, MLDSA65PubKeyLen)
	for i := range pk {
		pk[i] = byte(i + 7)
	}
	in := &MintOutput{
		OutputOwners: OutputOwners{
			Level:     SecLevelMLDSA65,
			Locktime:  0,
			Threshold: 1,
			Addrs:     [][]byte{pk},
		},
	}
	got, err := WrapMintOutput(in.Bytes())
	if err != nil {
		t.Fatalf("WrapMintOutput: %v", err)
	}
	if !got.OutputOwners.Equals(&in.OutputOwners) {
		t.Errorf("OutputOwners mismatch")
	}
}

func TestWire_MintOperation_RoundTrip(t *testing.T) {
	pk := make([]byte, MLDSA65PubKeyLen)
	for i := range pk {
		pk[i] = byte(i)
	}
	owners := OutputOwners{
		Level:     SecLevelMLDSA65,
		Locktime:  0,
		Threshold: 1,
		Addrs:     [][]byte{pk},
	}
	in := &MintOperation{
		MintInput: Input{SigIndices: []uint32{0}},
		MintOutput: MintOutput{
			OutputOwners: owners,
		},
		TransferOutput: TransferOutput{
			Amt:          100,
			OutputOwners: owners,
		},
	}
	got, err := WrapMintOperation(in.Bytes())
	if err != nil {
		t.Fatalf("WrapMintOperation: %v", err)
	}
	if got.TransferOutput.Amt != 100 {
		t.Errorf("TransferOutput.Amt: got %d, want 100", got.TransferOutput.Amt)
	}
}

func TestWire_Credential_RoundTrip_MLDSA65(t *testing.T) {
	sig1 := make([]byte, MLDSA65SigLen)
	sig2 := make([]byte, MLDSA65SigLen)
	for i := range sig1 {
		sig1[i] = byte(i)
	}
	for i := range sig2 {
		sig2[i] = byte(0xFF - i)
	}
	in := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{sig1, sig2},
	}
	got, err := WrapCredential(in.Bytes())
	if err != nil {
		t.Fatalf("WrapCredential: %v", err)
	}
	if got.Level != SecLevelMLDSA65 {
		t.Errorf("Level: got %v, want %v", got.Level, SecLevelMLDSA65)
	}
	if len(got.Sigs) != 2 {
		t.Fatalf("Sigs.Len: got %d, want 2", len(got.Sigs))
	}
	if !bytes.Equal(got.Sigs[0], sig1) {
		t.Errorf("Sigs[0] mismatch")
	}
	if !bytes.Equal(got.Sigs[1], sig2) {
		t.Errorf("Sigs[1] mismatch")
	}
}

func TestWire_Credential_RoundTrip_MLDSA44(t *testing.T) {
	sig := make([]byte, MLDSA44SigLen)
	for i := range sig {
		sig[i] = byte(i)
	}
	in := &Credential{
		Level: SecLevelMLDSA44,
		Sigs:  [][]byte{sig},
	}
	got, err := WrapCredential(in.Bytes())
	if err != nil {
		t.Fatalf("WrapCredential: %v", err)
	}
	if got.Level != SecLevelMLDSA44 {
		t.Errorf("Level: got %v, want %v", got.Level, SecLevelMLDSA44)
	}
	if !bytes.Equal(got.Sigs[0], sig) {
		t.Errorf("Sigs[0] mismatch")
	}
}
