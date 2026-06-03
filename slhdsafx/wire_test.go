// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsafx

import (
	"bytes"
	"testing"
)

func TestWire_OutputOwners_RoundTrip(t *testing.T) {
	pk1 := make([]byte, SLH192fPubKeyLen)
	pk2 := make([]byte, SLH192fPubKeyLen)
	for i := range pk1 {
		pk1[i] = byte(i)
	}
	for i := range pk2 {
		pk2[i] = byte(0xFF - i)
	}
	in := &OutputOwners{
		Level:     SecLevelSLH192f,
		Locktime:  9999,
		Threshold: 1,
		Addrs:     [][]byte{pk1, pk2},
	}
	got, err := WrapOutputOwners(in.Bytes())
	if err != nil {
		t.Fatalf("WrapOutputOwners: %v", err)
	}
	if got.Level != SecLevelSLH192f {
		t.Errorf("Level: got %v, want %v", got.Level, SecLevelSLH192f)
	}
	if got.Threshold != 1 {
		t.Errorf("Threshold: got %d, want 1", got.Threshold)
	}
	if !bytes.Equal(got.Addrs[0], pk1) {
		t.Errorf("Addrs[0] mismatch")
	}
}

func TestWire_TransferOutput_RoundTrip(t *testing.T) {
	pk := make([]byte, SLH192fPubKeyLen)
	for i := range pk {
		pk[i] = byte(i)
	}
	in := &TransferOutput{
		Amt: 1_000_000,
		OutputOwners: OutputOwners{
			Level:     SecLevelSLH192f,
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
		Input: Input{SigIndices: []uint32{0, 1}},
	}
	got, err := WrapTransferInput(in.Bytes())
	if err != nil {
		t.Fatalf("WrapTransferInput: %v", err)
	}
	if got.Amt != in.Amt {
		t.Errorf("Amt: got %d, want %d", got.Amt, in.Amt)
	}
	if len(got.SigIndices) != 2 {
		t.Fatalf("SigIndices.Len: got %d, want 2", len(got.SigIndices))
	}
}

func TestWire_MintOutput_RoundTrip(t *testing.T) {
	pk := make([]byte, SLH192fPubKeyLen)
	for i := range pk {
		pk[i] = byte(i + 7)
	}
	in := &MintOutput{
		OutputOwners: OutputOwners{
			Level:     SecLevelSLH192f,
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
	pk := make([]byte, SLH192fPubKeyLen)
	for i := range pk {
		pk[i] = byte(i)
	}
	owners := OutputOwners{
		Level:     SecLevelSLH192f,
		Threshold: 1,
		Addrs:     [][]byte{pk},
	}
	in := &MintOperation{
		MintInput:      Input{SigIndices: []uint32{0}},
		MintOutput:     MintOutput{OutputOwners: owners},
		TransferOutput: TransferOutput{Amt: 100, OutputOwners: owners},
	}
	got, err := WrapMintOperation(in.Bytes())
	if err != nil {
		t.Fatalf("WrapMintOperation: %v", err)
	}
	if got.TransferOutput.Amt != 100 {
		t.Errorf("TransferOutput.Amt: got %d, want 100", got.TransferOutput.Amt)
	}
}

func TestWire_Credential_RoundTrip_192f(t *testing.T) {
	sig := make([]byte, SLH192fSigLen)
	for i := range sig {
		sig[i] = byte(i)
	}
	in := &Credential{
		Level: SecLevelSLH192f,
		Sigs:  [][]byte{sig},
	}
	got, err := WrapCredential(in.Bytes())
	if err != nil {
		t.Fatalf("WrapCredential: %v", err)
	}
	if got.Level != SecLevelSLH192f {
		t.Errorf("Level: got %v, want %v", got.Level, SecLevelSLH192f)
	}
	if len(got.Sigs) != 1 {
		t.Fatalf("Sigs.Len: got %d, want 1", len(got.Sigs))
	}
	if !bytes.Equal(got.Sigs[0], sig) {
		t.Errorf("Sigs[0] mismatch")
	}
}
