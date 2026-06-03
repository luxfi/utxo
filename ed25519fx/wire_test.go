// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519fx

import (
	"bytes"
	"testing"

	"github.com/luxfi/ids"
)

func TestWire_OutputOwners_RoundTrip(t *testing.T) {
	in := &OutputOwners{
		Locktime:  1234,
		Threshold: 2,
		Addrs: []ids.ShortID{
			{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		},
	}
	got, err := WrapOutputOwners(in.Bytes())
	if err != nil {
		t.Fatalf("WrapOutputOwners: %v", err)
	}
	if !in.Equals(got) {
		t.Errorf("OutputOwners mismatch")
	}
}

func TestWire_TransferOutput_RoundTrip(t *testing.T) {
	in := &TransferOutput{
		Amt: 1_000_000,
		OutputOwners: OutputOwners{
			Locktime:  42,
			Threshold: 1,
			Addrs:     []ids.ShortID{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}},
		},
	}
	got, err := WrapTransferOutput(in.Bytes())
	if err != nil {
		t.Fatalf("WrapTransferOutput: %v", err)
	}
	if got.Amt != in.Amt {
		t.Errorf("Amt: got %d, want %d", got.Amt, in.Amt)
	}
	if !in.OutputOwners.Equals(&got.OutputOwners) {
		t.Errorf("OutputOwners mismatch")
	}
}

func TestWire_TransferInput_RoundTrip(t *testing.T) {
	in := &TransferInput{
		Amt:   500,
		Input: Input{SigIndices: []uint32{0, 2}},
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
	in := &MintOutput{
		OutputOwners: OutputOwners{
			Threshold: 1,
			Addrs:     []ids.ShortID{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}},
		},
	}
	got, err := WrapMintOutput(in.Bytes())
	if err != nil {
		t.Fatalf("WrapMintOutput: %v", err)
	}
	if !in.OutputOwners.Equals(&got.OutputOwners) {
		t.Errorf("OutputOwners mismatch")
	}
}

func TestWire_MintOperation_RoundTrip(t *testing.T) {
	addr := ids.ShortID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	owners := OutputOwners{Threshold: 1, Addrs: []ids.ShortID{addr}}
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

func TestWire_Credential_RoundTrip(t *testing.T) {
	var s1, s2 [SigLen]byte
	for i := range s1 {
		s1[i] = byte(i)
	}
	for i := range s2 {
		s2[i] = byte(0xFF - i)
	}
	pk1 := make([]byte, PubKeyLen)
	pk2 := make([]byte, PubKeyLen)
	for i := range pk1 {
		pk1[i] = byte(i)
	}
	for i := range pk2 {
		pk2[i] = byte(0xFF - i)
	}
	in := &Credential{
		Sigs:    [][SigLen]byte{s1, s2},
		PubKeys: [][]byte{pk1, pk2},
	}
	got, err := WrapCredential(in.Bytes())
	if err != nil {
		t.Fatalf("WrapCredential: %v", err)
	}
	if len(got.Sigs) != 2 {
		t.Fatalf("Sigs.Len: got %d, want 2", len(got.Sigs))
	}
	if !bytes.Equal(got.Sigs[0][:], s1[:]) {
		t.Errorf("Sigs[0] mismatch")
	}
	if !bytes.Equal(got.Sigs[1][:], s2[:]) {
		t.Errorf("Sigs[1] mismatch")
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
