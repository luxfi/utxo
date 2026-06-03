// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256r1fx

import (
	"bytes"
	"testing"

	"github.com/luxfi/ids"
)

func TestWire_OutputOwners_RoundTrip(t *testing.T) {
	in := &OutputOwners{
		Locktime:  1234,
		Threshold: 1,
		Addrs:     []ids.ShortID{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}},
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
	var s [SigLen]byte
	for i := range s {
		s[i] = byte(i)
	}
	pk := make([]byte, PubKeyLen)
	for i := range pk {
		pk[i] = byte(i + 7)
	}
	in := &Credential{
		Sigs:    [][SigLen]byte{s},
		PubKeys: [][]byte{pk},
	}
	got, err := WrapCredential(in.Bytes())
	if err != nil {
		t.Fatalf("WrapCredential: %v", err)
	}
	if !bytes.Equal(got.Sigs[0][:], s[:]) {
		t.Errorf("Sigs[0] mismatch")
	}
	if !bytes.Equal(got.PubKeys[0], pk) {
		t.Errorf("PubKeys[0] mismatch")
	}
}
