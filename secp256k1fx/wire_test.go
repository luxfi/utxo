// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1fx

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/ids"
)

func TestWire_OutputOwners_RoundTrip(t *testing.T) {
	in := &OutputOwners{
		Locktime:  1234567,
		Threshold: 2,
		Addrs: []ids.ShortID{
			{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
		},
	}
	got, err := WrapOutputOwners(in.Bytes())
	if err != nil {
		t.Fatalf("WrapOutputOwners: %v", err)
	}
	if !in.Equals(got) {
		t.Errorf("OutputOwners mismatch: got %+v, want %+v", got, in)
	}
}

func TestWire_TransferOutput_RoundTrip(t *testing.T) {
	in := &TransferOutput{
		Amt: 7_777_777,
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
		t.Errorf("OutputOwners mismatch: got %+v, want %+v", got.OutputOwners, in.OutputOwners)
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
	if !equalUint32Slice(got.SigIndices, in.SigIndices) {
		t.Errorf("SigIndices: got %v, want %v", got.SigIndices, in.SigIndices)
	}
}

func TestWire_MintOutput_RoundTrip(t *testing.T) {
	in := &MintOutput{
		OutputOwners: OutputOwners{
			Locktime:  0,
			Threshold: 1,
			Addrs:     []ids.ShortID{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}},
		},
	}
	got, err := WrapMintOutput(in.Bytes())
	if err != nil {
		t.Fatalf("WrapMintOutput: %v", err)
	}
	if !in.OutputOwners.Equals(&got.OutputOwners) {
		t.Errorf("OutputOwners mismatch: got %+v, want %+v", got.OutputOwners, in.OutputOwners)
	}
}

func TestWire_MintOperation_RoundTrip(t *testing.T) {
	addr := ids.ShortID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	in := &MintOperation{
		MintInput: Input{SigIndices: []uint32{0}},
		MintOutput: MintOutput{
			OutputOwners: OutputOwners{Locktime: 0, Threshold: 1, Addrs: []ids.ShortID{addr}},
		},
		TransferOutput: TransferOutput{
			Amt:          100,
			OutputOwners: OutputOwners{Locktime: 0, Threshold: 1, Addrs: []ids.ShortID{addr}},
		},
	}
	got, err := WrapMintOperation(in.Bytes())
	if err != nil {
		t.Fatalf("WrapMintOperation: %v", err)
	}
	if !equalUint32Slice(got.MintInput.SigIndices, in.MintInput.SigIndices) {
		t.Errorf("MintInput.SigIndices: got %v, want %v", got.MintInput.SigIndices, in.MintInput.SigIndices)
	}
	if !in.MintOutput.OutputOwners.Equals(&got.MintOutput.OutputOwners) {
		t.Errorf("MintOutput.OutputOwners mismatch")
	}
	if got.TransferOutput.Amt != in.TransferOutput.Amt {
		t.Errorf("TransferOutput.Amt: got %d, want %d", got.TransferOutput.Amt, in.TransferOutput.Amt)
	}
}

func TestWire_Credential_RoundTrip(t *testing.T) {
	var s1, s2 [secp256k1.SignatureLen]byte
	for i := range s1 {
		s1[i] = byte(i)
	}
	for i := range s2 {
		s2[i] = byte(0xFF - i)
	}
	in := &Credential{Sigs: [][secp256k1.SignatureLen]byte{s1, s2}}
	got, err := WrapCredential(in.Bytes())
	if err != nil {
		t.Fatalf("WrapCredential: %v", err)
	}
	if len(got.Sigs) != 2 {
		t.Fatalf("Sigs len: got %d, want 2", len(got.Sigs))
	}
	if !bytes.Equal(got.Sigs[0][:], s1[:]) {
		t.Errorf("Sigs[0] mismatch")
	}
	if !bytes.Equal(got.Sigs[1][:], s2[:]) {
		t.Errorf("Sigs[1] mismatch")
	}
}

func equalUint32Slice(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
