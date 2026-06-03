// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"bytes"
	"testing"
)

func TestPQOutputOwners_RoundTrip(t *testing.T) {
	// Two ML-DSA-65 pubkeys (1952 bytes each), simulated.
	const stride = 1952
	pk1 := make([]byte, stride)
	pk2 := make([]byte, stride)
	for i := range pk1 {
		pk1[i] = byte(i)
	}
	for i := range pk2 {
		pk2[i] = byte(0xFF - i)
	}
	in := PQOutputOwnersInput{
		TypeKind:      TypeKindMLDSA,
		SecurityLevel: 1, // ML-DSA-65
		Locktime:      9999,
		Threshold:     1,
		PubKeyStride:  stride,
		PubKeys:       [][]byte{pk1, pk2},
	}
	envelope := NewPQOutputOwners(in)
	got, err := WrapPQOutputOwners(envelope, stride)
	if err != nil {
		t.Fatalf("WrapPQOutputOwners: %v", err)
	}
	if got.TypeKind() != TypeKindMLDSA {
		t.Errorf("TypeKind: got %x, want %x", got.TypeKind(), TypeKindMLDSA)
	}
	if got.SecurityLevel() != 1 {
		t.Errorf("SecurityLevel: got %d, want 1", got.SecurityLevel())
	}
	if got.Locktime() != 9999 {
		t.Errorf("Locktime: got %d, want 9999", got.Locktime())
	}
	if got.Threshold() != 1 {
		t.Errorf("Threshold: got %d, want 1", got.Threshold())
	}
	pks := got.PubKeys()
	if pks.Len() != 2 {
		t.Fatalf("PubKeys.Len: got %d, want 2", pks.Len())
	}
	if !bytes.Equal(pks.At(0), pk1) {
		t.Errorf("PubKeys[0] mismatch")
	}
	if !bytes.Equal(pks.At(1), pk2) {
		t.Errorf("PubKeys[1] mismatch")
	}
	// pk1 < pk2 lexicographically (bytes 0x00..ff < 0xFF..00 starting at byte 0).
	if err := got.SyntacticVerify(); err != nil {
		t.Errorf("SyntacticVerify: %v", err)
	}
}

func TestPQTransferOutput_RoundTrip(t *testing.T) {
	// Single SLH-DSA-SHA2-192f pubkey (48 bytes), simulated.
	const stride = 48
	pk := make([]byte, stride)
	for i := range pk {
		pk[i] = byte(i + 10)
	}
	in := PQTransferOutputInput{
		TypeKind:      TypeKindSLHDSA,
		SecurityLevel: 1,
		Amount:        7_777_777,
		Locktime:      42,
		Threshold:     1,
		PubKeyStride:  stride,
		PubKeys:       [][]byte{pk},
	}
	envelope := NewPQTransferOutput(in)
	got, err := WrapPQTransferOutput(envelope, stride)
	if err != nil {
		t.Fatalf("WrapPQTransferOutput: %v", err)
	}
	if got.Amount() != 7_777_777 {
		t.Errorf("Amount: got %d, want 7_777_777", got.Amount())
	}
	if got.Threshold() != 1 {
		t.Errorf("Threshold: got %d, want 1", got.Threshold())
	}
	pks := got.PubKeys()
	if pks.Len() != 1 {
		t.Fatalf("PubKeys.Len: got %d, want 1", pks.Len())
	}
	if !bytes.Equal(pks.At(0), pk) {
		t.Errorf("PubKeys[0] mismatch")
	}
	if err := got.SyntacticVerify(); err != nil {
		t.Errorf("SyntacticVerify: %v", err)
	}
}

func TestPQMintOutput_RoundTrip(t *testing.T) {
	const stride = 1952
	pk := make([]byte, stride)
	for i := range pk {
		pk[i] = byte(i * 3)
	}
	in := PQMintOutputInput{
		TypeKind:      TypeKindMLDSA,
		SecurityLevel: 1,
		Locktime:      0,
		Threshold:     1,
		PubKeyStride:  stride,
		PubKeys:       [][]byte{pk},
	}
	envelope := NewPQMintOutput(in)
	got, err := WrapPQMintOutput(envelope, stride)
	if err != nil {
		t.Fatalf("WrapPQMintOutput: %v", err)
	}
	if got.SecurityLevel() != 1 {
		t.Errorf("SecurityLevel: got %d, want 1", got.SecurityLevel())
	}
	if got.Threshold() != 1 {
		t.Errorf("Threshold: got %d, want 1", got.Threshold())
	}
	if !bytes.Equal(got.PubKeys().At(0), pk) {
		t.Errorf("PubKeys[0] mismatch")
	}
	if err := got.SyntacticVerify(); err != nil {
		t.Errorf("SyntacticVerify: %v", err)
	}
}

func TestPQOutputOwners_RejectsWrongShape(t *testing.T) {
	// Build a classical OutputOwners and feed it to the PQ Wrap. Should fail
	// the ShapeKind check.
	classical := NewOutputOwners(OutputOwnersInput{
		Locktime:  0,
		Threshold: 1,
	})
	if _, err := WrapPQOutputOwners(classical, 1952); err != ErrWrongShapeKind {
		t.Errorf("WrapPQOutputOwners(classical): got err=%v, want ErrWrongShapeKind", err)
	}
}
