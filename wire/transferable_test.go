// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"bytes"
	"testing"

	"github.com/luxfi/ids"
)

// innerSecp256k1TransferOutput builds the exact wire envelope that
// secp256k1fx.TransferOutput.Bytes() produces (TypeKindSecp256k1 +
// ShapeKindTransferOutput). Built via the wire constructor here to avoid the
// secp256k1fx -> wire import cycle in this in-package test.
func innerSecp256k1TransferOutput(amount uint64, addr ids.ShortID) []byte {
	return NewTransferOutput(TransferOutputInput{
		TypeKind:  TypeKindSecp256k1,
		Amount:    amount,
		Locktime:  0,
		Threshold: 1,
		Addresses: []ids.ShortID{addr},
	})
}

// innerSecp256k1TransferInput mirrors secp256k1fx.TransferInput.Bytes().
func innerSecp256k1TransferInput(amount uint64, sigIndices []uint32) []byte {
	return NewTransferInput(TransferInputInput{
		TypeKind:   TypeKindSecp256k1,
		Amount:     amount,
		SigIndices: sigIndices,
	})
}

func TestTransferableOut_RoundTrip(t *testing.T) {
	addr := ids.ShortID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	inner := innerSecp256k1TransferOutput(2_500_000, addr)
	assetID := ids.ID{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	envelope := NewTransferableOut(assetID, inner)

	// Canonical: the envelope must consume every byte (no trailing tail).
	if _, _, zapBytes, err := readEnvelopePrefix(envelope); err != nil {
		t.Fatalf("readEnvelopePrefix: %v", err)
	} else if len(zapBytes) == 0 {
		t.Fatal("empty zap body")
	}

	got, err := WrapTransferableOut(envelope)
	if err != nil {
		t.Fatalf("WrapTransferableOut: %v", err)
	}
	if got.AssetID() != assetID {
		t.Errorf("AssetID: got %x, want %x", got.AssetID(), assetID)
	}
	outBytes := got.OutputBytes()
	if !bytes.Equal(outBytes, inner) {
		t.Errorf("OutputBytes mismatch: got %x, want %x", outBytes, inner)
	}
	tk, sk := got.OutputDiscriminator()
	if tk != TypeKindSecp256k1 {
		t.Errorf("OutputDiscriminator TypeKind: got %x, want %x", tk, TypeKindSecp256k1)
	}
	if sk != ShapeKindTransferOutput {
		t.Errorf("OutputDiscriminator ShapeKind: got %x, want %x", sk, ShapeKindTransferOutput)
	}

	// Round-trip the inner secp256k1fx output.
	innerGot, err := WrapTransferOutput(outBytes)
	if err != nil {
		t.Fatalf("WrapTransferOutput inner: %v", err)
	}
	if innerGot.Amount() != 2_500_000 {
		t.Errorf("inner Amount: got %d, want 2_500_000", innerGot.Amount())
	}
	if innerGot.TypeKind() != TypeKindSecp256k1 {
		t.Errorf("inner TypeKind: got %x, want %x", innerGot.TypeKind(), TypeKindSecp256k1)
	}

	// Wrong-shape rejection: a TransferableOut buffer must not Wrap as
	// TransferableIn.
	if _, err := WrapTransferableIn(envelope); err != ErrWrongShapeKind {
		t.Errorf("WrapTransferableIn(out envelope): got %v, want ErrWrongShapeKind", err)
	}

	// Canonical rejection: a trailing byte must be refused.
	tampered := append(append([]byte(nil), envelope...), 0xFF)
	if _, err := WrapTransferableOut(tampered); err != ErrTrailingBytes {
		t.Errorf("WrapTransferableOut(trailing): got %v, want ErrTrailingBytes", err)
	}
}

func TestTransferableIn_RoundTrip(t *testing.T) {
	inner := innerSecp256k1TransferInput(2_500_000, []uint32{0, 3})
	txID := ids.ID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	assetID := ids.ID{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	envelope := NewTransferableIn(txID, 7, assetID, inner)

	got, err := WrapTransferableIn(envelope)
	if err != nil {
		t.Fatalf("WrapTransferableIn: %v", err)
	}
	if got.TxID() != txID {
		t.Errorf("TxID: got %x, want %x", got.TxID(), txID)
	}
	if got.OutputIndex() != 7 {
		t.Errorf("OutputIndex: got %d, want 7", got.OutputIndex())
	}
	if got.AssetID() != assetID {
		t.Errorf("AssetID: got %x, want %x", got.AssetID(), assetID)
	}
	inBytes := got.InputBytes()
	if !bytes.Equal(inBytes, inner) {
		t.Errorf("InputBytes mismatch: got %x, want %x", inBytes, inner)
	}
	tk, sk := got.InputDiscriminator()
	if tk != TypeKindSecp256k1 {
		t.Errorf("InputDiscriminator TypeKind: got %x, want %x", tk, TypeKindSecp256k1)
	}
	if sk != ShapeKindTransferInput {
		t.Errorf("InputDiscriminator ShapeKind: got %x, want %x", sk, ShapeKindTransferInput)
	}

	// Round-trip the inner secp256k1fx input.
	innerGot, err := WrapTransferInput(inBytes)
	if err != nil {
		t.Fatalf("WrapTransferInput inner: %v", err)
	}
	if innerGot.Amount() != 2_500_000 {
		t.Errorf("inner Amount: got %d, want 2_500_000", innerGot.Amount())
	}
	sigs := innerGot.SigIndices()
	if len(sigs) != 2 || sigs[0] != 0 || sigs[1] != 3 {
		t.Errorf("inner SigIndices: got %v, want [0 3]", sigs)
	}

	// Wrong-shape + canonical rejection.
	if _, err := WrapTransferableOut(envelope); err != ErrWrongShapeKind {
		t.Errorf("WrapTransferableOut(in envelope): got %v, want ErrWrongShapeKind", err)
	}
	tampered := append(append([]byte(nil), envelope...), 0xFF)
	if _, err := WrapTransferableIn(tampered); err != ErrTrailingBytes {
		t.Errorf("WrapTransferableIn(trailing): got %v, want ErrTrailingBytes", err)
	}
}

// TestXVMBaseTx_MultiAsset is the end-to-end proof that the multi-asset gap is
// closed: an XVMBaseTx built from TransferableOut/TransferableIn envelopes
// yields per-out/per-in AssetIDs via OutAt/InAt.
func TestXVMBaseTx_MultiAsset(t *testing.T) {
	addr := ids.ShortID{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	assetA := ids.ID{0xA1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	assetB := ids.ID{0xB2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	txID := ids.ID{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}

	out0 := NewTransferableOut(assetA, innerSecp256k1TransferOutput(1_000, addr))
	out1 := NewTransferableOut(assetB, innerSecp256k1TransferOutput(2_000, addr))
	in0 := NewTransferableIn(txID, 0, assetA, innerSecp256k1TransferInput(1_000, []uint32{0}))
	in1 := NewTransferableIn(txID, 1, assetB, innerSecp256k1TransferInput(2_000, []uint32{0}))

	envelope := NewXVMBaseTx(XVMBaseTxInput{
		NetworkID:    96369,
		BlockchainID: [32]byte{1, 2, 3},
		Outs:         [][]byte{out0, out1},
		Ins:          [][]byte{in0, in1},
		Memo:         []byte("multi-asset"),
	})

	tx, err := WrapXVMBaseTx(envelope)
	if err != nil {
		t.Fatalf("WrapXVMBaseTx: %v", err)
	}
	if tx.OutsCount() != 2 {
		t.Fatalf("OutsCount: got %d, want 2", tx.OutsCount())
	}
	if tx.InsCount() != 2 {
		t.Fatalf("InsCount: got %d, want 2", tx.InsCount())
	}

	// Outputs carry their AssetIDs (the gap that OutAt previously dropped).
	gotOut0, err := tx.OutAt(0)
	if err != nil {
		t.Fatalf("OutAt(0): %v", err)
	}
	if gotOut0.AssetID() != assetA {
		t.Errorf("OutAt(0).AssetID: got %x, want %x", gotOut0.AssetID(), assetA)
	}
	gotOut1, err := tx.OutAt(1)
	if err != nil {
		t.Fatalf("OutAt(1): %v", err)
	}
	if gotOut1.AssetID() != assetB {
		t.Errorf("OutAt(1).AssetID: got %x, want %x", gotOut1.AssetID(), assetB)
	}
	inner1, err := WrapTransferOutput(gotOut1.OutputBytes())
	if err != nil {
		t.Fatalf("inner WrapTransferOutput: %v", err)
	}
	if inner1.Amount() != 2_000 {
		t.Errorf("OutAt(1) inner Amount: got %d, want 2000", inner1.Amount())
	}

	// Inputs carry their UTXOID + AssetID (the gap that InAt previously dropped).
	gotIn0, err := tx.InAt(0)
	if err != nil {
		t.Fatalf("InAt(0): %v", err)
	}
	if gotIn0.AssetID() != assetA || gotIn0.TxID() != txID || gotIn0.OutputIndex() != 0 {
		t.Errorf("InAt(0): got (asset=%x, tx=%x, idx=%d)", gotIn0.AssetID(), gotIn0.TxID(), gotIn0.OutputIndex())
	}
	gotIn1, err := tx.InAt(1)
	if err != nil {
		t.Fatalf("InAt(1): %v", err)
	}
	if gotIn1.AssetID() != assetB || gotIn1.OutputIndex() != 1 {
		t.Errorf("InAt(1): got (asset=%x, idx=%d), want (assetB, 1)", gotIn1.AssetID(), gotIn1.OutputIndex())
	}
	if !bytes.Equal(tx.Memo(), []byte("multi-asset")) {
		t.Errorf("Memo: got %q, want %q", tx.Memo(), "multi-asset")
	}
}
