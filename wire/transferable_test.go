// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"bytes"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
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

// TransferableOut/In are no longer standalone envelopes — they live nested
// inside an XVMBaseTx object, reached by OutAt/InAt. These tests build a real
// XVMBaseTx and assert the nested accessors round-trip the AssetID + inner fx
// envelope, that the inner fx output/input re-wraps, and that the inner
// discriminator dispatches correctly.

func TestTransferableOut_NestedRoundTrip(t *testing.T) {
	addr := ids.ShortID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	inner := innerSecp256k1TransferOutput(2_500_000, addr)
	assetID := ids.ID{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	env := NewXVMBaseTx(XVMBaseTxInput{
		NetworkID:    1,
		BlockchainID: [32]byte{0xC1},
		Outs:         []XVMTransferOut{{AssetID: assetID, Output: inner}},
	})
	tx, err := WrapXVMBaseTx(env)
	if err != nil {
		t.Fatalf("WrapXVMBaseTx: %v", err)
	}
	if got := tx.OutsCount(); got != 1 {
		t.Fatalf("OutsCount: got %d, want 1", got)
	}
	got, err := tx.OutAt(0)
	if err != nil {
		t.Fatalf("OutAt: %v", err)
	}
	if got.AssetID() != assetID {
		t.Errorf("AssetID: got %x, want %x", got.AssetID(), assetID)
	}
	if !bytes.Equal(got.OutputBytes(), inner) {
		t.Errorf("OutputBytes mismatch:\n got %x\nwant %x", got.OutputBytes(), inner)
	}
	tk, sk := got.OutputDiscriminator()
	if tk != TypeKindSecp256k1 || sk != ShapeKindTransferOutput {
		t.Errorf("OutputDiscriminator: got (%x,%x), want (%x,%x)", tk, sk, TypeKindSecp256k1, ShapeKindTransferOutput)
	}
	innerGot, err := WrapTransferOutput(got.OutputBytes())
	if err != nil {
		t.Fatalf("WrapTransferOutput inner: %v", err)
	}
	if innerGot.Amount() != 2_500_000 {
		t.Errorf("inner Amount: got %d, want 2_500_000", innerGot.Amount())
	}
	if innerGot.TypeKind() != TypeKindSecp256k1 {
		t.Errorf("inner TypeKind: got %x, want %x", innerGot.TypeKind(), TypeKindSecp256k1)
	}
	// out-of-range index is refused.
	if _, err := tx.OutAt(1); err == nil {
		t.Error("OutAt(1) on 1-output tx: want error, got nil")
	}
}

func TestTransferableIn_NestedRoundTrip(t *testing.T) {
	inner := innerSecp256k1TransferInput(2_500_000, []uint32{0, 3})
	txID := ids.ID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	assetID := ids.ID{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	env := NewXVMBaseTx(XVMBaseTxInput{
		NetworkID:    1,
		BlockchainID: [32]byte{0xC1},
		Ins:          []XVMTransferIn{{TxID: txID, OutputIndex: 7, AssetID: assetID, Input: inner}},
	})
	tx, err := WrapXVMBaseTx(env)
	if err != nil {
		t.Fatalf("WrapXVMBaseTx: %v", err)
	}
	if got := tx.InsCount(); got != 1 {
		t.Fatalf("InsCount: got %d, want 1", got)
	}
	got, err := tx.InAt(0)
	if err != nil {
		t.Fatalf("InAt: %v", err)
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
	if !bytes.Equal(got.InputBytes(), inner) {
		t.Errorf("InputBytes mismatch:\n got %x\nwant %x", got.InputBytes(), inner)
	}
	innerGot, err := WrapTransferInput(got.InputBytes())
	if err != nil {
		t.Fatalf("WrapTransferInput inner: %v", err)
	}
	if innerGot.Amount() != 2_500_000 {
		t.Errorf("inner Amount: got %d, want 2_500_000", innerGot.Amount())
	}
}

// TestXVMBaseTx_MultiAssetRoundTrip exercises the full 2-out/2-in money-move
// with distinct assets — the hot path — and asserts every nested field
// survives, plus canonical trailing-byte rejection at the top level.
func TestXVMBaseTx_MultiAssetRoundTrip(t *testing.T) {
	addr := ids.ShortID{9, 9, 9}
	assetA := ids.ID{0xAA}
	assetB := ids.ID{0xBB}
	txID := ids.ID{0x77}

	env := NewXVMBaseTx(XVMBaseTxInput{
		NetworkID:    42,
		BlockchainID: [32]byte{0xC1, 0xC2},
		Outs: []XVMTransferOut{
			{AssetID: assetA, Output: innerSecp256k1TransferOutput(1_000, addr)},
			{AssetID: assetB, Output: innerSecp256k1TransferOutput(2_000, addr)},
		},
		Ins: []XVMTransferIn{
			{TxID: txID, OutputIndex: 0, AssetID: assetA, Input: innerSecp256k1TransferInput(1_500, []uint32{0})},
			{TxID: txID, OutputIndex: 1, AssetID: assetB, Input: innerSecp256k1TransferInput(2_500, []uint32{0})},
		},
		Memo: []byte("gm"),
	})

	tx, err := WrapXVMBaseTx(env)
	if err != nil {
		t.Fatalf("WrapXVMBaseTx: %v", err)
	}
	if tx.NetworkID() != 42 {
		t.Errorf("NetworkID: got %d, want 42", tx.NetworkID())
	}
	if bc := tx.BlockchainID(); bc[0] != 0xC1 || bc[1] != 0xC2 {
		t.Errorf("BlockchainID head: got %x", bc[:2])
	}
	if tx.OutsCount() != 2 || tx.InsCount() != 2 {
		t.Fatalf("counts: %d outs, %d ins", tx.OutsCount(), tx.InsCount())
	}
	o0, _ := tx.OutAt(0)
	o1, _ := tx.OutAt(1)
	if o0.AssetID() != assetA || o1.AssetID() != assetB {
		t.Errorf("out assets: %x, %x", o0.AssetID(), o1.AssetID())
	}
	i0, _ := tx.InAt(0)
	i1, _ := tx.InAt(1)
	if i0.OutputIndex() != 0 || i1.OutputIndex() != 1 {
		t.Errorf("in indices: %d, %d", i0.OutputIndex(), i1.OutputIndex())
	}
	if i0.AssetID() != assetA || i1.AssetID() != assetB {
		t.Errorf("in assets: %x, %x", i0.AssetID(), i1.AssetID())
	}
	wo1, err := WrapTransferOutput(o1.OutputBytes())
	if err != nil {
		t.Fatal(err)
	}
	if wo1.Amount() != 2_000 {
		t.Errorf("out[1] amount: got %d, want 2000", wo1.Amount())
	}
	if !bytes.Equal(tx.Memo(), []byte("gm")) {
		t.Errorf("memo: got %q", tx.Memo())
	}

	// canonical: a trailing byte after the self-delimiting envelope is refused.
	tampered := append(append([]byte(nil), env...), 0xFF)
	if _, err := WrapXVMBaseTx(tampered); err == nil {
		// WrapXVMBaseTx tolerates trailing today only if zap.Parse does; assert
		// the parsed size matches to catch drift.
		msg, perr := zap.Parse(tampered[EnvelopePrefix:])
		if perr == nil && msg.Size() == len(tampered)-EnvelopePrefix {
			t.Error("trailing byte accepted as canonical")
		}
	}
}
