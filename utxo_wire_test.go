// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package utxo_test

// External test package — exercises both the root utxo package and the
// fx packages without creating an import cycle.

import (
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/vm/components/verify"

	"github.com/luxfi/utxo"
	"github.com/luxfi/utxo/secp256k1fx"
	"github.com/luxfi/utxo/wire"
)

// Test that a UTXO carrying a *secp256k1fx.TransferOutput round-trips
// through the wire envelope cleanly.
func TestUTXO_WireBytes_Secp256k1_TransferOutput_RoundTrip(t *testing.T) {
	addr := ids.ShortID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	txID := ids.ID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	assetID := ids.ID{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	inOut := &secp256k1fx.TransferOutput{
		Amt: 1_000_000,
		OutputOwners: secp256k1fx.OutputOwners{
			Locktime:  42,
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	in := &utxo.UTXO{
		UTXOID: utxo.UTXOID{TxID: txID, OutputIndex: 7},
		Asset:  utxo.Asset{ID: assetID},
		Out:    inOut,
	}

	envelope, err := in.WireBytes()
	if err != nil {
		t.Fatalf("WireBytes: %v", err)
	}

	got, err := utxo.WrapUTXOBytes(envelope)
	if err != nil {
		t.Fatalf("WrapUTXOBytes: %v", err)
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

	tk, sk := got.OutputDiscriminator()
	if tk != wire.TypeKindSecp256k1 {
		t.Errorf("OutputDiscriminator TypeKind: got %x, want %x", tk, wire.TypeKindSecp256k1)
	}
	if sk != wire.ShapeKindTransferOutput {
		t.Errorf("OutputDiscriminator ShapeKind: got %x, want %x", sk, wire.ShapeKindTransferOutput)
	}

	// Dispatch on the discriminator into the fx-package WrapTransferOutput.
	gotOut, err := secp256k1fx.WrapTransferOutput(got.OutputBytes())
	if err != nil {
		t.Fatalf("WrapTransferOutput: %v", err)
	}
	if gotOut.Amt != inOut.Amt {
		t.Errorf("Out.Amt: got %d, want %d", gotOut.Amt, inOut.Amt)
	}
	if !gotOut.OutputOwners.Equals(&inOut.OutputOwners) {
		t.Errorf("Out.OutputOwners mismatch")
	}
}

// Test that WireBytes refuses a non-wire-serializable Out.
func TestUTXO_WireBytes_RejectsNonWireSerializableOut(t *testing.T) {
	in := &utxo.UTXO{
		UTXOID: utxo.UTXOID{TxID: ids.ID{1}, OutputIndex: 0},
		Asset:  utxo.Asset{ID: ids.ID{2}},
		Out:    unknownOut{},
	}
	if _, err := in.WireBytes(); err != utxo.ErrUTXOOutNotWireSerializable {
		t.Errorf("WireBytes: got err=%v, want ErrUTXOOutNotWireSerializable", err)
	}
}

// unknownOut is a verify.State that does NOT implement Bytes() — used to
// confirm WireBytes refuses unknown types cleanly.
type unknownOut struct {
	verify.IsState
}

func (unknownOut) Verify() error { return nil }
