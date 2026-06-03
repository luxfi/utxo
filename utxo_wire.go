// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package utxo

import (
	"errors"

	"github.com/luxfi/utxo/wire"
)

// ErrUTXOOutNotWireSerializable is returned by UTXO.WireBytes when the
// in-memory polymorphic Out field is not a known fxs primitive with a
// wire.NewXxx adapter. Each fx package's wire.go adapter file registers
// its concrete types to satisfy the wireSerializable interface — if a
// caller stuffs a third-party type into UTXO.Out, the wire layer cannot
// build a deterministic envelope and refuses.
var ErrUTXOOutNotWireSerializable = errors.New("utxo: UTXO.Out type does not implement wire-serializable interface; add Bytes() []byte to the fx primitive")

// wireSerializable is the minimal contract every fxs primitive's wire
// adapter must satisfy: a Bytes() returning the (TypeKind+ShapeKind+
// ZAP-message) envelope. All fx wire.go files satisfy this for their
// TransferOutput / MintOutput / AttestationOutput types.
type wireSerializable interface {
	Bytes() []byte
}

// WireBytes returns the ZAP-native wire envelope for the UTXO. The
// envelope is = (TypeKindReserved, ShapeKindUTXO, ZAP message) where the
// ZAP message carries TxID, OutputIndex, AssetID, and the inner output's
// wire envelope (which itself carries its own TypeKind+ShapeKind+ZAP
// message).
//
// Returns ErrUTXOOutNotWireSerializable when the in-memory Out is not a
// known fxs primitive. The fx packages provide the adapter side via
// their `wire.go` Bytes() methods.
func (u *UTXO) WireBytes() ([]byte, error) {
	if u == nil {
		return nil, errNilUTXO
	}
	if u.Out == nil {
		return nil, errEmptyUTXO
	}
	ws, ok := u.Out.(wireSerializable)
	if !ok {
		return nil, ErrUTXOOutNotWireSerializable
	}
	outputBytes := ws.Bytes()
	return wire.NewUTXO(wire.UTXOInput{
		TxID:        u.TxID,
		OutputIndex: u.OutputIndex,
		AssetID:     u.Asset.ID,
		Output:      outputBytes,
	}), nil
}

// WrapUTXOBytes parses the outer UTXO wire envelope into the (TxID,
// OutputIndex, AssetID, Output-envelope-bytes) tuple. The caller is
// responsible for parsing the Output envelope through the appropriate
// fx package's WrapTransferOutput / WrapMintOutput / WrapAttestationOutput
// dispatched on the inner discriminator pair.
//
// This split is intentional: the root utxo package cannot import the fx
// packages (would be a cycle), so the inner envelope parse stays at the
// caller. Use wire.UTXO.OutputDiscriminator() to learn (TypeKind,
// ShapeKind) before dispatch.
func WrapUTXOBytes(b []byte) (wire.UTXO, error) {
	return wire.WrapUTXO(b)
}
