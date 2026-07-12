// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// This file closes the multi-asset correctness gap in wire.XVMBaseTx.
// X-Chain is a universal multi-asset settlement layer, so an output/input
// on the wire is NOT a bare fx TransferOutput/TransferInput — it MUST name
// the asset it moves. TransferableOut and TransferableIn are the reserved
// cross-fx envelopes that bind an AssetID (and, for inputs, the spent
// UTXOID) to a concrete inner fx primitive.
//
// Both are cross-fx CONTAINERS: TypeKind is TypeKindReserved (0x00) — the
// envelope itself is not fx-owned; the owning fx TypeKind travels on the
// INNER Output/Input envelope's own discriminator prefix. This mirrors the
// UTXO envelope (wire/utxo.go), which is likewise reserved-TypeKind and
// carries an fx-typed Output.

// ---- TransferableOut (ShapeKindTransferableOut = 0x0B) ----
//
// TransferableOut binds an AssetID to a concrete spending Output. It is the
// output-list counterpart of UTXO's (AssetID, Output) tail — the same
// AssetID+Output layout, minus the UTXOID (TxID+OutputIndex), because a
// freshly-created output is not yet a spent-UTXO reference.
//
// The Output bytes field carries the inner fx primitive's wire envelope
// (2-byte discriminator prefix + ZAP message): a TransferOutput, MintOutput,
// or one of the NFT* output shapes. Consumers dispatch on the inner
// envelope's (TypeKind, ShapeKind) pair via OutputDiscriminator, then
// WrapTransferOutput / WrapMintOutput / WrapNFT*.
//
// Fixed-section layout (size 40 bytes):
//
//	AssetID  32B   @ 0
//	Output   bytes @ 32  (relOffset + length, 8 bytes)
//
// Wire prefix: TypeKind=0x00 (reserved), ShapeKind=0x0B (TransferableOut).
const (
	OffsetTransferableOut_AssetID = 0  // 32B
	OffsetTransferableOut_Output  = 32 // bytes (relOffset + length, 8 bytes)
	SizeTransferableOut           = 40
)

// TransferableOut is the zero-copy typed accessor over a ZAP-encoded
// TransferableOut wire envelope.
//
// READ-ONLY: every field aliases the underlying ZAP buffer. Mutation
// corrupts any TxID = hash(buffer) computed downstream. Use
// append([]byte(nil), ...) to take ownership of OutputBytes when handing
// off to another goroutine.
type TransferableOut struct {
	b   []byte
	msg *zap.Message
	obj zap.Object
}

// AssetID returns the asset identifier this output moves.
func (t TransferableOut) AssetID() ids.ID {
	var out ids.ID
	for i := 0; i < 32; i++ {
		out[i] = t.obj.Uint8(OffsetTransferableOut_AssetID + i)
	}
	return out
}

// OutputBytes returns the inner fx Output wire envelope (2-byte
// discriminator prefix + ZAP message). Dispatch on OutputDiscriminator,
// then WrapTransferOutput / WrapMintOutput / WrapNFT*.
//
// READ-ONLY: aliases the underlying buffer.
func (t TransferableOut) OutputBytes() []byte {
	return t.obj.Bytes(OffsetTransferableOut_Output)
}

// OutputDiscriminator returns the (TypeKind, ShapeKind) pair embedded at the
// head of OutputBytes(). Returns (0, 0) when OutputBytes is shorter than the
// 2-byte prefix. This is the type accessor consumers dispatch on to pick the
// inner fx Wrap*.
func (t TransferableOut) OutputDiscriminator() (TypeKind, ShapeKind) {
	b := t.OutputBytes()
	if len(b) < EnvelopePrefix {
		return 0, 0
	}
	return TypeKind(b[0]), ShapeKind(b[1])
}

// Bytes returns the full wire envelope (2-byte discriminator prefix + ZAP
// message). Stable across calls — backed by the originally-parsed buffer.
func (t TransferableOut) Bytes() []byte { return t.b }

// IsZero reports whether the accessor wraps a parsed message.
func (t TransferableOut) IsZero() bool { return t.msg == nil }

// WrapTransferableOut parses a TransferableOut wire envelope into a typed
// accessor.
//
// Returns ErrShortEnvelope when the buffer is shorter than the 2-byte
// discriminator prefix; ErrWrongShapeKind when the prefix names a
// non-TransferableOut shape; ErrTrailingBytes when the buffer carries bytes
// beyond the self-delimiting ZAP message (non-canonical).
func WrapTransferableOut(b []byte) (TransferableOut, error) {
	_, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return TransferableOut{}, err
	}
	if sk != ShapeKindTransferableOut {
		return TransferableOut{}, ErrWrongShapeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return TransferableOut{}, err
	}
	if msg.Size() != len(zapBytes) {
		return TransferableOut{}, ErrTrailingBytes
	}
	return TransferableOut{b: b, msg: msg, obj: msg.Root()}, nil
}

// NewTransferableOut builds a TransferableOut wire envelope from an asset id
// and an already-built inner fx Output envelope (from NewTransferOutput /
// NewMintOutput / NewNFT*). The inner envelope's bytes are stored verbatim
// in the Output field.
func NewTransferableOut(assetID ids.ID, innerEnvelope []byte) []byte {
	capEstimate := zap.HeaderSize + SizeTransferableOut + len(innerEnvelope) + 64
	b := zap.NewBuilder(capEstimate)

	ob := b.StartObject(SizeTransferableOut)
	for i := 0; i < 32; i++ {
		ob.SetUint8(OffsetTransferableOut_AssetID+i, assetID[i])
	}
	ob.SetBytes(OffsetTransferableOut_Output, innerEnvelope)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(TypeKindReserved, ShapeKindTransferableOut, b.Finish())
}

// ---- TransferableIn (ShapeKindTransferableIn = 0x0C) ----
//
// TransferableIn binds a UTXO reference (TxID + OutputIndex + AssetID) to a
// spending Input. Every consumed input on the wire must name the UTXO it
// spends AND the asset that UTXO holds — so an XVMBaseTx input is a
// TransferableIn (UTXOID + AssetID + inner fx Input), NOT a bare
// TransferInput.
//
// This mirrors UTXO's fixed-section layout exactly (TxID + OutputIndex +
// AssetID + inner-envelope pointer): a TransferableIn IS a reference to a
// UTXO plus the Input that unlocks it.
//
// The Input bytes field carries the inner fx primitive's wire envelope
// (2-byte discriminator prefix + ZAP message): a TransferInput. Consumers
// dispatch on the inner (TypeKind, ShapeKind) pair via InputDiscriminator,
// then WrapTransferInput.
//
// Fixed-section layout (size 76 bytes; uint32/uint64 reads alignment-tolerant):
//
//	TxID         32B    @ 0
//	OutputIndex  uint32 @ 32
//	AssetID      32B    @ 36
//	Input        bytes  @ 68  (relOffset + length, 8 bytes)
//
// Wire prefix: TypeKind=0x00 (reserved), ShapeKind=0x0C (TransferableIn).
const (
	OffsetTransferableIn_TxID        = 0  // 32B
	OffsetTransferableIn_OutputIndex = 32 // uint32
	OffsetTransferableIn_AssetID     = 36 // 32B
	OffsetTransferableIn_Input       = 68 // bytes (relOffset + length, 8 bytes)
	SizeTransferableIn               = 76
)

// TransferableIn is the zero-copy typed accessor over a ZAP-encoded
// TransferableIn wire envelope.
//
// READ-ONLY: every field aliases the underlying ZAP buffer. Use
// append([]byte(nil), ...) to take ownership of InputBytes when handing off
// to another goroutine.
type TransferableIn struct {
	b   []byte
	msg *zap.Message
	obj zap.Object
}

// TxID returns the spent UTXO's tx id.
func (t TransferableIn) TxID() ids.ID {
	var out ids.ID
	for i := 0; i < 32; i++ {
		out[i] = t.obj.Uint8(OffsetTransferableIn_TxID + i)
	}
	return out
}

// OutputIndex returns the spent UTXO's output index.
func (t TransferableIn) OutputIndex() uint32 {
	return t.obj.Uint32(OffsetTransferableIn_OutputIndex)
}

// AssetID returns the asset identifier the spent UTXO holds.
func (t TransferableIn) AssetID() ids.ID {
	var out ids.ID
	for i := 0; i < 32; i++ {
		out[i] = t.obj.Uint8(OffsetTransferableIn_AssetID + i)
	}
	return out
}

// InputBytes returns the inner fx Input wire envelope (2-byte discriminator
// prefix + ZAP message). Dispatch on InputDiscriminator, then
// WrapTransferInput.
//
// READ-ONLY: aliases the underlying buffer.
func (t TransferableIn) InputBytes() []byte {
	return t.obj.Bytes(OffsetTransferableIn_Input)
}

// InputDiscriminator returns the (TypeKind, ShapeKind) pair embedded at the
// head of InputBytes(). Returns (0, 0) when InputBytes is shorter than the
// 2-byte prefix. This is the type accessor consumers dispatch on to pick the
// inner fx Wrap*.
func (t TransferableIn) InputDiscriminator() (TypeKind, ShapeKind) {
	b := t.InputBytes()
	if len(b) < EnvelopePrefix {
		return 0, 0
	}
	return TypeKind(b[0]), ShapeKind(b[1])
}

// Bytes returns the full wire envelope (2-byte discriminator prefix + ZAP
// message). Stable across calls — backed by the originally-parsed buffer.
func (t TransferableIn) Bytes() []byte { return t.b }

// IsZero reports whether the accessor wraps a parsed message.
func (t TransferableIn) IsZero() bool { return t.msg == nil }

// WrapTransferableIn parses a TransferableIn wire envelope into a typed
// accessor.
//
// Returns ErrShortEnvelope when the buffer is shorter than the 2-byte
// discriminator prefix; ErrWrongShapeKind when the prefix names a
// non-TransferableIn shape; ErrTrailingBytes when the buffer carries bytes
// beyond the self-delimiting ZAP message (non-canonical).
func WrapTransferableIn(b []byte) (TransferableIn, error) {
	_, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return TransferableIn{}, err
	}
	if sk != ShapeKindTransferableIn {
		return TransferableIn{}, ErrWrongShapeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return TransferableIn{}, err
	}
	if msg.Size() != len(zapBytes) {
		return TransferableIn{}, ErrTrailingBytes
	}
	return TransferableIn{b: b, msg: msg, obj: msg.Root()}, nil
}

// NewTransferableIn builds a TransferableIn wire envelope from a UTXO
// reference (txID + outputIndex + assetID) and an already-built inner fx
// Input envelope (from NewTransferInput). The inner envelope's bytes are
// stored verbatim in the Input field.
func NewTransferableIn(txID ids.ID, outputIndex uint32, assetID ids.ID, innerEnvelope []byte) []byte {
	capEstimate := zap.HeaderSize + SizeTransferableIn + len(innerEnvelope) + 64
	b := zap.NewBuilder(capEstimate)

	ob := b.StartObject(SizeTransferableIn)
	for i := 0; i < 32; i++ {
		ob.SetUint8(OffsetTransferableIn_TxID+i, txID[i])
	}
	ob.SetUint32(OffsetTransferableIn_OutputIndex, outputIndex)
	for i := 0; i < 32; i++ {
		ob.SetUint8(OffsetTransferableIn_AssetID+i, assetID[i])
	}
	ob.SetBytes(OffsetTransferableIn_Input, innerEnvelope)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(TypeKindReserved, ShapeKindTransferableIn, b.Finish())
}
