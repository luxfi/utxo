// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// UTXO is the cross-VM ZAP schema for github.com/luxfi/utxo.UTXO. Carries
// the spent TxID + OutputIndex (UTXOID), the asset identifier, and the
// concrete output payload (a fxs primitive — TransferOutput, MintOutput,
// AttestationOutput). The output payload is itself a wire envelope with
// its own (TypeKind, ShapeKind) discriminator pair, written as a bytes
// field in the parent UTXO message.
//
// Fixed-section layout (size 76 bytes; uint64 reads alignment-tolerant):
//
//	TxID         32B    @ 0
//	OutputIndex  uint32 @ 32
//	AssetID      32B    @ 36
//	Output       bytes  @ 68  (relOffset + length, 8 bytes)
//
// Total fixed section = 32 + 4 + 32 + 8 = 76 bytes.
//
// The Output bytes field carries the inner fxs primitive's wire envelope
// (2-byte discriminator prefix + ZAP message). Consumers parse it via
// WrapTransferableOutput / WrapMintOutput / WrapAttestationOutput,
// dispatching on the discriminator pair.
const (
	OffsetUTXO_TxID        = 0
	OffsetUTXO_OutputIndex = 32 // uint32
	OffsetUTXO_AssetID     = 36 // 32B
	OffsetUTXO_Output      = 68 // bytes (relOffset + length, 8 bytes)
	SizeUTXO               = 76
)

// UTXO is the zero-copy typed accessor over a ZAP-encoded UTXO wire
// envelope.
//
// READ-ONLY: every field aliases the underlying ZAP buffer. Mutation
// corrupts any UTXOID = hash(buffer) computed downstream and breaks
// cross-VM atomic UTXO transfer semantics. Use append([]byte(nil), ...)
// to take ownership of the Output bytes when handing off to a different
// goroutine.
type UTXO struct {
	msg *zap.Message
	obj zap.Object
}

// TxID returns the spent UTXO's tx id.
func (u UTXO) TxID() ids.ID {
	var out ids.ID
	for i := 0; i < 32; i++ {
		out[i] = u.obj.Uint8(OffsetUTXO_TxID + i)
	}
	return out
}

// OutputIndex returns the spent UTXO's output index.
func (u UTXO) OutputIndex() uint32 {
	return u.obj.Uint32(OffsetUTXO_OutputIndex)
}

// AssetID returns the asset identifier.
func (u UTXO) AssetID() ids.ID {
	var out ids.ID
	for i := 0; i < 32; i++ {
		out[i] = u.obj.Uint8(OffsetUTXO_AssetID + i)
	}
	return out
}

// OutputBytes returns the inner fxs primitive's wire envelope (2-byte
// discriminator prefix + ZAP message). Use WrapTransferableOutput,
// WrapMintOutput, etc. to parse the bytes into a typed accessor after
// dispatching on the (TypeKind, ShapeKind) pair.
//
// READ-ONLY: aliases the underlying ZAP buffer.
func (u UTXO) OutputBytes() []byte {
	return u.obj.Bytes(OffsetUTXO_Output)
}

// OutputDiscriminator returns the (TypeKind, ShapeKind) pair embedded
// at the head of OutputBytes(). Returns (0, 0) when OutputBytes is
// shorter than the 2-byte prefix.
func (u UTXO) OutputDiscriminator() (TypeKind, ShapeKind) {
	b := u.OutputBytes()
	if len(b) < EnvelopePrefix {
		return 0, 0
	}
	return TypeKind(b[0]), ShapeKind(b[1])
}

// Bytes returns the full wire envelope (2-byte discriminator prefix +
// ZAP message) for the UTXO. Stable across calls — backed by the
// originally-parsed buffer.
func (u UTXO) Bytes() []byte {
	out := make([]byte, EnvelopePrefix+len(u.msg.Bytes()))
	out[0] = byte(TypeKindReserved) // UTXOs aren't fx-owned; TypeKind=0
	out[1] = byte(ShapeKindUTXO)
	copy(out[EnvelopePrefix:], u.msg.Bytes())
	return out
}

// IsZero reports whether the accessor wraps a parsed message.
func (u UTXO) IsZero() bool { return u.msg == nil }

// WrapUTXO parses a UTXO wire envelope into a typed accessor.
//
// Returns ErrShortEnvelope when the buffer is shorter than the 2-byte
// discriminator prefix; ErrWrongShapeKind when the prefix names a
// non-UTXO shape.
func WrapUTXO(b []byte) (UTXO, error) {
	_, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return UTXO{}, err
	}
	if sk != ShapeKindUTXO {
		return UTXO{}, ErrWrongShapeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return UTXO{}, err
	}
	return UTXO{msg: msg, obj: msg.Root()}, nil
}

// UTXOInput is the constructor input for NewUTXO.
type UTXOInput struct {
	TxID        ids.ID
	OutputIndex uint32
	AssetID     ids.ID
	// Output is the inner fxs primitive's wire envelope (already
	// prefixed with its own discriminator). The constructor stores
	// these bytes verbatim in the Output field.
	Output []byte
}

// NewUTXO builds a UTXO wire envelope (2-byte discriminator prefix +
// ZAP message) from the input fields. The returned slice is the
// canonical on-wire representation.
func NewUTXO(in UTXOInput) []byte {
	capEstimate := zap.HeaderSize + SizeUTXO + len(in.Output) + 64
	b := zap.NewBuilder(capEstimate)

	ob := b.StartObject(SizeUTXO)
	for i := 0; i < 32; i++ {
		ob.SetUint8(OffsetUTXO_TxID+i, in.TxID[i])
	}
	ob.SetUint32(OffsetUTXO_OutputIndex, in.OutputIndex)
	for i := 0; i < 32; i++ {
		ob.SetUint8(OffsetUTXO_AssetID+i, in.AssetID[i])
	}
	ob.SetBytes(OffsetUTXO_Output, in.Output)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(TypeKindReserved, ShapeKindUTXO, b.Finish())
}
