// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// TransferableOut / TransferableIn are the cross-fx CONTAINERS that bind an
// AssetID (and, for inputs, the spent UTXOID) to a concrete inner fx
// primitive. X-Chain is a universal multi-asset settlement layer, so an
// output/input on the wire is NOT a bare fx TransferOutput/TransferInput — it
// MUST name the asset it moves.
//
// NATIVE-NESTED FORM: a TransferableOut/In is a ZAP object living INLINE inside
// its parent XVMBaseTx buffer (referenced by an AddObjectPtr list slot), NOT a
// standalone prefixed envelope. The container itself is fx-agnostic — it needs
// no TypeKind/ShapeKind prefix; the owning fx TypeKind travels on the INNER
// Output/Input envelope's own 2-byte discriminator. Dropping the container
// prefix + the parent blob-concat is the write-path win: the accessors below
// alias the parent message's buffer directly.

// ---- TransferableOut object ----
//
//	AssetID 32B   @ 0
//	Output  bytes @ 32  (relOffset + length, 8 bytes — inner fx Output envelope)
const (
	OffsetTransferableOut_AssetID = 0
	OffsetTransferableOut_Output  = 32
	SizeTransferableOut           = 40
)

// TransferableOut is a zero-copy typed accessor over a TransferableOut object
// nested in a parent (XVMBaseTx) ZAP message.
//
// READ-ONLY: every field aliases the parent buffer. Use append([]byte(nil),
// ...) to take ownership of OutputBytes when handing off to another goroutine.
type TransferableOut struct {
	msg *zap.Message
	obj zap.Object
}

// transferableOutAt wraps the object at a parent list slot.
func transferableOutAt(msg *zap.Message, obj zap.Object) TransferableOut {
	return TransferableOut{msg: msg, obj: obj}
}

// TransferableOutFromObject wraps a nested TransferableOut object reached from
// a parent AddObjectPtr list slot (e.g. ExportTx's ExportedOuts list). msg is
// the parent message (obj.Message()); obj is the list element from
// List.ObjectPtr. This is the exported reader every native-nested carrier of
// TransferableOut objects uses — one way to read a nested transferable.
func TransferableOutFromObject(msg *zap.Message, obj zap.Object) TransferableOut {
	return TransferableOut{msg: msg, obj: obj}
}

// AssetID returns the asset identifier this output moves.
func (t TransferableOut) AssetID() ids.ID {
	return ids.ID(t.obj.BytesFixedSlice(OffsetTransferableOut_AssetID, 32))
}

// OutputBytes returns the inner fx Output wire envelope (2-byte discriminator
// prefix + ZAP message). Dispatch on OutputDiscriminator, then the fx Wrap*.
//
// READ-ONLY: aliases the parent buffer.
func (t TransferableOut) OutputBytes() []byte {
	return t.obj.Bytes(OffsetTransferableOut_Output)
}

// OutputDiscriminator returns the (TypeKind, ShapeKind) at the head of
// OutputBytes(). Returns (0, 0) when shorter than the 2-byte prefix.
func (t TransferableOut) OutputDiscriminator() (TypeKind, ShapeKind) {
	b := t.OutputBytes()
	if len(b) < EnvelopePrefix {
		return 0, 0
	}
	return TypeKind(b[0]), ShapeKind(b[1])
}

// IsZero reports whether the accessor wraps a parsed object.
func (t TransferableOut) IsZero() bool { return t.msg == nil }

// ---- TransferableIn object ----
//
//	TxID        32B    @ 0
//	OutputIndex uint32 @ 32
//	AssetID     32B    @ 36
//	Input       bytes  @ 68  (relOffset + length, 8 bytes — inner fx Input envelope)
const (
	OffsetTransferableIn_TxID        = 0
	OffsetTransferableIn_OutputIndex = 32
	OffsetTransferableIn_AssetID     = 36
	OffsetTransferableIn_Input       = 68
	SizeTransferableIn               = 76
)

// TransferableIn is a zero-copy typed accessor over a TransferableIn object
// nested in a parent (XVMBaseTx) ZAP message.
type TransferableIn struct {
	msg *zap.Message
	obj zap.Object
}

func transferableInAt(msg *zap.Message, obj zap.Object) TransferableIn {
	return TransferableIn{msg: msg, obj: obj}
}

// TransferableInFromObject wraps a nested TransferableIn object reached from a
// parent AddObjectPtr list slot (e.g. ImportTx's ImportedIns list).
func TransferableInFromObject(msg *zap.Message, obj zap.Object) TransferableIn {
	return TransferableIn{msg: msg, obj: obj}
}

// TxID returns the spent UTXO's tx id.
func (t TransferableIn) TxID() ids.ID {
	return ids.ID(t.obj.BytesFixedSlice(OffsetTransferableIn_TxID, 32))
}

// OutputIndex returns the spent UTXO's output index.
func (t TransferableIn) OutputIndex() uint32 {
	return t.obj.Uint32(OffsetTransferableIn_OutputIndex)
}

// AssetID returns the asset identifier the spent UTXO holds.
func (t TransferableIn) AssetID() ids.ID {
	return ids.ID(t.obj.BytesFixedSlice(OffsetTransferableIn_AssetID, 32))
}

// InputBytes returns the inner fx Input wire envelope (2-byte discriminator
// prefix + ZAP message). Dispatch on InputDiscriminator, then WrapTransferInput.
//
// READ-ONLY: aliases the parent buffer.
func (t TransferableIn) InputBytes() []byte {
	return t.obj.Bytes(OffsetTransferableIn_Input)
}

// InputDiscriminator returns the (TypeKind, ShapeKind) at the head of
// InputBytes(). Returns (0, 0) when shorter than the 2-byte prefix.
func (t TransferableIn) InputDiscriminator() (TypeKind, ShapeKind) {
	b := t.InputBytes()
	if len(b) < EnvelopePrefix {
		return 0, 0
	}
	return TypeKind(b[0]), ShapeKind(b[1])
}

// IsZero reports whether the accessor wraps a parsed object.
func (t TransferableIn) IsZero() bool { return t.msg == nil }

// ---- inline builders (write a Transferable object into an open builder) ----

// AppendTransferableOut writes a TransferableOut object into b and returns its
// offset (for an AddObjectPtr slot). The inner fx Output envelope bytes are
// stored zero-copy in the Output field. Exported so any native-nested carrier
// (XVMBaseTx here, ExportTx in node) nests a transferable ONE way.
func AppendTransferableOut(b *zap.Builder, assetID ids.ID, innerEnvelope []byte) int {
	ob := b.StartObject(SizeTransferableOut)
	ob.SetBytesFixed(OffsetTransferableOut_AssetID, assetID[:])
	ob.SetBytes(OffsetTransferableOut_Output, innerEnvelope)
	return ob.Finish()
}

// AppendTransferableIn writes a TransferableIn object into b and returns its
// offset.
func AppendTransferableIn(b *zap.Builder, txID ids.ID, outputIndex uint32, assetID ids.ID, innerEnvelope []byte) int {
	ob := b.StartObject(SizeTransferableIn)
	ob.SetBytesFixed(OffsetTransferableIn_TxID, txID[:])
	ob.SetUint32(OffsetTransferableIn_OutputIndex, outputIndex)
	ob.SetBytesFixed(OffsetTransferableIn_AssetID, assetID[:])
	ob.SetBytes(OffsetTransferableIn_Input, innerEnvelope)
	return ob.Finish()
}
