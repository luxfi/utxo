// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// XVMBaseTx is the X-chain BaseTx wire object — the ZAP-native replacement for
// the reflection-encoded `xvm/txs.BaseTx`.
//
// NATIVE-NESTED FORM: the outputs and inputs are AddObjectPtr object-lists —
// each element is a TransferableOut/In object living INLINE in this same
// buffer, reached by a 4-byte signed pointer slot. There are no per-container
// TypeKind/ShapeKind prefixes, no blob concatenation, and no parallel length
// list: the object-ptr list is the native "repeated message" encoding. The
// inner fx Output/Input envelope (which DOES carry an fx discriminator, since
// polymorphism lives there) is stored zero-copy in the leaf object's bytes
// field.
//
//	NetworkID    uint32     @ 0
//	BlockchainID 32B        @ 8   (8-aligned)
//	Outs         objptrlist @ 40  (relOffset + count, 8 bytes)
//	Ins          objptrlist @ 48  (relOffset + count, 8 bytes)
//	Memo         bytes      @ 56  (relOffset + length, 8 bytes)
const (
	OffsetXVMBaseTx_NetworkID    = 0
	OffsetXVMBaseTx_BlockchainID = 8
	OffsetXVMBaseTx_Outs         = 40
	OffsetXVMBaseTx_Ins          = 48
	OffsetXVMBaseTx_Memo         = 56
	SizeXVMBaseTx                = 64

	// objPtrStride is the per-element width of an AddObjectPtr list (a 4-byte
	// signed relative pointer).
	objPtrStride = 4
)

// XVMBaseTx is the zero-copy typed accessor.
//
// READ-ONLY: every accessor aliases the underlying ZAP buffer. Mutation
// corrupts any TxID = hash(buffer) computed downstream.
type XVMBaseTx struct {
	b   []byte
	msg *zap.Message
	obj zap.Object
}

// NetworkID returns the network id.
func (t XVMBaseTx) NetworkID() uint32 {
	return t.obj.Uint32(OffsetXVMBaseTx_NetworkID)
}

// BlockchainID returns the 32-byte chain id.
func (t XVMBaseTx) BlockchainID() [32]byte {
	return [32]byte(t.obj.BytesFixedSlice(OffsetXVMBaseTx_BlockchainID, 32))
}

// OutsCount returns the number of transferable outputs.
func (t XVMBaseTx) OutsCount() uint32 {
	return uint32(t.obj.ListStride(OffsetXVMBaseTx_Outs, objPtrStride).Len())
}

// OutAt returns the i'th TransferableOut (AssetID + inner fx Output). X-Chain
// is multi-asset, so every output names the asset it moves.
func (t XVMBaseTx) OutAt(i uint32) (TransferableOut, error) {
	l := t.obj.ListStride(OffsetXVMBaseTx_Outs, objPtrStride)
	if int(i) >= l.Len() {
		return TransferableOut{}, ErrShortEnvelope
	}
	o := l.ObjectPtr(int(i))
	if o.IsNull() {
		return TransferableOut{}, ErrShortEnvelope
	}
	return transferableOutAt(t.msg, o), nil
}

// InsCount returns the number of transferable inputs.
func (t XVMBaseTx) InsCount() uint32 {
	return uint32(t.obj.ListStride(OffsetXVMBaseTx_Ins, objPtrStride).Len())
}

// InAt returns the i'th TransferableIn (UTXOID + AssetID + inner fx Input).
func (t XVMBaseTx) InAt(i uint32) (TransferableIn, error) {
	l := t.obj.ListStride(OffsetXVMBaseTx_Ins, objPtrStride)
	if int(i) >= l.Len() {
		return TransferableIn{}, ErrShortEnvelope
	}
	o := l.ObjectPtr(int(i))
	if o.IsNull() {
		return TransferableIn{}, ErrShortEnvelope
	}
	return transferableInAt(t.msg, o), nil
}

// Memo returns the memo bytes.
//
// READ-ONLY: aliases the underlying buffer.
func (t XVMBaseTx) Memo() []byte {
	return t.obj.Bytes(OffsetXVMBaseTx_Memo)
}

// Bytes returns the full wire envelope (2-byte discriminator prefix + ZAP
// message). Stable across calls — backed by the originally-parsed buffer.
func (t XVMBaseTx) Bytes() []byte { return t.b }

// IsZero reports whether the accessor wraps a parsed message.
func (t XVMBaseTx) IsZero() bool { return t.msg == nil }

// WrapXVMBaseTx parses an XVM BaseTx wire envelope into a typed accessor.
func WrapXVMBaseTx(b []byte) (XVMBaseTx, error) {
	_, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return XVMBaseTx{}, err
	}
	if sk != ShapeKindXVMBaseTx {
		return XVMBaseTx{}, ErrWrongShapeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return XVMBaseTx{}, err
	}
	return XVMBaseTx{b: b, msg: msg, obj: msg.Root()}, nil
}

// XVMTransferOut is one output: an AssetID plus the already-built inner fx
// Output envelope (from NewTransferOutput / NewMintOutput / NewNFT*).
type XVMTransferOut struct {
	AssetID ids.ID
	Output  []byte
}

// XVMTransferIn is one input: a spent-UTXO reference plus the already-built
// inner fx Input envelope (from NewTransferInput).
type XVMTransferIn struct {
	TxID        ids.ID
	OutputIndex uint32
	AssetID     ids.ID
	Input       []byte
}

// XVMBaseTxInput is the constructor input.
type XVMBaseTxInput struct {
	NetworkID    uint32
	BlockchainID [32]byte
	Outs         []XVMTransferOut
	Ins          []XVMTransferIn
	Memo         []byte
}

// NewXVMBaseTx builds an XVM BaseTx wire envelope with native-nested out/in
// object lists — one buffer, one Finish, zero per-container prefix, zero blob
// concatenation.
func NewXVMBaseTx(in XVMBaseTxInput) []byte {
	b := zap.GetBuilder()
	defer zap.PutBuilder(b)

	// 1. tail each Transferable object; collect absolute offsets.
	outOffs := make([]int, len(in.Outs))
	for i := range in.Outs {
		outOffs[i] = AppendTransferableOut(b, in.Outs[i].AssetID, in.Outs[i].Output)
	}
	inOffs := make([]int, len(in.Ins))
	for i := range in.Ins {
		inOffs[i] = AppendTransferableIn(b, in.Ins[i].TxID, in.Ins[i].OutputIndex, in.Ins[i].AssetID, in.Ins[i].Input)
	}

	// 2. object-ptr lists over those offsets.
	ol := b.StartList(objPtrStride)
	for _, off := range outOffs {
		ol.AddObjectPtr(off)
	}
	outsOff, outsLen := ol.Finish()
	il := b.StartList(objPtrStride)
	for _, off := range inOffs {
		il.AddObjectPtr(off)
	}
	insOff, insLen := il.Finish()

	// 3. root object.
	ob := b.StartObject(SizeXVMBaseTx)
	ob.SetUint32(OffsetXVMBaseTx_NetworkID, in.NetworkID)
	ob.SetBytesFixed(OffsetXVMBaseTx_BlockchainID, in.BlockchainID[:])
	ob.SetList(OffsetXVMBaseTx_Outs, outsOff, outsLen)
	ob.SetList(OffsetXVMBaseTx_Ins, insOff, insLen)
	ob.SetBytes(OffsetXVMBaseTx_Memo, in.Memo)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(TypeKindReserved, ShapeKindXVMBaseTx, b.Finish())
}
