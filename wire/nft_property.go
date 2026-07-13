// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// This file defines the wire envelopes for the two application fx families
// built on secp256k1 credentials: nftfx (TypeKindNFT) and propertyfx
// (TypeKindProperty). Their bare-OutputOwners states (propertyfx MintOutput /
// OwnedOutput, and credentials) reuse the existing MintOutput / Credential
// shapes; only the GroupID/Payload composites and the operation shapes are
// new:
//
//	ShapeKindNFTMintOutput     (0x10): GroupID + owners
//	ShapeKindNFTTransferOutput (0x11): GroupID + Payload + owners
//	ShapeKindNFTMintOperation  (0x13): SigIndices + GroupID + Payload + []owners
//	ShapeKindNFTTransferOp     (0x14): SigIndices + nested NFTTransferOutput
//	ShapeKindOwnedOutput       (0x15): bare owners (property state output)
//	ShapeKindBurnOperation     (0x16): SigIndices only

// ---- NFTMintOutput ----
//
// Fixed-section layout (size 24 bytes):
//
//	GroupID     uint32 @ 0
//	Locktime    uint64 @ 4
//	Threshold   uint32 @ 12
//	AddressList list   @ 16   (8 bytes)
const (
	OffsetNFTMintOutput_GroupID     = 0
	OffsetNFTMintOutput_Locktime    = 4
	OffsetNFTMintOutput_Threshold   = 12
	OffsetNFTMintOutput_AddressList = 16
	SizeNFTMintOutput               = 24
)

// NFTMintOutput is the zero-copy typed accessor.
type NFTMintOutput struct {
	tk  TypeKind
	msg *zap.Message
	obj zap.Object
}

func (m NFTMintOutput) TypeKind() TypeKind { return m.tk }
func (m NFTMintOutput) GroupID() uint32    { return m.obj.Uint32(OffsetNFTMintOutput_GroupID) }
func (m NFTMintOutput) Locktime() uint64   { return m.obj.Uint64(OffsetNFTMintOutput_Locktime) }
func (m NFTMintOutput) Threshold() uint32  { return m.obj.Uint32(OffsetNFTMintOutput_Threshold) }
func (m NFTMintOutput) AddressList() AddressList {
	return AddressList{list: m.obj.ListStride(OffsetNFTMintOutput_AddressList, AddressStride)}
}
func (m NFTMintOutput) IsZero() bool { return m.msg == nil }

// WrapNFTMintOutput parses an NFTMintOutput wire envelope.
func WrapNFTMintOutput(b []byte) (NFTMintOutput, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return NFTMintOutput{}, err
	}
	if sk != ShapeKindNFTMintOutput {
		return NFTMintOutput{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return NFTMintOutput{}, ErrWrongTypeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return NFTMintOutput{}, err
	}
	return NFTMintOutput{tk: tk, msg: msg, obj: msg.Root()}, nil
}

// NFTMintOutputInput is the constructor input.
type NFTMintOutputInput struct {
	TypeKind  TypeKind
	GroupID   uint32
	Locktime  uint64
	Threshold uint32
	Addresses []ids.ShortID
}

// NewNFTMintOutput builds an NFTMintOutput wire envelope.
func NewNFTMintOutput(in NFTMintOutputInput) []byte {
	b := zap.GetBuilder()
	defer zap.PutBuilder(b)

	addrListOff, addrListCount := writeAddressList(b, in.Addresses)

	ob := b.StartObject(SizeNFTMintOutput)
	ob.SetUint32(OffsetNFTMintOutput_GroupID, in.GroupID)
	ob.SetUint64(OffsetNFTMintOutput_Locktime, in.Locktime)
	ob.SetUint32(OffsetNFTMintOutput_Threshold, in.Threshold)
	ob.SetList(OffsetNFTMintOutput_AddressList, addrListOff, addrListCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindNFTMintOutput, b.Finish())
}

// ---- NFTTransferOutput ----
//
// Fixed-section layout (size 32 bytes):
//
//	GroupID     uint32 @ 0
//	Locktime    uint64 @ 4
//	Threshold   uint32 @ 12
//	AddressList list   @ 16   (8 bytes)
//	Payload     bytes  @ 24   (8 bytes)
const (
	OffsetNFTTransferOutput_GroupID     = 0
	OffsetNFTTransferOutput_Locktime    = 4
	OffsetNFTTransferOutput_Threshold   = 12
	OffsetNFTTransferOutput_AddressList = 16
	OffsetNFTTransferOutput_Payload     = 24
	SizeNFTTransferOutput               = 32
)

// NFTTransferOutput is the zero-copy typed accessor.
type NFTTransferOutput struct {
	tk  TypeKind
	msg *zap.Message
	obj zap.Object
}

func (m NFTTransferOutput) TypeKind() TypeKind { return m.tk }
func (m NFTTransferOutput) GroupID() uint32    { return m.obj.Uint32(OffsetNFTTransferOutput_GroupID) }
func (m NFTTransferOutput) Locktime() uint64 {
	return m.obj.Uint64(OffsetNFTTransferOutput_Locktime)
}
func (m NFTTransferOutput) Threshold() uint32 {
	return m.obj.Uint32(OffsetNFTTransferOutput_Threshold)
}
func (m NFTTransferOutput) AddressList() AddressList {
	return AddressList{list: m.obj.ListStride(OffsetNFTTransferOutput_AddressList, AddressStride)}
}

// Payload returns the NFT payload bytes.
//
// READ-ONLY: aliases the underlying buffer.
func (m NFTTransferOutput) Payload() []byte {
	return m.obj.Bytes(OffsetNFTTransferOutput_Payload)
}
func (m NFTTransferOutput) IsZero() bool { return m.msg == nil }

// WrapNFTTransferOutput parses an NFTTransferOutput wire envelope.
func WrapNFTTransferOutput(b []byte) (NFTTransferOutput, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return NFTTransferOutput{}, err
	}
	if sk != ShapeKindNFTTransferOutput {
		return NFTTransferOutput{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return NFTTransferOutput{}, ErrWrongTypeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return NFTTransferOutput{}, err
	}
	return NFTTransferOutput{tk: tk, msg: msg, obj: msg.Root()}, nil
}

// NFTTransferOutputInput is the constructor input.
type NFTTransferOutputInput struct {
	TypeKind  TypeKind
	GroupID   uint32
	Payload   []byte
	Locktime  uint64
	Threshold uint32
	Addresses []ids.ShortID
}

// NewNFTTransferOutput builds an NFTTransferOutput wire envelope.
func NewNFTTransferOutput(in NFTTransferOutputInput) []byte {
	b := zap.GetBuilder()
	defer zap.PutBuilder(b)

	addrListOff, addrListCount := writeAddressList(b, in.Addresses)

	ob := b.StartObject(SizeNFTTransferOutput)
	ob.SetUint32(OffsetNFTTransferOutput_GroupID, in.GroupID)
	ob.SetUint64(OffsetNFTTransferOutput_Locktime, in.Locktime)
	ob.SetUint32(OffsetNFTTransferOutput_Threshold, in.Threshold)
	ob.SetList(OffsetNFTTransferOutput_AddressList, addrListOff, addrListCount)
	ob.SetBytes(OffsetNFTTransferOutput_Payload, in.Payload)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindNFTTransferOutput, b.Finish())
}

// ---- NFTMintOperation ----
//
// Fixed-section layout (size 36 bytes):
//
//	SigIndicesList list  @ 0    (8 bytes)
//	GroupID        uint32 @ 8
//	Payload        bytes @ 12   (8 bytes)
//	OwnersCount    uint32 @ 20
//	OwnersBytes    bytes @ 24   (8 bytes — concatenated OutputOwners envelopes)
//	_pad           uint32 @ 32  (reserved, zero)
//
// Each owners entry is a self-describing OutputOwners wire envelope; walk
// with OwnersAt.
const (
	OffsetNFTMintOperation_SigIndicesList = 0
	OffsetNFTMintOperation_GroupID        = 8
	OffsetNFTMintOperation_Payload        = 12
	OffsetNFTMintOperation_OwnersCount    = 20
	OffsetNFTMintOperation_OwnersBytes    = 24
	SizeNFTMintOperation                  = 36
)

// NFTMintOperation is the zero-copy typed accessor.
type NFTMintOperation struct {
	tk  TypeKind
	msg *zap.Message
	obj zap.Object
}

func (m NFTMintOperation) TypeKind() TypeKind { return m.tk }
func (m NFTMintOperation) GroupID() uint32    { return m.obj.Uint32(OffsetNFTMintOperation_GroupID) }

// SigIndices returns the mint-authority signature indices.
func (m NFTMintOperation) SigIndices() []uint32 {
	l := m.obj.ListStride(OffsetNFTMintOperation_SigIndicesList, SigIndexStride)
	n := l.Len()
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = l.Uint32(i)
	}
	return out
}

// Payload returns the NFT payload bytes.
//
// READ-ONLY: aliases the underlying buffer.
func (m NFTMintOperation) Payload() []byte {
	return m.obj.Bytes(OffsetNFTMintOperation_Payload)
}

// OwnersCount returns the number of minted-to owner groups.
func (m NFTMintOperation) OwnersCount() uint32 {
	return m.obj.Uint32(OffsetNFTMintOperation_OwnersCount)
}

// OwnersBytes returns the concatenated OutputOwners envelopes blob.
//
// READ-ONLY: aliases the underlying buffer.
func (m NFTMintOperation) OwnersBytes() []byte {
	return m.obj.Bytes(OffsetNFTMintOperation_OwnersBytes)
}

func (m NFTMintOperation) IsZero() bool { return m.msg == nil }

// WrapNFTMintOperation parses an NFTMintOperation wire envelope.
func WrapNFTMintOperation(b []byte) (NFTMintOperation, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return NFTMintOperation{}, err
	}
	if sk != ShapeKindNFTMintOperation {
		return NFTMintOperation{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return NFTMintOperation{}, ErrWrongTypeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return NFTMintOperation{}, err
	}
	return NFTMintOperation{tk: tk, msg: msg, obj: msg.Root()}, nil
}

// NFTMintOperationInput is the constructor input.
type NFTMintOperationInput struct {
	TypeKind   TypeKind
	SigIndices []uint32
	GroupID    uint32
	Payload    []byte
	Owners     [][]byte // wire envelopes from NewOutputOwners
}

// NewNFTMintOperation builds an NFTMintOperation wire envelope.
func NewNFTMintOperation(in NFTMintOperationInput) []byte {
	ownersLen := 0
	for _, o := range in.Owners {
		ownersLen += len(o)
	}
	b := zap.GetBuilder()
	defer zap.PutBuilder(b)

	sigIdxOff, sigIdxCount := writeSigIndices(b, in.SigIndices)

	var ownersBlob []byte
	for _, o := range in.Owners {
		ownersBlob = append(ownersBlob, o...)
	}

	ob := b.StartObject(SizeNFTMintOperation)
	ob.SetList(OffsetNFTMintOperation_SigIndicesList, sigIdxOff, sigIdxCount)
	ob.SetUint32(OffsetNFTMintOperation_GroupID, in.GroupID)
	ob.SetBytes(OffsetNFTMintOperation_Payload, in.Payload)
	ob.SetUint32(OffsetNFTMintOperation_OwnersCount, uint32(len(in.Owners)))
	ob.SetBytes(OffsetNFTMintOperation_OwnersBytes, ownersBlob)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindNFTMintOperation, b.Finish())
}

// ---- NFTTransferOperation ----
//
// Fixed-section layout (size 16 bytes):
//
//	SigIndicesList list  @ 0   (8 bytes)
//	OutputBytes    bytes @ 8   (8 bytes — wire envelope of NFTTransferOutput)
const (
	OffsetNFTTransferOp_SigIndicesList = 0
	OffsetNFTTransferOp_OutputBytes    = 8
	SizeNFTTransferOp                  = 16
)

// NFTTransferOperation is the zero-copy typed accessor.
type NFTTransferOperation struct {
	tk  TypeKind
	msg *zap.Message
	obj zap.Object
}

func (m NFTTransferOperation) TypeKind() TypeKind { return m.tk }

// SigIndices returns the input signature indices.
func (m NFTTransferOperation) SigIndices() []uint32 {
	l := m.obj.ListStride(OffsetNFTTransferOp_SigIndicesList, SigIndexStride)
	n := l.Len()
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = l.Uint32(i)
	}
	return out
}

// OutputBytes returns the inner NFTTransferOutput wire envelope.
//
// READ-ONLY: aliases the underlying buffer.
func (m NFTTransferOperation) OutputBytes() []byte {
	return m.obj.Bytes(OffsetNFTTransferOp_OutputBytes)
}

func (m NFTTransferOperation) IsZero() bool { return m.msg == nil }

// WrapNFTTransferOperation parses an NFTTransferOperation wire envelope.
func WrapNFTTransferOperation(b []byte) (NFTTransferOperation, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return NFTTransferOperation{}, err
	}
	if sk != ShapeKindNFTTransferOp {
		return NFTTransferOperation{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return NFTTransferOperation{}, ErrWrongTypeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return NFTTransferOperation{}, err
	}
	return NFTTransferOperation{tk: tk, msg: msg, obj: msg.Root()}, nil
}

// NFTTransferOperationInput is the constructor input.
type NFTTransferOperationInput struct {
	TypeKind   TypeKind
	SigIndices []uint32
	Output     []byte // wire envelope from NewNFTTransferOutput
}

// NewNFTTransferOperation builds an NFTTransferOperation wire envelope.
func NewNFTTransferOperation(in NFTTransferOperationInput) []byte {
	b := zap.GetBuilder()
	defer zap.PutBuilder(b)

	sigIdxOff, sigIdxCount := writeSigIndices(b, in.SigIndices)

	ob := b.StartObject(SizeNFTTransferOp)
	ob.SetList(OffsetNFTTransferOp_SigIndicesList, sigIdxOff, sigIdxCount)
	ob.SetBytes(OffsetNFTTransferOp_OutputBytes, in.Output)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindNFTTransferOp, b.Finish())
}

// ---- OwnedOutput ----
//
// Bare OutputOwners state output (propertyfx). Same payload layout as
// OutputOwners/MintOutput; the distinct ShapeKind is what separates a
// property state output from a mint authority.
const (
	OffsetOwnedOutput_Locktime    = OffsetOutputOwners_Locktime
	OffsetOwnedOutput_Threshold   = OffsetOutputOwners_Threshold
	OffsetOwnedOutput_AddressList = OffsetOutputOwners_AddressList
	SizeOwnedOutput               = SizeOutputOwners
)

// OwnedOutput is the zero-copy typed accessor.
type OwnedOutput struct {
	tk  TypeKind
	msg *zap.Message
	obj zap.Object
}

func (m OwnedOutput) TypeKind() TypeKind { return m.tk }
func (m OwnedOutput) Locktime() uint64   { return m.obj.Uint64(OffsetOwnedOutput_Locktime) }
func (m OwnedOutput) Threshold() uint32  { return m.obj.Uint32(OffsetOwnedOutput_Threshold) }
func (m OwnedOutput) AddressList() AddressList {
	return AddressList{list: m.obj.ListStride(OffsetOwnedOutput_AddressList, AddressStride)}
}
func (m OwnedOutput) IsZero() bool { return m.msg == nil }

// WrapOwnedOutput parses an OwnedOutput wire envelope.
func WrapOwnedOutput(b []byte) (OwnedOutput, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return OwnedOutput{}, err
	}
	if sk != ShapeKindOwnedOutput {
		return OwnedOutput{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return OwnedOutput{}, ErrWrongTypeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return OwnedOutput{}, err
	}
	return OwnedOutput{tk: tk, msg: msg, obj: msg.Root()}, nil
}

// OwnedOutputInput is the constructor input.
type OwnedOutputInput struct {
	TypeKind  TypeKind
	Locktime  uint64
	Threshold uint32
	Addresses []ids.ShortID
}

// NewOwnedOutput builds an OwnedOutput wire envelope.
func NewOwnedOutput(in OwnedOutputInput) []byte {
	b := zap.GetBuilder()
	defer zap.PutBuilder(b)

	addrListOff, addrListCount := writeAddressList(b, in.Addresses)

	ob := b.StartObject(SizeOwnedOutput)
	ob.SetUint64(OffsetOwnedOutput_Locktime, in.Locktime)
	ob.SetUint32(OffsetOwnedOutput_Threshold, in.Threshold)
	ob.SetList(OffsetOwnedOutput_AddressList, addrListOff, addrListCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindOwnedOutput, b.Finish())
}

// ---- BurnOperation ----
//
// Fixed-section layout (size 8 bytes):
//
//	SigIndicesList list @ 0   (8 bytes)
const (
	OffsetBurnOperation_SigIndicesList = 0
	SizeBurnOperation                  = 8
)

// BurnOperation is the zero-copy typed accessor.
type BurnOperation struct {
	tk  TypeKind
	msg *zap.Message
	obj zap.Object
}

func (m BurnOperation) TypeKind() TypeKind { return m.tk }

// SigIndices returns the input signature indices.
func (m BurnOperation) SigIndices() []uint32 {
	l := m.obj.ListStride(OffsetBurnOperation_SigIndicesList, SigIndexStride)
	n := l.Len()
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = l.Uint32(i)
	}
	return out
}

func (m BurnOperation) IsZero() bool { return m.msg == nil }

// WrapBurnOperation parses a BurnOperation wire envelope.
func WrapBurnOperation(b []byte) (BurnOperation, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return BurnOperation{}, err
	}
	if sk != ShapeKindBurnOperation {
		return BurnOperation{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return BurnOperation{}, ErrWrongTypeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return BurnOperation{}, err
	}
	return BurnOperation{tk: tk, msg: msg, obj: msg.Root()}, nil
}

// BurnOperationInput is the constructor input.
type BurnOperationInput struct {
	TypeKind   TypeKind
	SigIndices []uint32
}

// NewBurnOperation builds a BurnOperation wire envelope.
func NewBurnOperation(in BurnOperationInput) []byte {
	b := zap.GetBuilder()
	defer zap.PutBuilder(b)

	sigIdxOff, sigIdxCount := writeSigIndices(b, in.SigIndices)

	ob := b.StartObject(SizeBurnOperation)
	ob.SetList(OffsetBurnOperation_SigIndicesList, sigIdxOff, sigIdxCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindBurnOperation, b.Finish())
}
