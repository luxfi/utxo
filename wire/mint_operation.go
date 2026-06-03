// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import "github.com/luxfi/zap"

// MintOperation is the cross-fx ZAP schema for the MintOperation
// primitive (Input { SigIndices } + MintOutput + TransferOutput).
// Operationally: an asset-minting authority (the MintInput's SigIndices)
// produces a new TransferOutput (value) and updates/re-confirms the
// MintOutput (mint authority continuation).
//
// Fixed-section layout (size 24 bytes):
//
//	SigIndicesList list @ 0    (8 bytes — for the mint authority signatures)
//	MintOutputBytes bytes @ 8  (8 bytes — wire envelope of MintOutput)
//	TransferOutputBytes bytes @ 16  (8 bytes — wire envelope of TransferOutput)
//
// Wire prefix: TypeKind names the fx; ShapeKind is
// ShapeKindMintOperation (0x05). The inner MintOutputBytes and
// TransferOutputBytes carry their own discriminator pairs — consumers
// dispatch via WrapMintOutput / WrapTransferOutput.
const (
	OffsetMintOperation_SigIndicesList      = 0  // list (8 bytes)
	OffsetMintOperation_MintOutputBytes     = 8  // bytes (8 bytes)
	OffsetMintOperation_TransferOutputBytes = 16 // bytes (8 bytes)
	SizeMintOperation                       = 24
)

// MintOperation is the zero-copy typed accessor.
type MintOperation struct {
	tk  TypeKind
	msg *zap.Message
	obj zap.Object
}

// TypeKind returns the fx family that owns this operation.
func (m MintOperation) TypeKind() TypeKind { return m.tk }

// SigIndices returns the mint-authority signature indices.
func (m MintOperation) SigIndices() []uint32 {
	l := m.obj.ListStride(OffsetMintOperation_SigIndicesList, SigIndexStride)
	n := l.Len()
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = l.Uint32(i)
	}
	return out
}

// MintOutputBytes returns the inner MintOutput wire envelope. Pass to
// WrapMintOutput for typed access.
//
// READ-ONLY: aliases the underlying buffer.
func (m MintOperation) MintOutputBytes() []byte {
	return m.obj.Bytes(OffsetMintOperation_MintOutputBytes)
}

// TransferOutputBytes returns the inner TransferOutput wire envelope.
// Pass to WrapTransferOutput for typed access.
//
// READ-ONLY: aliases the underlying buffer.
func (m MintOperation) TransferOutputBytes() []byte {
	return m.obj.Bytes(OffsetMintOperation_TransferOutputBytes)
}

// IsZero reports whether the accessor wraps a parsed message.
func (m MintOperation) IsZero() bool { return m.msg == nil }

// WrapMintOperation parses a MintOperation wire envelope.
func WrapMintOperation(b []byte) (MintOperation, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return MintOperation{}, err
	}
	if sk != ShapeKindMintOperation {
		return MintOperation{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return MintOperation{}, ErrWrongTypeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return MintOperation{}, err
	}
	return MintOperation{tk: tk, msg: msg, obj: msg.Root()}, nil
}

// MintOperationInput is the constructor input.
type MintOperationInput struct {
	TypeKind       TypeKind
	SigIndices     []uint32
	MintOutput     []byte // wire envelope from NewMintOutput
	TransferOutput []byte // wire envelope from NewTransferOutput
}

// NewMintOperation builds a MintOperation wire envelope.
func NewMintOperation(in MintOperationInput) []byte {
	capEstimate := zap.HeaderSize + SizeMintOperation +
		len(in.SigIndices)*SigIndexStride +
		len(in.MintOutput) + len(in.TransferOutput) + 64
	b := zap.NewBuilder(capEstimate)

	sigIdxOff, sigIdxCount := writeSigIndices(b, in.SigIndices)

	ob := b.StartObject(SizeMintOperation)
	ob.SetList(OffsetMintOperation_SigIndicesList, sigIdxOff, sigIdxCount)
	ob.SetBytes(OffsetMintOperation_MintOutputBytes, in.MintOutput)
	ob.SetBytes(OffsetMintOperation_TransferOutputBytes, in.TransferOutput)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindMintOperation, b.Finish())
}
