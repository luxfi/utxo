// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import "github.com/luxfi/zap"

// TransferInput is the cross-fx ZAP schema for the TransferInput
// primitive (`Amt uint64 + SigIndices []uint32`). The semantics are
// uniform across classical and PQ fxs — only the matching Credential's
// signature size varies.
//
// Fixed-section layout (size 16 bytes):
//
//	Amount         uint64 @ 0
//	SigIndicesList list   @ 8   (4-byte relOffset + 4-byte length, 8 bytes)
//
// SigIndicesList payload is stride-4 (each entry is a uint32).
//
// Wire prefix discriminator: TypeKind names the fx; ShapeKind is
// ShapeKindTransferInput (0x02).
const (
	OffsetTransferInput_Amount         = 0 // uint64
	OffsetTransferInput_SigIndicesList = 8 // list (8 bytes)
	SizeTransferInput                  = 16
)

// SigIndexStride is the per-element width of the SigIndices list (one
// uint32 per index).
const SigIndexStride = 4

// TransferInput is the zero-copy typed accessor.
type TransferInput struct {
	tk  TypeKind
	msg *zap.Message
	obj zap.Object
}

// TypeKind returns the fx family that owns this input.
func (t TransferInput) TypeKind() TypeKind { return t.tk }

// Amount returns the amount being spent.
func (t TransferInput) Amount() uint64 {
	return t.obj.Uint64(OffsetTransferInput_Amount)
}

// SigIndices returns the SigIndices view as a fresh []uint32.
func (t TransferInput) SigIndices() []uint32 {
	l := t.obj.ListStride(OffsetTransferInput_SigIndicesList, SigIndexStride)
	n := l.Len()
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = l.Uint32(i)
	}
	return out
}

// SigIndicesLen returns the number of signature indices.
func (t TransferInput) SigIndicesLen() int {
	return t.obj.ListStride(OffsetTransferInput_SigIndicesList, SigIndexStride).Len()
}

// IsZero reports whether the accessor wraps a parsed message.
func (t TransferInput) IsZero() bool { return t.msg == nil }

// WrapTransferInput parses a TransferInput wire envelope.
func WrapTransferInput(b []byte) (TransferInput, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return TransferInput{}, err
	}
	if sk != ShapeKindTransferInput {
		return TransferInput{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return TransferInput{}, ErrWrongTypeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return TransferInput{}, err
	}
	return TransferInput{tk: tk, msg: msg, obj: msg.Root()}, nil
}

// TransferInputInput is the constructor input.
type TransferInputInput struct {
	TypeKind   TypeKind
	Amount     uint64
	SigIndices []uint32
}

// NewTransferInput builds a TransferInput wire envelope.
func NewTransferInput(in TransferInputInput) []byte {
	capEstimate := zap.HeaderSize + SizeTransferInput + len(in.SigIndices)*SigIndexStride + 64
	b := zap.NewBuilder(capEstimate)

	sigIdxOff, sigIdxCount := writeSigIndices(b, in.SigIndices)

	ob := b.StartObject(SizeTransferInput)
	ob.SetUint64(OffsetTransferInput_Amount, in.Amount)
	ob.SetList(OffsetTransferInput_SigIndicesList, sigIdxOff, sigIdxCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindTransferInput, b.Finish())
}

// writeSigIndices writes a stride-4 list of uint32 signature indices.
func writeSigIndices(b *zap.Builder, sigs []uint32) (offset, entryCount int) {
	if len(sigs) == 0 {
		return 0, 0
	}
	lb := b.StartList(SigIndexStride)
	for _, s := range sigs {
		lb.AddUint32(s)
	}
	off, _ := lb.Finish()
	return off, len(sigs)
}
