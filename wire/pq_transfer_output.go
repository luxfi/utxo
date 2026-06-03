// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import "github.com/luxfi/zap"

// PQTransferOutput is the cross-PQ-fx ZAP schema for the TransferOutput
// primitive carrying variable-length PQ pubkeys (mldsafx, slhdsafx).
//
// Fixed-section layout (size 40 bytes; uint64 alignment-tolerant):
//
//	SecurityLevel uint8  @ 0
//	_padding      7B     @ 1   (reserved-zero, 8-aligned)
//	Amount        uint64 @ 8
//	Locktime      uint64 @ 16
//	Threshold     uint32 @ 24
//	_padding      4B     @ 28  (reserved-zero, 8-aligned)
//	PubKeyList    list   @ 32  (8 bytes; payload stride is fx-specific)
//
// Wire prefix: TypeKind names the fx; ShapeKind is
// ShapeKindPQTransferOutput (0x10).
const (
	OffsetPQTransferOutput_SecurityLevel = 0  // uint8
	OffsetPQTransferOutput_Amount        = 8  // uint64
	OffsetPQTransferOutput_Locktime      = 16 // uint64
	OffsetPQTransferOutput_Threshold     = 24 // uint32
	OffsetPQTransferOutput_PubKeyList    = 32 // list (8 bytes)
	SizePQTransferOutput                 = 40
)

// ShapeKindPQTransferOutput is the discriminator for PQ-fx TransferOutput.
const ShapeKindPQTransferOutput ShapeKind = 0x10

// PQTransferOutput is the zero-copy typed accessor.
type PQTransferOutput struct {
	tk     TypeKind
	stride int
	msg    *zap.Message
	obj    zap.Object
}

// TypeKind returns the PQ fx family.
func (t PQTransferOutput) TypeKind() TypeKind { return t.tk }

// SecurityLevel returns the fx-specific security level byte.
func (t PQTransferOutput) SecurityLevel() uint8 {
	return t.obj.Uint8(OffsetPQTransferOutput_SecurityLevel)
}

// Amount returns the asset amount this output is worth.
func (t PQTransferOutput) Amount() uint64 {
	return t.obj.Uint64(OffsetPQTransferOutput_Amount)
}

// Locktime returns the unix timestamp before which the output cannot be
// spent.
func (t PQTransferOutput) Locktime() uint64 {
	return t.obj.Uint64(OffsetPQTransferOutput_Locktime)
}

// Threshold returns the signatures-required count.
func (t PQTransferOutput) Threshold() uint32 {
	return t.obj.Uint32(OffsetPQTransferOutput_Threshold)
}

// PubKeyStride returns the per-element width of the PubKeys list.
func (t PQTransferOutput) PubKeyStride() int { return t.stride }

// PubKeys returns the variable-stride pubkey list view.
func (t PQTransferOutput) PubKeys() PQPubKeyList {
	return PQPubKeyList{stride: t.stride, list: t.obj.ListStride(OffsetPQTransferOutput_PubKeyList, uint32(t.stride))}
}

// SyntacticVerify enforces Amount > 0 plus the PQOutputOwners gates.
func (t PQTransferOutput) SyntacticVerify() error {
	if t.Amount() == 0 {
		return ErrPQAmountZero
	}
	pks := t.PubKeys()
	n := pks.Len()
	if n == 0 {
		return ErrPQOwnerPubKeysEmpty
	}
	th := t.Threshold()
	if th == 0 {
		return ErrPQOwnerThresholdZero
	}
	if uint64(th) > uint64(n) {
		return ErrPQOwnerThresholdExceeds
	}
	var prev []byte
	for i := 0; i < n; i++ {
		pk := pks.At(i)
		if len(pk) != t.stride {
			return ErrPQOwnerPubKeyWrongStride
		}
		if prev != nil && pqCompare(prev, pk) >= 0 {
			return ErrPQOwnerPubKeysNotSortedUq
		}
		prev = pk
	}
	return nil
}

// IsZero reports whether the accessor wraps a parsed message.
func (t PQTransferOutput) IsZero() bool { return t.msg == nil }

// WrapPQTransferOutput parses a PQTransferOutput wire envelope.
func WrapPQTransferOutput(b []byte, stride int) (PQTransferOutput, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return PQTransferOutput{}, err
	}
	if sk != ShapeKindPQTransferOutput {
		return PQTransferOutput{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return PQTransferOutput{}, ErrWrongTypeKind
	}
	if stride <= 0 {
		return PQTransferOutput{}, ErrPQOwnerPubKeyWrongStride
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return PQTransferOutput{}, err
	}
	return PQTransferOutput{tk: tk, stride: stride, msg: msg, obj: msg.Root()}, nil
}

// PQTransferOutputInput is the constructor input.
type PQTransferOutputInput struct {
	TypeKind      TypeKind
	SecurityLevel uint8
	Amount        uint64
	Locktime      uint64
	Threshold     uint32
	PubKeyStride  int
	PubKeys       [][]byte
}

// NewPQTransferOutput builds a PQTransferOutput wire envelope.
func NewPQTransferOutput(in PQTransferOutputInput) []byte {
	stride := in.PubKeyStride
	if stride <= 0 {
		stride = 1
	}
	capEstimate := zap.HeaderSize + SizePQTransferOutput + len(in.PubKeys)*stride + 64
	b := zap.NewBuilder(capEstimate)

	pkListOff, pkListCount := writePQPubKeyList(b, in.PubKeys, stride)

	ob := b.StartObject(SizePQTransferOutput)
	ob.SetUint8(OffsetPQTransferOutput_SecurityLevel, in.SecurityLevel)
	ob.SetUint64(OffsetPQTransferOutput_Amount, in.Amount)
	ob.SetUint64(OffsetPQTransferOutput_Locktime, in.Locktime)
	ob.SetUint32(OffsetPQTransferOutput_Threshold, in.Threshold)
	ob.SetList(OffsetPQTransferOutput_PubKeyList, pkListOff, pkListCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindPQTransferOutput, b.Finish())
}
