// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import "github.com/luxfi/zap"

// LockedOutput is the cross-fx ZAP schema for stakeable-locked outputs
// (the platformvm/stakeable.LockOut primitive). Carries a Locktime and
// an inner TransferableOut wire envelope (any fx's TransferOutput).
// Operationally: an output that cannot be spent until block.Timestamp
// >= Locktime, wrapping any fx's transfer output.
//
// Fixed-section layout (size 16 bytes):
//
//	Locktime         uint64 @ 0   (8 bytes — unlock unix time)
//	TransferOutBytes bytes  @ 8   (8 bytes — inner wire envelope)
//
// Wire prefix: TypeKind is TypeKindReserved (lock is fx-agnostic; inner
// envelope carries its own fx TypeKind). ShapeKind is
// ShapeKindLockedOutput (0x0F). The inner TransferOutBytes carries its
// own discriminator pair — consumers dispatch via WrapTransferOutput
// or the fx-specific wrap.
const (
	OffsetLockedOutput_Locktime         = 0 // uint64
	OffsetLockedOutput_TransferOutBytes = 8 // bytes (8 bytes)
	SizeLockedOutput                    = 16
)

// LockedOutput is the zero-copy typed accessor.
type LockedOutput struct {
	msg *zap.Message
	obj zap.Object
}

// Locktime returns the unix timestamp before which the inner output
// cannot be spent.
func (l LockedOutput) Locktime() uint64 {
	return l.obj.Uint64(OffsetLockedOutput_Locktime)
}

// TransferOutBytes returns the inner TransferableOut wire envelope.
// Pass to the appropriate fx's WrapTransferOutput for typed access.
//
// READ-ONLY: aliases the underlying buffer.
func (l LockedOutput) TransferOutBytes() []byte {
	return l.obj.Bytes(OffsetLockedOutput_TransferOutBytes)
}

// IsZero reports whether the accessor wraps a parsed message.
func (l LockedOutput) IsZero() bool { return l.msg == nil }

// WrapLockedOutput parses a LockedOutput wire envelope.
func WrapLockedOutput(b []byte) (LockedOutput, error) {
	_, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return LockedOutput{}, err
	}
	if sk != ShapeKindLockedOutput {
		return LockedOutput{}, ErrWrongShapeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return LockedOutput{}, err
	}
	return LockedOutput{msg: msg, obj: msg.Root()}, nil
}

// LockedOutputInput is the constructor input.
type LockedOutputInput struct {
	Locktime         uint64
	TransferOutBytes []byte // wire envelope from any fx's NewTransferOutput
}

// NewLockedOutput builds a LockedOutput wire envelope.
func NewLockedOutput(in LockedOutputInput) []byte {
	capEstimate := zap.HeaderSize + SizeLockedOutput + len(in.TransferOutBytes) + 64
	b := zap.NewBuilder(capEstimate)

	ob := b.StartObject(SizeLockedOutput)
	ob.SetUint64(OffsetLockedOutput_Locktime, in.Locktime)
	ob.SetBytes(OffsetLockedOutput_TransferOutBytes, in.TransferOutBytes)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(TypeKindReserved, ShapeKindLockedOutput, b.Finish())
}
