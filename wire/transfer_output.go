// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// TransferOutput is the cross-fx ZAP schema for the TransferOutput
// primitive (`Amt uint64 + OutputOwners`). Every classical fx
// (secp256k1fx, ed25519fx, secp256r1fx, schnorrfx) and post-quantum fx
// (mldsafx, slhdsafx) use this same shape — they differ only in the
// Credential's signature size, not in the spending-output layout.
//
// Fixed-section layout (size 28 bytes; uint64 reads alignment-tolerant):
//
//	Amount      uint64 @ 0
//	Locktime    uint64 @ 8
//	Threshold   uint32 @ 16
//	AddressList list   @ 20   (4-byte relOffset + 4-byte length, 8 bytes)
//
// Total fixed section = 28 bytes. The TypeKind discriminator byte in the
// 2-byte wire prefix names the owning fx (e.g. 0x01=secp256k1fx,
// 0x02=mldsafx). The ShapeKind byte is always
// ShapeKindTransferOutput (0x01).
const (
	OffsetTransferOutput_Amount      = 0  // uint64
	OffsetTransferOutput_Locktime    = 8  // uint64
	OffsetTransferOutput_Threshold   = 16 // uint32
	OffsetTransferOutput_AddressList = 20 // list (8 bytes)
	SizeTransferOutput               = 28
)

// TransferOutput is the zero-copy typed accessor over a ZAP-encoded
// TransferOutput wire envelope.
type TransferOutput struct {
	tk  TypeKind
	msg *zap.Message
	obj zap.Object
}

// TypeKind returns the fx family that owns this output.
func (t TransferOutput) TypeKind() TypeKind { return t.tk }

// Amount returns the asset amount this output is worth.
func (t TransferOutput) Amount() uint64 {
	return t.obj.Uint64(OffsetTransferOutput_Amount)
}

// Locktime returns the unix timestamp before which the output cannot be
// spent.
func (t TransferOutput) Locktime() uint64 {
	return t.obj.Uint64(OffsetTransferOutput_Locktime)
}

// Threshold returns the signatures-required count.
func (t TransferOutput) Threshold() uint32 {
	return t.obj.Uint32(OffsetTransferOutput_Threshold)
}

// AddressList returns the address list view.
func (t TransferOutput) AddressList() AddressList {
	return AddressList{list: t.obj.ListStride(OffsetTransferOutput_AddressList, AddressStride)}
}

// SyntacticVerify enforces the same gates as OutputOwners.SyntacticVerify
// plus Amount > 0.
func (t TransferOutput) SyntacticVerify() error {
	addrs := t.AddressList()
	n := addrs.Len()
	if n == 0 {
		return ErrOwnerAddrsEmpty
	}
	th := t.Threshold()
	if th == 0 {
		return ErrOwnerThresholdZero
	}
	if uint64(th) > uint64(n) {
		return ErrOwnerThresholdExceedsAddrs
	}
	for i := 0; i < n; i++ {
		if addrs.At(i) == (ids.ShortID{}) {
			return ErrOwnerAddrZero
		}
	}
	return nil
}

// IsZero reports whether the accessor wraps a parsed message.
func (t TransferOutput) IsZero() bool { return t.msg == nil }

// WrapTransferOutput parses a TransferOutput wire envelope into a typed
// accessor. Accepts any TypeKind (classical or PQ); ShapeKind must be
// ShapeKindTransferOutput.
func WrapTransferOutput(b []byte) (TransferOutput, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return TransferOutput{}, err
	}
	if sk != ShapeKindTransferOutput {
		return TransferOutput{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return TransferOutput{}, ErrWrongTypeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return TransferOutput{}, err
	}
	return TransferOutput{tk: tk, msg: msg, obj: msg.Root()}, nil
}

// TransferOutputInput is the constructor input.
type TransferOutputInput struct {
	TypeKind  TypeKind
	Amount    uint64
	Locktime  uint64
	Threshold uint32
	Addresses []ids.ShortID
}

// NewTransferOutput builds a TransferOutput wire envelope.
func NewTransferOutput(in TransferOutputInput) []byte {
	capEstimate := zap.HeaderSize + SizeTransferOutput + len(in.Addresses)*AddressStride + 64
	b := zap.NewBuilder(capEstimate)

	addrListOff, addrListCount := writeAddressList(b, in.Addresses)

	ob := b.StartObject(SizeTransferOutput)
	ob.SetUint64(OffsetTransferOutput_Amount, in.Amount)
	ob.SetUint64(OffsetTransferOutput_Locktime, in.Locktime)
	ob.SetUint32(OffsetTransferOutput_Threshold, in.Threshold)
	ob.SetList(OffsetTransferOutput_AddressList, addrListOff, addrListCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindTransferOutput, b.Finish())
}
