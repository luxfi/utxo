// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// MintOutput is the cross-fx ZAP schema for the MintOutput primitive
// (`OutputOwners`). Same shape as OutputOwners — MintOutput identifies a
// mint-authority owner group, not a value-bearing output.
//
// Fixed-section layout (size 20 bytes; identical to OutputOwners):
//
//	Locktime    uint64 @ 0
//	Threshold   uint32 @ 8
//	AddressList list   @ 12   (4-byte relOffset + 4-byte length, 8 bytes)
//
// Wire prefix: TypeKind names the fx; ShapeKind is ShapeKindMintOutput
// (0x03). Same payload bytes as a TransferOutput owner section — only
// the ShapeKind discriminator distinguishes "mint authority" from
// "spending output".
const (
	OffsetMintOutput_Locktime    = OffsetOutputOwners_Locktime    // 0
	OffsetMintOutput_Threshold   = OffsetOutputOwners_Threshold   // 8
	OffsetMintOutput_AddressList = OffsetOutputOwners_AddressList // 12
	SizeMintOutput               = SizeOutputOwners               // 20
)

// MintOutput is the zero-copy typed accessor.
type MintOutput struct {
	tk  TypeKind
	msg *zap.Message
	obj zap.Object
}

// TypeKind returns the fx family that owns this mint authority.
func (m MintOutput) TypeKind() TypeKind { return m.tk }

// Locktime returns the unix timestamp before which mint cannot fire.
func (m MintOutput) Locktime() uint64 {
	return m.obj.Uint64(OffsetMintOutput_Locktime)
}

// Threshold returns the signatures-required count for mint authority.
func (m MintOutput) Threshold() uint32 {
	return m.obj.Uint32(OffsetMintOutput_Threshold)
}

// AddressList returns the mint authority address list.
func (m MintOutput) AddressList() AddressList {
	return AddressList{list: m.obj.ListStride(OffsetMintOutput_AddressList, AddressStride)}
}

// SyntacticVerify enforces the same gates as OutputOwners.
func (m MintOutput) SyntacticVerify() error {
	addrs := m.AddressList()
	n := addrs.Len()
	if n == 0 {
		return ErrOwnerAddrsEmpty
	}
	th := m.Threshold()
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
func (m MintOutput) IsZero() bool { return m.msg == nil }

// WrapMintOutput parses a MintOutput wire envelope.
func WrapMintOutput(b []byte) (MintOutput, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return MintOutput{}, err
	}
	if sk != ShapeKindMintOutput {
		return MintOutput{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return MintOutput{}, ErrWrongTypeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return MintOutput{}, err
	}
	return MintOutput{tk: tk, msg: msg, obj: msg.Root()}, nil
}

// MintOutputInput is the constructor input.
type MintOutputInput struct {
	TypeKind  TypeKind
	Locktime  uint64
	Threshold uint32
	Addresses []ids.ShortID
}

// NewMintOutput builds a MintOutput wire envelope.
func NewMintOutput(in MintOutputInput) []byte {
	capEstimate := zap.HeaderSize + SizeMintOutput + len(in.Addresses)*AddressStride + 64
	b := zap.NewBuilder(capEstimate)

	addrListOff, addrListCount := writeAddressList(b, in.Addresses)

	ob := b.StartObject(SizeMintOutput)
	ob.SetUint64(OffsetMintOutput_Locktime, in.Locktime)
	ob.SetUint32(OffsetMintOutput_Threshold, in.Threshold)
	ob.SetList(OffsetMintOutput_AddressList, addrListOff, addrListCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindMintOutput, b.Finish())
}
