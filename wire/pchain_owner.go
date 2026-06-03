// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// PChainOwner is the cross-VM ZAP schema for
// github.com/luxfi/node/vms/platformvm/warp/message.PChainOwner. Strict
// subset of OutputOwners: Threshold + Addresses, no Locktime.
//
// Used in warp validator registration where locktime is not a meaningful
// gate (validator weight changes happen at known points in the
// permissionless validator pipeline).
//
// Fixed-section layout (size 12 bytes):
//
//	Threshold   uint32 @ 0
//	AddressList list   @ 4   (4-byte relOffset + 4-byte length, 8 bytes)
//
// Total fixed section = 12 bytes.
const (
	OffsetPChainOwner_Threshold   = 0 // uint32
	OffsetPChainOwner_AddressList = 4 // list (8 bytes)
	SizePChainOwner               = 12
)

// PChainOwner is the zero-copy typed accessor over a ZAP-encoded
// PChainOwner wire envelope.
type PChainOwner struct {
	msg *zap.Message
	obj zap.Object
}

// Threshold returns the signatures-required count.
func (p PChainOwner) Threshold() uint32 {
	return p.obj.Uint32(OffsetPChainOwner_Threshold)
}

// AddressList returns the variable-stride address list view.
func (p PChainOwner) AddressList() AddressList {
	return AddressList{list: p.obj.ListStride(OffsetPChainOwner_AddressList, AddressStride)}
}

// IsZero reports whether the accessor wraps a parsed message.
func (p PChainOwner) IsZero() bool { return p.msg == nil }

// SyntacticVerify enforces the executor-side semantic gates: non-empty
// addresses, non-zero threshold, threshold <= len(addresses), every
// address non-zero. Returns one of the OutputOwners error sentinels.
func (p PChainOwner) SyntacticVerify() error {
	addrs := p.AddressList()
	n := addrs.Len()
	if n == 0 {
		return ErrOwnerAddrsEmpty
	}
	t := p.Threshold()
	if t == 0 {
		return ErrOwnerThresholdZero
	}
	if uint64(t) > uint64(n) {
		return ErrOwnerThresholdExceedsAddrs
	}
	for i := 0; i < n; i++ {
		if addrs.At(i) == (ids.ShortID{}) {
			return ErrOwnerAddrZero
		}
	}
	return nil
}

// WrapPChainOwner parses a PChainOwner wire envelope into a typed
// accessor.
func WrapPChainOwner(b []byte) (PChainOwner, error) {
	_, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return PChainOwner{}, err
	}
	if sk != ShapeKindPChainOwner {
		return PChainOwner{}, ErrWrongShapeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return PChainOwner{}, err
	}
	return PChainOwner{msg: msg, obj: msg.Root()}, nil
}

// PChainOwnerInput is the constructor input for NewPChainOwner.
type PChainOwnerInput struct {
	Threshold uint32
	Addresses []ids.ShortID
}

// NewPChainOwner builds a PChainOwner wire envelope.
func NewPChainOwner(in PChainOwnerInput) []byte {
	capEstimate := zap.HeaderSize + SizePChainOwner + len(in.Addresses)*AddressStride + 64
	b := zap.NewBuilder(capEstimate)

	addrListOff, addrListCount := writeAddressList(b, in.Addresses)

	ob := b.StartObject(SizePChainOwner)
	ob.SetUint32(OffsetPChainOwner_Threshold, in.Threshold)
	ob.SetList(OffsetPChainOwner_AddressList, addrListOff, addrListCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(TypeKindReserved, ShapeKindPChainOwner, b.Finish())
}
