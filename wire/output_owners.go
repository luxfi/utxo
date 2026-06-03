// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"errors"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// OutputOwners is the cross-VM ZAP schema for
// github.com/luxfi/utxo/secp256k1fx.OutputOwners. Carries a Locktime, a
// signature-threshold count, and a variable-length list of 20-byte
// addresses (the addresses that may co-sign to spend an output owned
// by this group).
//
// Fixed-section layout (size 20 bytes; uint64 reads alignment-tolerant):
//
//	Locktime    uint64 @ 0
//	Threshold   uint32 @ 8
//	AddressList list   @ 12   (4-byte relOffset + 4-byte length, 8 bytes)
//
// Total fixed section = 20 bytes. AddressList payload is stride-20 in
// the variable section.
//
// Semantically equivalent to message.PChainOwner when Locktime=0; the
// PChainOwner wire envelope uses ShapeKindPChainOwner and skips the
// Locktime field entirely (see WrapPChainOwner below).
const (
	OffsetOutputOwners_Locktime    = 0  // uint64
	OffsetOutputOwners_Threshold   = 8  // uint32
	OffsetOutputOwners_AddressList = 12 // list (8 bytes)
	SizeOutputOwners               = 20
)

// AddressStride is the per-element width of an AddressList in the
// OutputOwners variable section. Each address is a 20-byte ids.ShortID.
const AddressStride = ids.ShortIDLen

// Semantic-verification errors. The wire layer (ZAP) is permissive by
// design — semantic gates live here. Mirrors the
// zap_native/owner.go Owner.SyntacticVerify error set so cross-VM
// consumers see a single canonical error set.
var (
	ErrOwnerThresholdZero         = errors.New("wire: OutputOwners.Threshold must be > 0; threshold=0 disables authorization")
	ErrOwnerThresholdExceedsAddrs = errors.New("wire: OutputOwners.Threshold exceeds Addresses.Len() — unsatisfiable signer quorum")
	ErrOwnerAddrsEmpty            = errors.New("wire: OutputOwners.Addresses is empty — signer set undefined")
	ErrOwnerAddrZero              = errors.New("wire: OutputOwners.Addresses contains the zero ShortID — phantom signer")
)

// OutputOwners is the zero-copy typed accessor over a ZAP-encoded
// OutputOwners wire envelope.
//
// READ-ONLY: each address aliases the underlying ZAP buffer.
type OutputOwners struct {
	msg *zap.Message
	obj zap.Object
}

// Locktime returns the unix timestamp before which the output cannot be
// spent.
func (o OutputOwners) Locktime() uint64 {
	return o.obj.Uint64(OffsetOutputOwners_Locktime)
}

// Threshold returns the number of signatures required to spend.
func (o OutputOwners) Threshold() uint32 {
	return o.obj.Uint32(OffsetOutputOwners_Threshold)
}

// AddressList returns the variable-stride address list view.
func (o OutputOwners) AddressList() AddressList {
	return AddressList{list: o.obj.ListStride(OffsetOutputOwners_AddressList, AddressStride)}
}

// IsZero reports whether the accessor wraps a parsed message.
func (o OutputOwners) IsZero() bool { return o.msg == nil }

// SyntacticVerify enforces every executor-side semantic gate on an
// OutputOwners read from an untrusted wire buffer:
//   - Addresses non-empty
//   - Threshold > 0
//   - Threshold <= len(Addresses)
//   - Every Address is non-zero
//
// Returns one of the typed sentinel errors above, or nil when valid.
// Every consumer that treats Threshold/Addresses as a quorum gate MUST
// call SyntacticVerify before trusting the values.
func (o OutputOwners) SyntacticVerify() error {
	addrs := o.AddressList()
	n := addrs.Len()
	if n == 0 {
		return ErrOwnerAddrsEmpty
	}
	t := o.Threshold()
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

// AddressList is the zero-copy view over the address list inside an
// OutputOwners. Stride is 20 bytes (ids.ShortIDLen).
type AddressList struct {
	list zap.List
}

// Len returns the number of addresses.
func (a AddressList) Len() int { return a.list.Len() }

// IsNull returns true if no list pointer was set.
func (a AddressList) IsNull() bool { return a.list.IsNull() }

// At returns the i'th address. Returns the zero ShortID when out of range.
//
// CONSUMER SAFETY (RED-HIGH-3): when i >= the actual entry count (a
// malicious encoder published a length-padded list), this returns the
// zero ShortID which is a phantom signer. Always call
// OutputOwners.SyntacticVerify() before iterating.
func (a AddressList) At(i int) ids.ShortID {
	var out ids.ShortID
	if i < 0 || i >= a.list.Len() {
		return out
	}
	obj := a.list.Object(i, AddressStride)
	for j := 0; j < AddressStride; j++ {
		out[j] = obj.Uint8(j)
	}
	return out
}

// All returns a fresh []ShortID copy of every address in the list.
func (a AddressList) All() []ids.ShortID {
	n := a.list.Len()
	out := make([]ids.ShortID, n)
	for i := 0; i < n; i++ {
		out[i] = a.At(i)
	}
	return out
}

// WrapOutputOwners parses an OutputOwners wire envelope into a typed
// accessor. The discriminator is (TypeKindReserved, ShapeKindOutputOwners)
// — owners are not fx-owned, every fx with multi-address ownership
// shares the same wire schema.
func WrapOutputOwners(b []byte) (OutputOwners, error) {
	_, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return OutputOwners{}, err
	}
	if sk != ShapeKindOutputOwners {
		return OutputOwners{}, ErrWrongShapeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return OutputOwners{}, err
	}
	return OutputOwners{msg: msg, obj: msg.Root()}, nil
}

// OutputOwnersInput is the constructor input for NewOutputOwners.
type OutputOwnersInput struct {
	Locktime  uint64
	Threshold uint32
	Addresses []ids.ShortID
}

// NewOutputOwners builds an OutputOwners wire envelope.
func NewOutputOwners(in OutputOwnersInput) []byte {
	capEstimate := zap.HeaderSize + SizeOutputOwners + len(in.Addresses)*AddressStride + 64
	b := zap.NewBuilder(capEstimate)

	// Write the address list first so its offset is known when the parent
	// object's list pointer is set.
	addrListOff, addrListCount := writeAddressList(b, in.Addresses)

	ob := b.StartObject(SizeOutputOwners)
	ob.SetUint64(OffsetOutputOwners_Locktime, in.Locktime)
	ob.SetUint32(OffsetOutputOwners_Threshold, in.Threshold)
	ob.SetList(OffsetOutputOwners_AddressList, addrListOff, addrListCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(TypeKindReserved, ShapeKindOutputOwners, b.Finish())
}

// writeAddressList writes a stride-20 address list and returns the
// (offset, entry-count) pair.
func writeAddressList(b *zap.Builder, addrs []ids.ShortID) (offset, entryCount int) {
	if len(addrs) == 0 {
		return 0, 0
	}
	lb := b.StartList(AddressStride)
	for _, a := range addrs {
		lb.AddBytes(a[:])
	}
	off, _ := lb.Finish()
	return off, len(addrs)
}
