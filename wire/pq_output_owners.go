// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"errors"

	"github.com/luxfi/zap"
)

// PQOutputOwners is the cross-PQ-fx ZAP schema for fx-specific
// OutputOwners that carry FULL post-quantum public keys (not the
// 20-byte hashed ShortIDs used by classical fxs). Both mldsafx and
// slhdsafx are pubkey-on-chain (no hash address derivation in the
// owner set), so they need a wire schema that varies the pubkey
// stride by the SecurityLevel byte.
//
// Fixed-section layout (size 28 bytes; uint64 alignment-tolerant):
//
//	SecurityLevel uint8  @ 0
//	_padding      7B     @ 1   (reserved-zero, 8-aligned)
//	Locktime      uint64 @ 8
//	Threshold     uint32 @ 16
//	_padding      4B     @ 20  (reserved-zero, 8-aligned)
//	PubKeyList    list   @ 24  (8 bytes; payload stride is fx-specific —
//	                            mldsafx: 1312/1952/2592, slhdsafx: 32/48/64)
//
// Wire prefix: TypeKind names the fx (mldsafx, slhdsafx); ShapeKind is
// ShapeKindPQOutputOwners (0x0F).
const (
	OffsetPQOutputOwners_SecurityLevel = 0  // uint8
	OffsetPQOutputOwners_Locktime      = 8  // uint64
	OffsetPQOutputOwners_Threshold     = 16 // uint32
	OffsetPQOutputOwners_PubKeyList    = 24 // list (8 bytes)
	SizePQOutputOwners                 = 32
)

// ShapeKindPQOutputOwners is the discriminator for PQ-fx OutputOwners.
const ShapeKindPQOutputOwners ShapeKind = 0x0F

// Semantic-verification errors for PQ owners.
var (
	ErrPQOwnerPubKeysEmpty       = errors.New("wire: PQOutputOwners.PubKeys is empty — signer set undefined")
	ErrPQOwnerThresholdZero      = errors.New("wire: PQOutputOwners.Threshold must be > 0; threshold=0 disables authorization")
	ErrPQOwnerThresholdExceeds   = errors.New("wire: PQOutputOwners.Threshold exceeds PubKeys.Len() — unsatisfiable signer quorum")
	ErrPQOwnerPubKeyWrongStride  = errors.New("wire: PQOutputOwners.PubKeys entry does not match SecurityLevel's pubkey stride")
	ErrPQOwnerPubKeysNotSortedUq = errors.New("wire: PQOutputOwners.PubKeys not sorted lexicographically and unique")
	ErrPQAmountZero              = errors.New("wire: PQTransferOutput.Amount must be > 0; zero-value transfers are not permitted")
)

// PQOutputOwners is the zero-copy typed accessor over a ZAP-encoded
// PQOutputOwners wire envelope.
//
// READ-ONLY: each pubkey aliases the underlying ZAP buffer.
type PQOutputOwners struct {
	tk     TypeKind
	stride int
	msg    *zap.Message
	obj    zap.Object
}

// TypeKind returns the PQ fx family that owns this owner set.
func (o PQOutputOwners) TypeKind() TypeKind { return o.tk }

// SecurityLevel returns the fx-specific security level byte.
func (o PQOutputOwners) SecurityLevel() uint8 {
	return o.obj.Uint8(OffsetPQOutputOwners_SecurityLevel)
}

// Locktime returns the unix timestamp before which the output cannot be
// spent.
func (o PQOutputOwners) Locktime() uint64 {
	return o.obj.Uint64(OffsetPQOutputOwners_Locktime)
}

// Threshold returns the number of signatures required to spend.
func (o PQOutputOwners) Threshold() uint32 {
	return o.obj.Uint32(OffsetPQOutputOwners_Threshold)
}

// PubKeyStride returns the per-element width of the PubKeys list, as
// passed to WrapPQOutputOwners. The caller is responsible for resolving
// SecurityLevel → stride; the wire layer is stride-agnostic.
func (o PQOutputOwners) PubKeyStride() int { return o.stride }

// PubKeys returns the variable-stride pubkey list view.
//
// READ-ONLY: each pubkey aliases the underlying ZAP buffer.
func (o PQOutputOwners) PubKeys() PQPubKeyList {
	return PQPubKeyList{stride: o.stride, list: o.obj.ListStride(OffsetPQOutputOwners_PubKeyList, uint32(o.stride))}
}

// IsZero reports whether the accessor wraps a parsed message.
func (o PQOutputOwners) IsZero() bool { return o.msg == nil }

// SyntacticVerify enforces the executor-side semantic gates on a PQ
// owner set read from an untrusted wire buffer. Stride is taken from
// the WrapPQOutputOwners call; per-entry stride mismatches are
// rejected, as are zero-threshold and threshold-exceeds-pubkeys.
func (o PQOutputOwners) SyntacticVerify() error {
	pks := o.PubKeys()
	n := pks.Len()
	if n == 0 {
		return ErrPQOwnerPubKeysEmpty
	}
	t := o.Threshold()
	if t == 0 {
		return ErrPQOwnerThresholdZero
	}
	if uint64(t) > uint64(n) {
		return ErrPQOwnerThresholdExceeds
	}
	var prev []byte
	for i := 0; i < n; i++ {
		pk := pks.At(i)
		if len(pk) != o.stride {
			return ErrPQOwnerPubKeyWrongStride
		}
		if prev != nil {
			if pqCompare(prev, pk) >= 0 {
				return ErrPQOwnerPubKeysNotSortedUq
			}
		}
		prev = pk
	}
	return nil
}

// PQPubKeyList is the zero-copy view over the pubkey list inside a
// PQOutputOwners. Stride is fx-specific.
type PQPubKeyList struct {
	stride int
	list   zap.List
}

// Len returns the number of pubkeys.
func (p PQPubKeyList) Len() int { return p.list.Len() }

// IsNull returns true if no list pointer was set.
func (p PQPubKeyList) IsNull() bool { return p.list.IsNull() }

// At returns the i'th pubkey as a fresh []byte copy of length stride.
// Returns nil when i is out of range.
func (p PQPubKeyList) At(i int) []byte {
	if i < 0 || i >= p.list.Len() {
		return nil
	}
	out := make([]byte, p.stride)
	obj := p.list.Object(i, p.stride)
	for j := 0; j < p.stride; j++ {
		out[j] = obj.Uint8(j)
	}
	return out
}

// All returns a fresh [][]byte copy of every pubkey in the list.
func (p PQPubKeyList) All() [][]byte {
	n := p.list.Len()
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = p.At(i)
	}
	return out
}

// pqCompare compares two byte slices lexicographically. Mirrors
// bytes.Compare without importing bytes (keeps the wire package's
// dependency surface minimal).
func pqCompare(a, b []byte) int {
	min := len(a)
	if len(b) < min {
		min = len(b)
	}
	for i := 0; i < min; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// WrapPQOutputOwners parses a PQOutputOwners wire envelope. The stride
// argument names the fx-specific pubkey size — the wire layer does
// not infer it from SecurityLevel because the fx-to-stride mapping
// lives in the fx package (mldsafx.SecurityLevel.PubKeyLen,
// slhdsafx.SecurityLevel.PubKeyLen).
func WrapPQOutputOwners(b []byte, stride int) (PQOutputOwners, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return PQOutputOwners{}, err
	}
	if sk != ShapeKindPQOutputOwners {
		return PQOutputOwners{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return PQOutputOwners{}, ErrWrongTypeKind
	}
	if stride <= 0 {
		return PQOutputOwners{}, ErrPQOwnerPubKeyWrongStride
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return PQOutputOwners{}, err
	}
	return PQOutputOwners{tk: tk, stride: stride, msg: msg, obj: msg.Root()}, nil
}

// PQOutputOwnersInput is the constructor input for NewPQOutputOwners.
type PQOutputOwnersInput struct {
	TypeKind      TypeKind
	SecurityLevel uint8
	Locktime      uint64
	Threshold     uint32
	// PubKeyStride names the per-entry width of the PubKeys list. The
	// caller is responsible for the SecurityLevel → stride mapping.
	PubKeyStride int
	// PubKeys MUST each be exactly PubKeyStride bytes. The constructor
	// does not pad or truncate.
	PubKeys [][]byte
}

// NewPQOutputOwners builds a PQOutputOwners wire envelope.
func NewPQOutputOwners(in PQOutputOwnersInput) []byte {
	stride := in.PubKeyStride
	if stride <= 0 {
		stride = 1 // refuse to corrupt; caller passes a meaningful stride
	}
	capEstimate := zap.HeaderSize + SizePQOutputOwners + len(in.PubKeys)*stride + 64
	b := zap.NewBuilder(capEstimate)

	pkListOff, pkListCount := writePQPubKeyList(b, in.PubKeys, stride)

	ob := b.StartObject(SizePQOutputOwners)
	ob.SetUint8(OffsetPQOutputOwners_SecurityLevel, in.SecurityLevel)
	ob.SetUint64(OffsetPQOutputOwners_Locktime, in.Locktime)
	ob.SetUint32(OffsetPQOutputOwners_Threshold, in.Threshold)
	ob.SetList(OffsetPQOutputOwners_PubKeyList, pkListOff, pkListCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindPQOutputOwners, b.Finish())
}

// writePQPubKeyList writes a stride-N pubkey list. N is the per-pubkey
// byte width passed in by the fx package.
func writePQPubKeyList(b *zap.Builder, pks [][]byte, stride int) (offset, entryCount int) {
	if len(pks) == 0 || stride <= 0 {
		return 0, 0
	}
	lb := b.StartList(stride)
	for _, pk := range pks {
		entry := make([]byte, stride)
		copy(entry, pk)
		lb.AddBytes(entry)
	}
	off, _ := lb.Finish()
	return off, len(pks)
}
