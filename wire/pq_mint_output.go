// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import "github.com/luxfi/zap"

// PQMintOutput is the cross-PQ-fx ZAP schema for the MintOutput
// primitive carrying variable-length PQ pubkeys (mldsafx, slhdsafx).
//
// Same payload as PQOutputOwners — MintOutput identifies a mint-authority
// owner group, not a value-bearing output. Only the ShapeKind
// discriminator distinguishes "mint authority" from "spending owner".
const (
	OffsetPQMintOutput_SecurityLevel = OffsetPQOutputOwners_SecurityLevel // 0
	OffsetPQMintOutput_Locktime      = OffsetPQOutputOwners_Locktime      // 8
	OffsetPQMintOutput_Threshold     = OffsetPQOutputOwners_Threshold     // 16
	OffsetPQMintOutput_PubKeyList    = OffsetPQOutputOwners_PubKeyList    // 24
	SizePQMintOutput                 = SizePQOutputOwners                 // 32
)

// ShapeKindPQMintOutput is the discriminator for PQ-fx MintOutput.
const ShapeKindPQMintOutput ShapeKind = 0x11

// PQMintOutput is the zero-copy typed accessor.
type PQMintOutput struct {
	tk     TypeKind
	stride int
	msg    *zap.Message
	obj    zap.Object
}

// TypeKind returns the PQ fx family.
func (m PQMintOutput) TypeKind() TypeKind { return m.tk }

// SecurityLevel returns the fx-specific security level byte.
func (m PQMintOutput) SecurityLevel() uint8 {
	return m.obj.Uint8(OffsetPQMintOutput_SecurityLevel)
}

// Locktime returns the unix timestamp before which mint cannot fire.
func (m PQMintOutput) Locktime() uint64 {
	return m.obj.Uint64(OffsetPQMintOutput_Locktime)
}

// Threshold returns the signatures-required count for mint authority.
func (m PQMintOutput) Threshold() uint32 {
	return m.obj.Uint32(OffsetPQMintOutput_Threshold)
}

// PubKeyStride returns the per-element width of the PubKeys list.
func (m PQMintOutput) PubKeyStride() int { return m.stride }

// PubKeys returns the variable-stride pubkey list view.
func (m PQMintOutput) PubKeys() PQPubKeyList {
	return PQPubKeyList{stride: m.stride, list: m.obj.ListStride(OffsetPQMintOutput_PubKeyList, uint32(m.stride))}
}

// SyntacticVerify enforces the same gates as PQOutputOwners.
func (m PQMintOutput) SyntacticVerify() error {
	pks := m.PubKeys()
	n := pks.Len()
	if n == 0 {
		return ErrPQOwnerPubKeysEmpty
	}
	th := m.Threshold()
	if th == 0 {
		return ErrPQOwnerThresholdZero
	}
	if uint64(th) > uint64(n) {
		return ErrPQOwnerThresholdExceeds
	}
	var prev []byte
	for i := 0; i < n; i++ {
		pk := pks.At(i)
		if len(pk) != m.stride {
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
func (m PQMintOutput) IsZero() bool { return m.msg == nil }

// WrapPQMintOutput parses a PQMintOutput wire envelope.
func WrapPQMintOutput(b []byte, stride int) (PQMintOutput, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return PQMintOutput{}, err
	}
	if sk != ShapeKindPQMintOutput {
		return PQMintOutput{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return PQMintOutput{}, ErrWrongTypeKind
	}
	if stride <= 0 {
		return PQMintOutput{}, ErrPQOwnerPubKeyWrongStride
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return PQMintOutput{}, err
	}
	return PQMintOutput{tk: tk, stride: stride, msg: msg, obj: msg.Root()}, nil
}

// PQMintOutputInput is the constructor input.
type PQMintOutputInput struct {
	TypeKind      TypeKind
	SecurityLevel uint8
	Locktime      uint64
	Threshold     uint32
	PubKeyStride  int
	PubKeys       [][]byte
}

// NewPQMintOutput builds a PQMintOutput wire envelope.
func NewPQMintOutput(in PQMintOutputInput) []byte {
	stride := in.PubKeyStride
	if stride <= 0 {
		stride = 1
	}
	capEstimate := zap.HeaderSize + SizePQMintOutput + len(in.PubKeys)*stride + 64
	b := zap.NewBuilder(capEstimate)

	pkListOff, pkListCount := writePQPubKeyList(b, in.PubKeys, stride)

	ob := b.StartObject(SizePQMintOutput)
	ob.SetUint8(OffsetPQMintOutput_SecurityLevel, in.SecurityLevel)
	ob.SetUint64(OffsetPQMintOutput_Locktime, in.Locktime)
	ob.SetUint32(OffsetPQMintOutput_Threshold, in.Threshold)
	ob.SetList(OffsetPQMintOutput_PubKeyList, pkListOff, pkListCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindPQMintOutput, b.Finish())
}
