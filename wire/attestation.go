// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import "github.com/luxfi/zap"

// BLS12381 attestation primitives. The bls12381fx is divergent from the
// classical / PQ pattern — it is attestation-only (no Mint primitives,
// no transfer-value semantics). The output records "this 32-byte
// commitment was attested to by the listed BLS public keys at the listed
// threshold". The input is a signer-bitmap selecting which committee
// members contributed.
//
// BLS12381 sizes:
//   - PubKeyLen        = 48 (compressed G1)
//   - AggSigLen        = 96 (compressed G2)
//   - AttestedHashLen  = 32
const (
	BLS12381PubKeyLen       = 48
	BLS12381AggSigLen       = 96
	BLS12381AttestedHashLen = 32
)

// AttestationOutput is the cross-fx ZAP schema for the bls12381fx
// AttestationOutput.
//
// Fixed-section layout (size 48 bytes):
//
//	AttestedHash  32B    @ 0
//	Threshold     uint32 @ 32
//	_padding      4B     @ 36   (reserved-zero, 8-aligned)
//	PubKeyList    list   @ 40   (8 bytes; payload is stride-48 G1 pubkeys)
//
// Wire prefix: TypeKind=0x07 (BLS12381), ShapeKind=0x07
// (AttestationOutput).
const (
	OffsetAttestationOutput_AttestedHash = 0  // 32B
	OffsetAttestationOutput_Threshold    = 32 // uint32
	OffsetAttestationOutput_PubKeyList   = 40 // list (8 bytes)
	SizeAttestationOutput                = 48
)

// AttestationOutput is the zero-copy typed accessor.
type AttestationOutput struct {
	msg *zap.Message
	obj zap.Object
}

// AttestedHash returns the 32-byte commitment.
func (a AttestationOutput) AttestedHash() [BLS12381AttestedHashLen]byte {
	var out [BLS12381AttestedHashLen]byte
	for i := 0; i < BLS12381AttestedHashLen; i++ {
		out[i] = a.obj.Uint8(OffsetAttestationOutput_AttestedHash + i)
	}
	return out
}

// Threshold returns the minimum number of pubkeys required.
func (a AttestationOutput) Threshold() uint32 {
	return a.obj.Uint32(OffsetAttestationOutput_Threshold)
}

// PubKeys returns the committee pubkeys as a fresh [][]byte slice (each
// inner []byte is BLS12381PubKeyLen = 48 bytes).
func (a AttestationOutput) PubKeys() [][]byte {
	l := a.obj.ListStride(OffsetAttestationOutput_PubKeyList, BLS12381PubKeyLen)
	n := l.Len()
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		pk := make([]byte, BLS12381PubKeyLen)
		obj := l.Object(i, BLS12381PubKeyLen)
		for j := 0; j < BLS12381PubKeyLen; j++ {
			pk[j] = obj.Uint8(j)
		}
		out[i] = pk
	}
	return out
}

// IsZero reports whether the accessor wraps a parsed message.
func (a AttestationOutput) IsZero() bool { return a.msg == nil }

// WrapAttestationOutput parses an AttestationOutput wire envelope.
func WrapAttestationOutput(b []byte) (AttestationOutput, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return AttestationOutput{}, err
	}
	if tk != TypeKindBLS12381 {
		return AttestationOutput{}, ErrWrongTypeKind
	}
	if sk != ShapeKindAttestationOut {
		return AttestationOutput{}, ErrWrongShapeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return AttestationOutput{}, err
	}
	return AttestationOutput{msg: msg, obj: msg.Root()}, nil
}

// AttestationOutputInput is the constructor input.
type AttestationOutputInput struct {
	AttestedHash [BLS12381AttestedHashLen]byte
	Threshold    uint32
	// PubKeys MUST each be BLS12381PubKeyLen bytes; the constructor does
	// not pad or truncate. Sort lexicographically before passing in —
	// AttestationOutput.Verify requires sorted-unique pubkeys.
	PubKeys [][]byte
}

// NewAttestationOutput builds an AttestationOutput wire envelope.
func NewAttestationOutput(in AttestationOutputInput) []byte {
	capEstimate := zap.HeaderSize + SizeAttestationOutput + len(in.PubKeys)*BLS12381PubKeyLen + 64
	b := zap.NewBuilder(capEstimate)

	pkListOff, pkListCount := writePubKeyList(b, in.PubKeys, BLS12381PubKeyLen)

	ob := b.StartObject(SizeAttestationOutput)
	for i := 0; i < BLS12381AttestedHashLen; i++ {
		ob.SetUint8(OffsetAttestationOutput_AttestedHash+i, in.AttestedHash[i])
	}
	ob.SetUint32(OffsetAttestationOutput_Threshold, in.Threshold)
	ob.SetList(OffsetAttestationOutput_PubKeyList, pkListOff, pkListCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(TypeKindBLS12381, ShapeKindAttestationOut, b.Finish())
}

// writePubKeyList writes a stride-N pubkey list. N is the per-pubkey byte
// width (48 for BLS12-381 G1, 32 for Ed25519/Schnorr, 64 for secp256r1).
func writePubKeyList(b *zap.Builder, pks [][]byte, pkLen int) (offset, entryCount int) {
	if len(pks) == 0 {
		return 0, 0
	}
	lb := b.StartList(pkLen)
	for _, pk := range pks {
		// Pad/truncate to pkLen so all entries are the same stride. A
		// well-behaved caller already enforces uniform length; we still
		// pad here so a buggy caller produces a parseable (if invalid)
		// message rather than corrupted memory.
		entry := make([]byte, pkLen)
		copy(entry, pk)
		lb.AddBytes(entry)
	}
	off, _ := lb.Finish()
	return off, len(pks)
}

// AttestationInput is the cross-fx ZAP schema for the bls12381fx
// AttestationInput.
//
// Fixed-section layout (size 8 bytes):
//
//	SignerBitmap bytes @ 0   (8 bytes — relOffset + length)
//
// The signer bitmap is a packed bit array where bit i (LSB of byte i/8)
// indicates that PubKeys[i] of the spent AttestationOutput contributed
// to the aggregate signature.
//
// Wire prefix: TypeKind=0x07 (BLS12381), ShapeKind=0x08
// (AttestationInput).
const (
	OffsetAttestationInput_SignerBitmap = 0 // bytes (8 bytes)
	SizeAttestationInput                = 8
)

// AttestationInput is the zero-copy typed accessor.
type AttestationInput struct {
	msg *zap.Message
	obj zap.Object
}

// SignerBitmap returns the signer-selection bitmap.
//
// READ-ONLY: aliases the underlying buffer.
func (a AttestationInput) SignerBitmap() []byte {
	return a.obj.Bytes(OffsetAttestationInput_SignerBitmap)
}

// IsZero reports whether the accessor wraps a parsed message.
func (a AttestationInput) IsZero() bool { return a.msg == nil }

// WrapAttestationInput parses an AttestationInput wire envelope.
func WrapAttestationInput(b []byte) (AttestationInput, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return AttestationInput{}, err
	}
	if tk != TypeKindBLS12381 {
		return AttestationInput{}, ErrWrongTypeKind
	}
	if sk != ShapeKindAttestationIn {
		return AttestationInput{}, ErrWrongShapeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return AttestationInput{}, err
	}
	return AttestationInput{msg: msg, obj: msg.Root()}, nil
}

// AttestationInputInput is the constructor input.
type AttestationInputInput struct {
	SignerBitmap []byte
}

// NewAttestationInput builds an AttestationInput wire envelope.
func NewAttestationInput(in AttestationInputInput) []byte {
	capEstimate := zap.HeaderSize + SizeAttestationInput + len(in.SignerBitmap) + 64
	b := zap.NewBuilder(capEstimate)

	ob := b.StartObject(SizeAttestationInput)
	ob.SetBytes(OffsetAttestationInput_SignerBitmap, in.SignerBitmap)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(TypeKindBLS12381, ShapeKindAttestationIn, b.Finish())
}
