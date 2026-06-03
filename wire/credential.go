// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"github.com/luxfi/zap"
)

// Credential is the cross-fx ZAP schema for fxs signature credentials.
//
// Classical fx credentials (secp256k1fx, schnorrfx) carry only signatures
// (the pubkey is recoverable from the sig or implicit from the spent
// output's address list). Modern fx credentials (ed25519fx, secp256r1fx)
// carry pubkeys alongside signatures because those schemes are not
// pubkey-recoverable from a single signature. Post-quantum credentials
// (mldsafx, slhdsafx) carry a SecurityLevel byte selecting the parameter
// set, then variable-length signatures.
//
// Fixed-section layout (size 12 bytes):
//
//	SecurityLevel  uint8 @ 0   (0=L1, 1=L2, 2=L3, ... — fx-specific; 0 for classical)
//	_padding       3B    @ 1   (reserved-zero for 4-byte alignment)
//	SignatureList  list  @ 4   (8 bytes; payload is concatenated signature blobs)
//
// Wire prefix: TypeKind names the fx; ShapeKind is ShapeKindCredential
// (0x06). The SignatureList payload is a stride-N byte run where N is
// the per-fx signature size (e.g. 65 for secp256k1, 64 for Ed25519/Schnorr,
// 3309 for ML-DSA-65). Length field counts CONCATENATED BYTES, not
// number of signatures — divide by per-fx stride to recover sig count.
//
// PubKeys (when an fx ships them on the wire alongside sigs) live in a
// trailing PubKeyList field; classical and PQ fxs leave it empty.
const (
	OffsetCredential_SecurityLevel = 0 // uint8
	OffsetCredential_SignatureList = 4 // list (8 bytes)
	OffsetCredential_PubKeyList    = 12
	SizeCredential                 = 20
)

// Credential is the zero-copy typed accessor.
type Credential struct {
	tk  TypeKind
	msg *zap.Message
	obj zap.Object
}

// TypeKind returns the fx family of this credential.
func (c Credential) TypeKind() TypeKind { return c.tk }

// SecurityLevel returns the fx-specific security level byte. 0 for
// classical fxs; (0,1,2) for ML-DSA (-44/-65/-87) and SLH-DSA variants.
func (c Credential) SecurityLevel() uint8 {
	return c.obj.Uint8(OffsetCredential_SecurityLevel)
}

// SignatureBytes returns the concatenated signature blob as a single
// fresh []byte. Divide len()/sigSize to get the signature count.
//
// READ-ONLY: aliases the underlying buffer when used via the List
// accessor. The returned slice is a copy.
func (c Credential) SignatureBytes() []byte {
	l := c.obj.ListStride(OffsetCredential_SignatureList, 1)
	n := l.Len()
	if n == 0 {
		return nil
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = l.Uint8(i)
	}
	return out
}

// SignatureCount returns the number of signatures, given the per-fx
// signature size. Returns 0 if sigSize is 0 or the total bytes don't
// divide cleanly.
func (c Credential) SignatureCount(sigSize int) int {
	if sigSize <= 0 {
		return 0
	}
	total := c.obj.ListStride(OffsetCredential_SignatureList, 1).Len()
	if total%sigSize != 0 {
		return 0
	}
	return total / sigSize
}

// SignatureAt returns the i'th signature, given the per-fx signature size.
// Returns nil when i is out of range or sigSize doesn't divide cleanly.
func (c Credential) SignatureAt(i, sigSize int) []byte {
	if sigSize <= 0 || i < 0 {
		return nil
	}
	all := c.SignatureBytes()
	start := i * sigSize
	end := start + sigSize
	if end > len(all) {
		return nil
	}
	return all[start:end]
}

// PubKeyBytes returns the concatenated pubkey blob, for fxs that ship
// pubkeys on the wire (Ed25519, secp256r1, Schnorr). Classical (secp256k1)
// and PQ (ML-DSA, SLH-DSA) leave this empty.
func (c Credential) PubKeyBytes() []byte {
	l := c.obj.ListStride(OffsetCredential_PubKeyList, 1)
	n := l.Len()
	if n == 0 {
		return nil
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = l.Uint8(i)
	}
	return out
}

// IsZero reports whether the accessor wraps a parsed message.
func (c Credential) IsZero() bool { return c.msg == nil }

// WrapCredential parses a Credential wire envelope.
func WrapCredential(b []byte) (Credential, error) {
	tk, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return Credential{}, err
	}
	if sk != ShapeKindCredential {
		return Credential{}, ErrWrongShapeKind
	}
	if tk == TypeKindReserved {
		return Credential{}, ErrWrongTypeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return Credential{}, err
	}
	return Credential{tk: tk, msg: msg, obj: msg.Root()}, nil
}

// CredentialInput is the constructor input. Signatures and PubKeys MUST
// already be concatenated by the caller — the constructor does not split
// or pad. For classical fxs, PubKeys should be nil.
type CredentialInput struct {
	TypeKind      TypeKind
	SecurityLevel uint8
	// Signatures is the concatenated signature blob: e.g. 2 secp256k1
	// signatures = 2*65 = 130 bytes.
	Signatures []byte
	// PubKeys is the concatenated pubkey blob (empty for classical fxs
	// and ML-DSA/SLH-DSA).
	PubKeys []byte
}

// NewCredential builds a Credential wire envelope.
func NewCredential(in CredentialInput) []byte {
	capEstimate := zap.HeaderSize + SizeCredential + len(in.Signatures) + len(in.PubKeys) + 64
	b := zap.NewBuilder(capEstimate)

	sigsOff, sigsCount := writeByteList(b, in.Signatures)
	pubKeysOff, pubKeysCount := writeByteList(b, in.PubKeys)

	ob := b.StartObject(SizeCredential)
	ob.SetUint8(OffsetCredential_SecurityLevel, in.SecurityLevel)
	ob.SetList(OffsetCredential_SignatureList, sigsOff, sigsCount)
	ob.SetList(OffsetCredential_PubKeyList, pubKeysOff, pubKeysCount)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(in.TypeKind, ShapeKindCredential, b.Finish())
}

// writeByteList writes a stride-1 byte list and returns (offset, length).
func writeByteList(b *zap.Builder, data []byte) (offset, length int) {
	if len(data) == 0 {
		return 0, 0
	}
	lb := b.StartList(1)
	for _, byteVal := range data {
		lb.AddUint8(byteVal)
	}
	off, _ := lb.Finish()
	return off, len(data)
}
