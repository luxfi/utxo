// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import "github.com/luxfi/zap"

// SignedTx is the ZAP-native replacement for the legacy
// `txs.Tx{Unsigned UnsignedTx; Creds []verify.Verifiable}` envelope used
// by both platformvm and xvm. It wraps:
//   - UnsignedBytes: the canonical wire bytes the signature was computed over
//   - Credentials:   a list of fxs Credential wire envelopes (one per input)
//
// The unsigned bytes already carry a TxKind discriminator at offset 0
// (see vms/platformvm/txs/zap_native/kind.go). The Credentials list
// indices align with the UnsignedTx's input list indices (1:1 by index)
// just like the legacy Tx.Creds slice.
//
// Fixed-section layout (size 16 bytes):
//
//	UnsignedBytes  bytes @ 0   (8 bytes — relOffset + length)
//	Credentials    list  @ 8   (8 bytes — relOffset + length; stride is
//	                            the per-credential ENVELOPE size, variable)
//
// Wire prefix: TypeKind=0x00 (reserved/cross-VM envelope),
// ShapeKind=0x0E (SignedTx).
//
// Because credentials are variable-stride byte envelopes (each carries
// its own TypeKind+ShapeKind+ZAP message of independent length), the
// credential list is encoded as a packed sequence of length-prefixed
// envelopes rather than a fixed-stride ZAP list. See
// SignedTx.CredentialAt for the parser.
const (
	OffsetSignedTx_UnsignedBytes   = 0  // bytes (8 bytes)
	OffsetSignedTx_CredentialCount = 8  // uint32 (number of credentials)
	OffsetSignedTx_CredentialBytes = 12 // bytes (8 bytes — all credential envelopes concatenated)
	SizeSignedTx                   = 20
)

// SignedTx is the zero-copy typed accessor.
type SignedTx struct {
	msg *zap.Message
	obj zap.Object
}

// UnsignedBytes returns the unsigned tx bytes. This is the canonical
// signing target — every fxs signature was computed over a hash of
// these bytes.
//
// READ-ONLY: aliases the underlying buffer. Use append([]byte(nil), ...)
// to take ownership.
func (s SignedTx) UnsignedBytes() []byte {
	return s.obj.Bytes(OffsetSignedTx_UnsignedBytes)
}

// CredentialCount returns the number of credentials.
func (s SignedTx) CredentialCount() uint32 {
	return s.obj.Uint32(OffsetSignedTx_CredentialCount)
}

// CredentialBytes returns the concatenated credential envelopes blob.
// Each credential is a self-describing wire envelope (2-byte prefix +
// length-prefixed ZAP message); see CredentialAt for the index walk.
func (s SignedTx) CredentialBytes() []byte {
	return s.obj.Bytes(OffsetSignedTx_CredentialBytes)
}

// CredentialAt parses the i'th credential envelope from the concatenated
// blob and returns its typed accessor. Returns the zero Credential
// (IsZero=true) if i is out of range or the blob is malformed.
//
// Walking is O(i) because each ZAP credential carries its own length in
// the wire header. For a hot-loop verifier, prefetch all credentials
// once into a []Credential slice.
func (s SignedTx) CredentialAt(i uint32) (Credential, error) {
	count := s.CredentialCount()
	if i >= count {
		return Credential{}, ErrWrongShapeKind
	}
	blob := s.CredentialBytes()
	cursor := 0
	for k := uint32(0); k <= i; k++ {
		if cursor+EnvelopePrefix > len(blob) {
			return Credential{}, ErrShortEnvelope
		}
		// Peek the inner ZAP message length from its header. ZAP header
		// carries (Magic:4, Version:2, Flags:2, RootOffset:4, Size:4) =
		// 16 bytes; Size is the inner message byte count.
		zapStart := cursor + EnvelopePrefix
		if zapStart+zap.HeaderSize > len(blob) {
			return Credential{}, ErrShortEnvelope
		}
		// Size is at offset 12..16 within the ZAP header (little-endian
		// uint32).
		zapSize := int(blob[zapStart+12]) |
			int(blob[zapStart+13])<<8 |
			int(blob[zapStart+14])<<16 |
			int(blob[zapStart+15])<<24
		envEnd := zapStart + zapSize
		if envEnd > len(blob) {
			return Credential{}, ErrShortEnvelope
		}
		if k == i {
			return WrapCredential(blob[cursor:envEnd])
		}
		cursor = envEnd
	}
	return Credential{}, ErrWrongShapeKind
}

// AllCredentials parses every credential into a fresh slice. Use this
// when the caller needs to iterate all credentials (the executor's
// VerifyTransfer pass).
func (s SignedTx) AllCredentials() ([]Credential, error) {
	count := s.CredentialCount()
	out := make([]Credential, 0, count)
	blob := s.CredentialBytes()
	cursor := 0
	for k := uint32(0); k < count; k++ {
		if cursor+EnvelopePrefix > len(blob) {
			return nil, ErrShortEnvelope
		}
		zapStart := cursor + EnvelopePrefix
		if zapStart+zap.HeaderSize > len(blob) {
			return nil, ErrShortEnvelope
		}
		zapSize := int(blob[zapStart+12]) |
			int(blob[zapStart+13])<<8 |
			int(blob[zapStart+14])<<16 |
			int(blob[zapStart+15])<<24
		envEnd := zapStart + zapSize
		if envEnd > len(blob) {
			return nil, ErrShortEnvelope
		}
		c, err := WrapCredential(blob[cursor:envEnd])
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		cursor = envEnd
	}
	return out, nil
}

// IsZero reports whether the accessor wraps a parsed message.
func (s SignedTx) IsZero() bool { return s.msg == nil }

// WrapSignedTx parses a SignedTx wire envelope.
func WrapSignedTx(b []byte) (SignedTx, error) {
	_, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return SignedTx{}, err
	}
	if sk != ShapeKindSignedTx {
		return SignedTx{}, ErrWrongShapeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return SignedTx{}, err
	}
	return SignedTx{msg: msg, obj: msg.Root()}, nil
}

// SignedTxInput is the constructor input.
type SignedTxInput struct {
	UnsignedBytes []byte
	// Credentials is the slice of credential wire envelopes (each one
	// already prefixed with its own TypeKind+ShapeKind+ZAP message).
	// The constructor concatenates them — order is preserved and aligns
	// 1:1 with the unsigned tx's input list.
	Credentials [][]byte
}

// NewSignedTx builds a SignedTx wire envelope. The unsigned bytes are
// stored verbatim, and the credentials slice is concatenated into a
// single byte run — the per-credential ZAP header carries each
// envelope's length so the parser can walk them.
func NewSignedTx(in SignedTxInput) []byte {
	// Concatenate all credential envelopes.
	totalCredBytes := 0
	for _, c := range in.Credentials {
		totalCredBytes += len(c)
	}
	credBlob := make([]byte, 0, totalCredBytes)
	for _, c := range in.Credentials {
		credBlob = append(credBlob, c...)
	}

	capEstimate := zap.HeaderSize + SizeSignedTx + len(in.UnsignedBytes) + totalCredBytes + 64
	b := zap.NewBuilder(capEstimate)

	ob := b.StartObject(SizeSignedTx)
	ob.SetBytes(OffsetSignedTx_UnsignedBytes, in.UnsignedBytes)
	ob.SetUint32(OffsetSignedTx_CredentialCount, uint32(len(in.Credentials)))
	ob.SetBytes(OffsetSignedTx_CredentialBytes, credBlob)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(TypeKindReserved, ShapeKindSignedTx, b.Finish())
}
