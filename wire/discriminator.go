// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package wire is the cross-VM ZAP-native wire format for the fxs
// (feature-extension) primitives shared by P-chain (platformvm) and
// X-chain (xvm). It replaces the legacy luxfi/codec.Manager registry
// with a (TypeKind, ShapeKind) discriminator pair on every primitive's
// wire envelope.
//
// Activation: 2025-12-25T16:20:00-08:00 (LP-023). New final Lux network.
// No backwards compatibility — legacy codec-encoded fxs primitives on the
// wire are a protocol-violation reject after activation.
//
// Wire envelope per primitive: [TypeKind:1][ShapeKind:1][ZAP message: N].
//
// The TypeKind byte names the fx family (secp256k1fx, mldsafx, ...) and
// the ShapeKind byte names the primitive shape within that family
// (TransferOutput, TransferInput, MintOutput, MintOperation, Credential,
// AttestationOutput, AttestationInput, OutputOwners). The remaining
// bytes are a ZAP message describing the shape's fields.
//
// This is decomposed from the legacy codec.Manager slot map (which
// braided "is this an Output? is this an Input? which fx?" into a
// single dense uint32 slot id). TypeKind + ShapeKind separates the two
// values cleanly — composition over inheritance.
package wire

import "errors"

// TypeKind names the fx family that owns the primitive. Dense values,
// 0x00 reserved (rejected by every Wrap*).
type TypeKind uint8

const (
	TypeKindReserved  TypeKind = 0x00
	TypeKindSecp256k1 TypeKind = 0x01
	TypeKindMLDSA     TypeKind = 0x02
	TypeKindSLHDSA    TypeKind = 0x03
	TypeKindEd25519   TypeKind = 0x04
	TypeKindSecp256r1 TypeKind = 0x05
	TypeKindSchnorr   TypeKind = 0x06
	TypeKindBLS12381  TypeKind = 0x07
	// Application fx families (built on secp256k1 credentials).
	TypeKindNFT      TypeKind = 0x08
	TypeKindProperty TypeKind = 0x09
)

// ShapeKind names the primitive shape within a fx family. Dense values,
// 0x00 reserved.
type ShapeKind uint8

const (
	ShapeKindReserved        ShapeKind = 0x00
	ShapeKindTransferOutput  ShapeKind = 0x01
	ShapeKindTransferInput   ShapeKind = 0x02
	ShapeKindMintOutput      ShapeKind = 0x03
	ShapeKindMintInput       ShapeKind = 0x04
	ShapeKindMintOperation   ShapeKind = 0x05
	ShapeKindCredential      ShapeKind = 0x06
	ShapeKindAttestationOut  ShapeKind = 0x07
	ShapeKindAttestationIn   ShapeKind = 0x08
	ShapeKindOutputOwners    ShapeKind = 0x09
	ShapeKindUTXO            ShapeKind = 0x0A
	ShapeKindTransferableOut ShapeKind = 0x0B
	ShapeKindTransferableIn  ShapeKind = 0x0C
	ShapeKindPChainOwner     ShapeKind = 0x0D
	ShapeKindSignedTx        ShapeKind = 0x0E
	ShapeKindLockedOutput    ShapeKind = 0x0F
	// NFT fx shapes (GroupID/Payload composites over OutputOwners).
	ShapeKindNFTMintOutput     ShapeKind = 0x10
	ShapeKindNFTTransferOutput ShapeKind = 0x11
	ShapeKindXVMBaseTx         ShapeKind = 0x12
	ShapeKindNFTMintOperation  ShapeKind = 0x13
	ShapeKindNFTTransferOp     ShapeKind = 0x14
	// Property fx shapes.
	ShapeKindOwnedOutput   ShapeKind = 0x15
	ShapeKindBurnOperation ShapeKind = 0x16
)

// Errors returned by every Wrap*Primitive accessor when the discriminator
// pair on the wire does not match the expected (TypeKind, ShapeKind) for
// the function being called. This closes the cross-type confusion surface
// where a TransferInput buffer could be Wrap'd as a TransferOutput and
// return garbage-but-deterministic field reads.
var (
	ErrWrongTypeKind  = errors.New("wire: TypeKind discriminator does not match expected fx family")
	ErrWrongShapeKind = errors.New("wire: ShapeKind discriminator does not match expected primitive shape")
	ErrShortEnvelope  = errors.New("wire: envelope shorter than 2-byte discriminator prefix")
	// ErrTrailingBytes is returned when an envelope carries bytes beyond the
	// self-delimiting ZAP message. zap.Parse truncates to the header size
	// field, so a buffer with a trailing tail would wrap the same message
	// but hash to a different id — a malleability vector. Canonical
	// envelopes MUST consume every byte; mirrors the proven node-side
	// block/blockwire.go ErrExtraSpace (msg.Size() != len(bytes)).
	ErrTrailingBytes = errors.New("wire: trailing bytes after zap message (non-canonical envelope)")
)

// EnvelopePrefix is the 2-byte discriminator prefix that every fxs
// primitive's wire envelope begins with. The remainder of the envelope
// is a ZAP message describing the shape's fields.
const EnvelopePrefix = 2

// readEnvelopePrefix parses the (TypeKind, ShapeKind) prefix from a wire
// buffer and returns the post-prefix ZAP slice. Returns ErrShortEnvelope
// when the buffer is shorter than 2 bytes.
func readEnvelopePrefix(b []byte) (TypeKind, ShapeKind, []byte, error) {
	if len(b) < EnvelopePrefix {
		return 0, 0, nil, ErrShortEnvelope
	}
	return TypeKind(b[0]), ShapeKind(b[1]), b[EnvelopePrefix:], nil
}

// PeekDiscriminator returns the (TypeKind, ShapeKind) of a wire envelope
// without consuming the ZAP body. Used by composite-shape dispatchers
// (e.g. LockedOutput) that need to recurse on an inner envelope's
// discriminator without committing to a Wrap*. Returns ErrShortEnvelope
// when the buffer is shorter than the 2-byte prefix.
func PeekDiscriminator(b []byte) (TypeKind, ShapeKind, error) {
	tk, sk, _, err := readEnvelopePrefix(b)
	return tk, sk, err
}

// NextEnvelope splits the first self-describing wire envelope off a packed
// sequence of concatenated envelopes and returns (envelope, rest). The
// envelope length is EnvelopePrefix + the inner ZAP message size (the
// little-endian uint32 at ZAP-header offset 12..16, which counts the full
// message including its header). This is the ONE walker for every packed
// envelope list (SignedTx credentials, XVMBaseTx outs/ins, nft mint owners).
func NextEnvelope(blob []byte) (env, rest []byte, err error) {
	if EnvelopePrefix > len(blob) {
		return nil, nil, ErrShortEnvelope
	}
	zapStart := EnvelopePrefix
	if zapStart+16 > len(blob) { // 16 = ZAP header size
		return nil, nil, ErrShortEnvelope
	}
	zapSize := int(blob[zapStart+12]) |
		int(blob[zapStart+13])<<8 |
		int(blob[zapStart+14])<<16 |
		int(blob[zapStart+15])<<24
	envEnd := zapStart + zapSize
	if zapSize < 16 || envEnd > len(blob) {
		return nil, nil, ErrShortEnvelope
	}
	return blob[:envEnd], blob[envEnd:], nil
}

// writeEnvelopePrefix prepends a (TypeKind, ShapeKind) discriminator to a
// ZAP message and returns the concatenated wire envelope.
//
// Allocates a single fresh buffer of size 2 + len(zapBytes). Callers
// that hold the ZAP bytes by reference must not retain ownership of the
// input slice — the returned slice is the canonical wire envelope.
func writeEnvelopePrefix(tk TypeKind, sk ShapeKind, zapBytes []byte) []byte {
	out := make([]byte, EnvelopePrefix+len(zapBytes))
	out[0] = byte(tk)
	out[1] = byte(sk)
	copy(out[EnvelopePrefix:], zapBytes)
	return out
}
