// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381fx

import (
	"errors"

	"github.com/luxfi/vm/components/verify"
)

const (
	// PubKeyLen is the compressed G1 public key size (BLS12-381).
	PubKeyLen = 48
	// SigLen is the compressed G2 aggregate signature size (BLS12-381).
	SigLen = 96
	// AttestedHashLen is the length of the commitment being attested to.
	AttestedHashLen = 32
)

var (
	ErrNilOutput               = errors.New("nil attestation output")
	ErrInvalidAttestedHash     = errors.New("attestation hash wrong length")
	ErrInvalidPubKeyLen        = errors.New("bls12381 pubkey wrong length")
	ErrEmptyPubKeys            = errors.New("attestation output must have >=1 pubkeys")
	ErrThresholdZero           = errors.New("attestation threshold must be >= 1")
	ErrThresholdExceedsPubKeys = errors.New("threshold exceeds number of pubkeys")
	ErrPubKeysNotSortedUnique  = errors.New("pubkeys not sorted and unique")

	ErrNilInput          = errors.New("nil attestation input")
	ErrSignerBitmapEmpty = errors.New("signer bitmap has no bits set")
	ErrSignerBitmapSize  = errors.New("signer bitmap size does not match pubkey count")

	ErrNilCredential    = errors.New("nil attestation credential")
	ErrWrongAggSigLen   = errors.New("aggregate signature wrong length")
	ErrInvalidAggSig    = errors.New("aggregate signature verification failed")
	ErrAggregatePubKeys = errors.New("failed to aggregate pubkeys")
)

// AttestationOutput records a quorum attestation to an arbitrary 32-byte
// commitment. It is write-only once created.
type AttestationOutput struct {
	verify.IsState `serialize:"-" json:"-"`

	// AttestedHash is the commitment being attested to (application-defined).
	AttestedHash [AttestedHashLen]byte `serialize:"true" json:"attestedHash"`
	// Threshold is the minimum number of pubkeys that must contribute to the
	// aggregate signature. Enforced at verification time against the signer
	// bitmap popcount.
	Threshold uint32 `serialize:"true" json:"threshold"`
	// PubKeys are the committee pubkeys, sorted lexicographically, each
	// exactly PubKeyLen bytes. Lexicographic order is consensus-enforced so
	// the codec output is deterministic.
	PubKeys [][]byte `serialize:"true" json:"pubKeys"`
}

func (out *AttestationOutput) Verify() error {
	if out == nil {
		return ErrNilOutput
	}
	switch {
	case len(out.PubKeys) == 0:
		return ErrEmptyPubKeys
	case out.Threshold == 0:
		return ErrThresholdZero
	case out.Threshold > uint32(len(out.PubKeys)):
		return ErrThresholdExceedsPubKeys
	}
	for i, pk := range out.PubKeys {
		if len(pk) != PubKeyLen {
			return ErrInvalidPubKeyLen
		}
		if i > 0 && !byteLess(out.PubKeys[i-1], pk) {
			return ErrPubKeysNotSortedUnique
		}
	}
	return nil
}

// AttestationInput references which pubkeys contributed to the aggregate.
// Bit i (little-endian) set in Signers means PubKeys[i] signed.
type AttestationInput struct {
	Signers []byte `serialize:"true" json:"signers"`
}

func (in *AttestationInput) Verify() error {
	if in == nil {
		return ErrNilInput
	}
	if len(in.Signers) == 0 {
		return ErrSignerBitmapEmpty
	}
	// Require at least one bit set.
	anySet := false
	for _, b := range in.Signers {
		if b != 0 {
			anySet = true
			break
		}
	}
	if !anySet {
		return ErrSignerBitmapEmpty
	}
	return nil
}

// Credential carries the single aggregate BLS signature.
type Credential struct {
	AggSig [SigLen]byte `serialize:"true" json:"aggregateSignature"`
}

func (cr *Credential) Verify() error {
	if cr == nil {
		return ErrNilCredential
	}
	return nil
}

// byteLess reports whether a < b lexicographically.
func byteLess(a, b []byte) bool {
	if len(a) < len(b) {
		return true
	}
	if len(a) > len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// popcountBitmap returns the total number of set bits in b.
func popcountBitmap(b []byte) uint32 {
	var n uint32
	for _, by := range b {
		n += popcount8(by)
	}
	return n
}

// popcount8 is the Brian Kernighan popcount.
func popcount8(b byte) uint32 {
	var n uint32
	for b != 0 {
		b &= b - 1
		n++
	}
	return n
}

// bitmapSetBits returns the indexes (ascending) whose bit is set in b.
// Bit 0 is the LSB of b[0], bit 8 is the LSB of b[1], etc. — the
// little-endian-per-byte convention.
func bitmapSetBits(b []byte, maxBits int) []int {
	out := make([]int, 0, popcountBitmap(b))
	for i := 0; i < maxBits; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		if byteIdx >= len(b) {
			break
		}
		if b[byteIdx]&(1<<uint(bitIdx)) != 0 {
			out = append(out, i)
		}
	}
	return out
}
