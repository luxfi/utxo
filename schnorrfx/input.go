// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schnorrfx

import (
	"errors"

	"github.com/luxfi/math"
	"github.com/luxfi/utils"
)

const (
	// CostPerSignature is the compute cost per BIP-340 Schnorr verification.
	// BIP-340 verify is comparable to secp256k1 ECDSA verify, but slightly
	// faster because there's no recovery. Set to 1000 (same as Ed25519, same
	// order as secp256k1).
	CostPerSignature uint64 = 1000
)

var (
	ErrNilInput                    = errors.New("nil input")
	ErrInputIndicesNotSortedUnique = errors.New("address indices not sorted and unique")
)

// Input references signature indices into the credential for spending.
type Input struct {
	SigIndices []uint32 `serialize:"true" json:"signatureIndices"`
}

func (in *Input) Cost() (uint64, error) {
	numSigs := uint64(len(in.SigIndices))
	return math.Mul64(numSigs, CostPerSignature)
}

// Verify this input is syntactically valid
func (in *Input) Verify() error {
	switch {
	case in == nil:
		return ErrNilInput
	case !utils.IsSortedAndUniqueOrdered(in.SigIndices):
		return ErrInputIndicesNotSortedUnique
	default:
		return nil
	}
}
