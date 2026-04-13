// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsafx

import (
	"errors"

	"github.com/luxfi/math"
	"github.com/luxfi/utils"
)

const (
	// CostPerSignature is the compute cost per ML-DSA signature verification.
	// Higher than secp256k1 due to larger signatures and lattice math.
	CostPerSignature uint64 = 3000
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
