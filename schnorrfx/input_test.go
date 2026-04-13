// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schnorrfx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInputVerify(t *testing.T) {
	in := &Input{SigIndices: []uint32{0, 1, 2}}
	require.NoError(t, in.Verify())
}

func TestInputVerifyNil(t *testing.T) {
	var in *Input
	require.ErrorIs(t, in.Verify(), ErrNilInput)
}

func TestInputVerifyUnsorted(t *testing.T) {
	in := &Input{SigIndices: []uint32{1, 0}}
	require.ErrorIs(t, in.Verify(), ErrInputIndicesNotSortedUnique)
}

func TestInputVerifyDuplicate(t *testing.T) {
	in := &Input{SigIndices: []uint32{0, 0}}
	require.ErrorIs(t, in.Verify(), ErrInputIndicesNotSortedUnique)
}

func TestInputCost(t *testing.T) {
	require := require.New(t)
	in := &Input{SigIndices: []uint32{0, 1, 2}}
	cost, err := in.Cost()
	require.NoError(err)
	require.Equal(uint64(3*CostPerSignature), cost)
}
