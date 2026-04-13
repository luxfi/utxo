// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsafx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInputVerify(t *testing.T) {
	require := require.New(t)

	in := &Input{
		SigIndices: []uint32{0, 1, 2},
	}
	require.NoError(in.Verify())
}

func TestInputVerifyNil(t *testing.T) {
	var in *Input
	require.ErrorIs(t, in.Verify(), ErrNilInput)
}

func TestInputVerifyUnsorted(t *testing.T) {
	in := &Input{
		SigIndices: []uint32{2, 0, 1},
	}
	require.ErrorIs(t, in.Verify(), ErrInputIndicesNotSortedUnique)
}

func TestInputVerifyDuplicate(t *testing.T) {
	in := &Input{
		SigIndices: []uint32{0, 0, 1},
	}
	require.ErrorIs(t, in.Verify(), ErrInputIndicesNotSortedUnique)
}

func TestInputCost(t *testing.T) {
	require := require.New(t)

	in := &Input{
		SigIndices: []uint32{0, 1},
	}
	cost, err := in.Cost()
	require.NoError(err)
	require.Equal(uint64(44000), cost) // 2 * 22000
}

func TestTransferInputVerify(t *testing.T) {
	require := require.New(t)

	in := &TransferInput{
		Amt: 100,
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	require.NoError(in.Verify())
}

func TestTransferInputVerifyNoValue(t *testing.T) {
	in := &TransferInput{
		Amt: 0,
		Input: Input{
			SigIndices: []uint32{0},
		},
	}
	require.ErrorIs(t, in.Verify(), ErrNoValueInput)
}

func TestTransferInputVerifyNil(t *testing.T) {
	var in *TransferInput
	require.ErrorIs(t, in.Verify(), ErrNilInput)
}

func TestTransferInputAmount(t *testing.T) {
	in := &TransferInput{Amt: 42}
	require.Equal(t, uint64(42), in.Amount())
}
