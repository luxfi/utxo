// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1fx

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/vm/components/verify"
)

func TestTransferInputAmount(t *testing.T) {
	require := require.New(t)
	in := TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{0, 1},
		},
	}
	require.Equal(uint64(1), in.Amount())
}

func TestTransferInputVerify(t *testing.T) {
	require := require.New(t)
	in := TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{0, 1},
		},
	}
	require.NoError(in.Verify())
}

func TestTransferInputVerifyNil(t *testing.T) {
	require := require.New(t)
	in := (*TransferInput)(nil)
	err := in.Verify()
	require.ErrorIs(err, ErrNilInput)
}

func TestTransferInputVerifyNoValue(t *testing.T) {
	require := require.New(t)
	in := TransferInput{
		Amt: 0,
		Input: Input{
			SigIndices: []uint32{0, 1},
		},
	}
	err := in.Verify()
	require.ErrorIs(err, ErrNoValueInput)
}

func TestTransferInputVerifyDuplicated(t *testing.T) {
	require := require.New(t)
	in := TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{0, 0},
		},
	}
	err := in.Verify()
	require.ErrorIs(err, ErrInputIndicesNotSortedUnique)
}

func TestTransferInputVerifyUnsorted(t *testing.T) {
	require := require.New(t)
	in := TransferInput{
		Amt: 1,
		Input: Input{
			SigIndices: []uint32{1, 0},
		},
	}
	err := in.Verify()
	require.ErrorIs(err, ErrInputIndicesNotSortedUnique)
}

// Legacy linearcodec wire-format test deleted with the codec rip.
// ZAP-native wire round-trip is covered in wire_test.go.

func TestTransferInputNotState(t *testing.T) {
	require := require.New(t)
	intf := interface{}(&TransferInput{})
	_, ok := intf.(verify.State)
	require.False(ok)
}
