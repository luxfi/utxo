// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package propertyfx

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/utxo/secp256k1fx"
	"github.com/luxfi/utxo/wire"
)

func TestWireRoundTrips(t *testing.T) {
	require := require.New(t)
	addr := ids.ShortID{0x01, 0x02, 0x03}

	mintOut := &MintOutput{
		OutputOwners: secp256k1fx.OutputOwners{
			Locktime:  11,
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	gotMintOut, err := WrapMintOutput(mintOut.Bytes())
	require.NoError(err)
	require.Equal(mintOut.OutputOwners.Locktime, gotMintOut.OutputOwners.Locktime)
	require.Equal(mintOut.OutputOwners.Addrs, gotMintOut.OutputOwners.Addrs)

	ownedOut := &OwnedOutput{
		OutputOwners: secp256k1fx.OutputOwners{
			Locktime:  22,
			Threshold: 1,
			Addrs:     []ids.ShortID{{0xcc}},
		},
	}
	gotOwnedOut, err := WrapOwnedOutput(ownedOut.Bytes())
	require.NoError(err)
	require.Equal(ownedOut.OutputOwners.Locktime, gotOwnedOut.OutputOwners.Locktime)
	require.Equal(ownedOut.OutputOwners.Addrs, gotOwnedOut.OutputOwners.Addrs)

	// mint authority vs state output must NOT cross-wrap (distinct shapes).
	_, err = WrapOwnedOutput(mintOut.Bytes())
	require.ErrorIs(err, wire.ErrWrongShapeKind)
	_, err = WrapMintOutput(ownedOut.Bytes())
	require.ErrorIs(err, wire.ErrWrongShapeKind)

	mintOp := &MintOperation{
		MintInput:   secp256k1fx.Input{SigIndices: []uint32{0}},
		MintOutput:  *mintOut,
		OwnedOutput: *ownedOut,
	}
	gotMintOp, err := WrapMintOperation(mintOp.Bytes())
	require.NoError(err)
	require.Equal(mintOp.MintInput.SigIndices, gotMintOp.MintInput.SigIndices)
	require.Equal(mintOp.MintOutput.OutputOwners.Locktime, gotMintOp.MintOutput.OutputOwners.Locktime)
	require.Equal(mintOp.OwnedOutput.OutputOwners.Addrs, gotMintOp.OwnedOutput.OutputOwners.Addrs)

	burnOp := &BurnOperation{Input: secp256k1fx.Input{SigIndices: []uint32{4, 5}}}
	gotBurnOp, err := WrapBurnOperation(burnOp.Bytes())
	require.NoError(err)
	require.Equal(burnOp.Input.SigIndices, gotBurnOp.Input.SigIndices)

	cred := &Credential{}
	cred.Sigs = [][65]byte{{0x33}}
	gotCred, err := WrapCredential(cred.Bytes())
	require.NoError(err)
	require.Equal(cred.Sigs, gotCred.Sigs)
}
