// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package nftfx

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
		GroupID: 7,
		OutputOwners: secp256k1fx.OutputOwners{
			Locktime:  99,
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	gotMintOut, err := WrapMintOutput(mintOut.Bytes())
	require.NoError(err)
	require.Equal(mintOut.GroupID, gotMintOut.GroupID)
	require.Equal(mintOut.OutputOwners.Locktime, gotMintOut.OutputOwners.Locktime)
	require.Equal(mintOut.OutputOwners.Threshold, gotMintOut.OutputOwners.Threshold)
	require.Equal(mintOut.OutputOwners.Addrs, gotMintOut.OutputOwners.Addrs)

	xferOut := &TransferOutput{
		GroupID: 3,
		Payload: []byte("nft payload"),
		OutputOwners: secp256k1fx.OutputOwners{
			Locktime:  5,
			Threshold: 2,
			Addrs:     []ids.ShortID{addr, {0xaa}},
		},
	}
	gotXferOut, err := WrapTransferOutput(xferOut.Bytes())
	require.NoError(err)
	require.Equal(xferOut.GroupID, gotXferOut.GroupID)
	require.Equal([]byte(xferOut.Payload), []byte(gotXferOut.Payload))
	require.Equal(xferOut.OutputOwners.Addrs, gotXferOut.OutputOwners.Addrs)

	mintOp := &MintOperation{
		MintInput: secp256k1fx.Input{SigIndices: []uint32{0, 2}},
		GroupID:   9,
		Payload:   []byte("mint me"),
		Outputs: []*secp256k1fx.OutputOwners{
			{Locktime: 1, Threshold: 1, Addrs: []ids.ShortID{addr}},
			{Locktime: 2, Threshold: 1, Addrs: []ids.ShortID{{0xbb}}},
		},
	}
	gotMintOp, err := WrapMintOperation(mintOp.Bytes())
	require.NoError(err)
	require.Equal(mintOp.MintInput.SigIndices, gotMintOp.MintInput.SigIndices)
	require.Equal(mintOp.GroupID, gotMintOp.GroupID)
	require.Equal([]byte(mintOp.Payload), []byte(gotMintOp.Payload))
	require.Len(gotMintOp.Outputs, 2)
	require.Equal(mintOp.Outputs[0].Addrs, gotMintOp.Outputs[0].Addrs)
	require.Equal(mintOp.Outputs[1].Locktime, gotMintOp.Outputs[1].Locktime)

	xferOp := &TransferOperation{
		Input:  secp256k1fx.Input{SigIndices: []uint32{1}},
		Output: *xferOut,
	}
	gotXferOp, err := WrapTransferOperation(xferOp.Bytes())
	require.NoError(err)
	require.Equal(xferOp.Input.SigIndices, gotXferOp.Input.SigIndices)
	require.Equal(xferOp.Output.GroupID, gotXferOp.Output.GroupID)
	require.Equal([]byte(xferOp.Output.Payload), []byte(gotXferOp.Output.Payload))

	cred := &Credential{}
	cred.Sigs = [][65]byte{{0x11}, {0x22}}
	gotCred, err := WrapCredential(cred.Bytes())
	require.NoError(err)
	require.Equal(cred.Sigs, gotCred.Sigs)

	// cross-fx confusion: an nft envelope must not wrap as secp mint output.
	_, err = secp256k1fx.WrapMintOutput(mintOut.Bytes())
	require.ErrorIs(err, wire.ErrWrongShapeKind)
}
