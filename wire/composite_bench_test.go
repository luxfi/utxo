// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire_test

import (
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/utxo/secp256k1fx"
	"github.com/luxfi/utxo/wire"
)

// BenchmarkComposite_XVMBaseTx measures the full X-chain money-move wire
// composition (2 outs + 2 ins, secp256k1fx inner envelopes + Transferable
// envelopes + XVMBaseTx envelope) — the exact per-tx build work xvm's
// serializeUnsigned performs. This is the pooled-builder + SetBytesFixed +
// zero-copy-SetBytes hot path.
func BenchmarkComposite_XVMBaseTx(b *testing.B) {
	assetID := ids.ID{0x51, 0xc2, 0x4f, 0xe7}
	txID := ids.ID{0xaa, 0xbb}
	addr := ids.ShortID{0x01, 0x02, 0x03}
	out := &secp256k1fx.TransferOutput{
		Amt: 1_000_000,
		OutputOwners: secp256k1fx.OutputOwners{
			Threshold: 1,
			Addrs:     []ids.ShortID{addr},
		},
	}
	in := &secp256k1fx.TransferInput{
		Amt:   2_000_000,
		Input: secp256k1fx.Input{SigIndices: []uint32{0}},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outs := make([]wire.XVMTransferOut, 2)
		for j := range outs {
			outs[j] = wire.XVMTransferOut{AssetID: assetID, Output: out.Bytes()}
		}
		ins := make([]wire.XVMTransferIn, 2)
		for j := range ins {
			ins[j] = wire.XVMTransferIn{TxID: txID, OutputIndex: uint32(j), AssetID: assetID, Input: in.Bytes()}
		}
		env := wire.NewXVMBaseTx(wire.XVMBaseTxInput{
			NetworkID:    1,
			BlockchainID: [32]byte{0x01},
			Outs:         outs,
			Ins:          ins,
		})
		if len(env) == 0 {
			b.Fatal("empty")
		}
	}
}
