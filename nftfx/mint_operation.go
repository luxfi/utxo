// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package nftfx

import (
	"errors"

	"github.com/luxfi/runtime"

	"github.com/luxfi/vm/components/verify"
	"github.com/luxfi/utxo/secp256k1fx"
	"github.com/luxfi/vm/types"
)

var errNilMintOperation = errors.New("nil mint operation")

type MintOperation struct {
	MintInput secp256k1fx.Input           `serialize:"true" json:"mintInput"`
	GroupID   uint32                      `serialize:"true" json:"groupID"`
	Payload   types.JSONByteSlice         `serialize:"true" json:"payload"`
	Outputs   []*secp256k1fx.OutputOwners `serialize:"true" json:"outputs"`
}

func (op *MintOperation) InitRuntime(rt *runtime.Runtime) {
	for _, out := range op.Outputs {
		out.InitRuntime(rt)
	}
}

func (op *MintOperation) InitializeRuntime(rt *runtime.Runtime) error {
	op.InitRuntime(rt)
	return nil
}

func (op *MintOperation) Cost() (uint64, error) {
	return op.MintInput.Cost()
}

// Outs Returns []TransferOutput as []verify.State
func (op *MintOperation) Outs() []verify.State {
	outs := []verify.State{}
	for _, out := range op.Outputs {
		outs = append(outs, &TransferOutput{
			GroupID:      op.GroupID,
			Payload:      op.Payload,
			OutputOwners: *out,
		})
	}
	return outs
}

func (op *MintOperation) Verify() error {
	switch {
	case op == nil:
		return errNilMintOperation
	case len(op.Payload) > MaxPayloadSize:
		return errPayloadTooLarge
	}

	for _, out := range op.Outputs {
		if err := out.Verify(); err != nil {
			return err
		}
	}
	return op.MintInput.Verify()
}
