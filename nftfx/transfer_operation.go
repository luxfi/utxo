// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package nftfx

import (
	"errors"

	"github.com/luxfi/runtime"

	"github.com/luxfi/utxo/secp256k1fx"
	"github.com/luxfi/vm/components/verify"
)

var errNilTransferOperation = errors.New("nil transfer operation")

type TransferOperation struct {
	Input  secp256k1fx.Input `serialize:"true" json:"input"`
	Output TransferOutput    `serialize:"true" json:"output"`
}

func (op *TransferOperation) InitRuntime(rt *runtime.Runtime) {
	op.Output.OutputOwners.InitRuntime(rt)
}

func (op *TransferOperation) InitializeRuntime(rt *runtime.Runtime) error {
	op.InitRuntime(rt)
	return nil
}

func (op *TransferOperation) Cost() (uint64, error) {
	return op.Input.Cost()
}

func (op *TransferOperation) Outs() []verify.State {
	return []verify.State{&op.Output}
}

func (op *TransferOperation) Verify() error {
	if op == nil {
		return errNilTransferOperation
	}

	return verify.All(&op.Input, &op.Output)
}
