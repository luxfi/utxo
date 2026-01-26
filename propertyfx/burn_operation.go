// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package propertyfx

import (
	"github.com/luxfi/runtime"
	"github.com/luxfi/vm/components/verify"
	"github.com/luxfi/utxo/secp256k1fx"
)

type BurnOperation struct {
	secp256k1fx.Input `serialize:"true"`
}

func (*BurnOperation) InitRuntime(*runtime.Runtime) {}

// InitializeContext implements the fxs.FxOperation interface
func (*BurnOperation) InitializeRuntime(*runtime.Runtime) error {
	return nil
}

func (*BurnOperation) Outs() []verify.State {
	return nil
}
