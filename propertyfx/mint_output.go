// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package propertyfx

import (
	"github.com/luxfi/runtime"

	"github.com/luxfi/utxo/secp256k1fx"
	"github.com/luxfi/vm/components/verify"
)

var _ verify.State = (*MintOutput)(nil)

type MintOutput struct {
	verify.IsState `serialize:"-" json:"-"`

	secp256k1fx.OutputOwners `serialize:"true"`
}

func (out *MintOutput) InitRuntime(rt *runtime.Runtime) {
	out.OutputOwners.InitRuntime(rt)
}
