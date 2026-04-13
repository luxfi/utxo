// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schnorrfx

import (
	"github.com/luxfi/vm/components/verify"
)

var _ verify.State = (*MintOutput)(nil)

type MintOutput struct {
	verify.IsState `serialize:"-" json:"-"`

	OutputOwners `serialize:"true"`
}

func (out *MintOutput) Verify() error {
	if out == nil {
		return ErrNilOutput
	}
	return out.OutputOwners.Verify()
}
