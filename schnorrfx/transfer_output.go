// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schnorrfx

import (
	"errors"

	"github.com/luxfi/vm/components/verify"
)

var (
	_ verify.State = (*TransferOutput)(nil)

	ErrNoValueOutput = errors.New("output has no value")
)

type TransferOutput struct {
	verify.IsState `serialize:"-" json:"-"`

	Amt          uint64 `serialize:"true" json:"amount"`
	OutputOwners `serialize:"true"`
}

// Amount returns the quantity of the asset this output consumes
func (out *TransferOutput) Amount() uint64 {
	return out.Amt
}

func (out *TransferOutput) Verify() error {
	switch {
	case out == nil:
		return ErrNilOutput
	case out.Amt == 0:
		return ErrNoValueOutput
	default:
		return out.OutputOwners.Verify()
	}
}

func (out *TransferOutput) Owners() interface{} {
	return &out.OutputOwners
}

func (*TransferOutput) isState() {}
