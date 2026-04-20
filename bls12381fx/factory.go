// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381fx

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/fx"
)

const Name = "bls12381fx"

var (
	_ fx.Factory = (*Factory)(nil)

	// ID that this Fx uses when labeled
	ID = ids.ID{'b', 'l', 's', '1', '2', '3', '8', '1', 'f', 'x'}
)

type Factory struct{}

func (*Factory) New() any {
	return &Fx{}
}
