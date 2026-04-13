// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schnorrfx

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/fx"
)

const Name = "schnorrfx"

var (
	_ fx.Factory = (*Factory)(nil)

	// ID that this Fx uses when labeled
	ID = ids.ID{'s', 'c', 'h', 'n', 'o', 'r', 'r', 'f', 'x'}
)

type Factory struct{}

func (*Factory) New() any {
	return &Fx{}
}
