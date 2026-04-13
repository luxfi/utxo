// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsafx

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/fx"
)

const Name = "slhdsafx"

var (
	_ fx.Factory = (*Factory)(nil)

	// ID that this Fx uses when labeled
	ID = ids.ID{'s', 'l', 'h', 'd', 's', 'a', 'f', 'x'}
)

type Factory struct{}

func (*Factory) New() any {
	return &Fx{}
}
