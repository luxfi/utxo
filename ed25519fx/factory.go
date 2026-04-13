// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519fx

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/fx"
)

const Name = "ed25519fx"

var (
	_ fx.Factory = (*Factory)(nil)

	// ID that this Fx uses when labeled
	ID = ids.ID{'e', 'd', '2', '5', '5', '1', '9', 'f', 'x'}
)

type Factory struct{}

func (*Factory) New() any {
	return &Fx{}
}
