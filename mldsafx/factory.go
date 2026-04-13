// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsafx

import (
	"github.com/luxfi/vm/fx"
)

const Name = "mldsafx"

var _ fx.Factory = (*Factory)(nil)

type Factory struct{}

func (*Factory) New() any {
	return &Fx{}
}
