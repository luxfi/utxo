// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1fx

import (
	log "github.com/luxfi/log"
	"github.com/luxfi/timer/mockable"
)

// VM that this Fx must be run by. ZAP-native: no runtime codec
// registration — wire schemas are compile-time static.
type VM interface {
	Clock() *mockable.Clock
	Logger() log.Logger
}

var _ VM = (*TestVM)(nil)

// TestVM is a minimal implementation of a VM
type TestVM struct {
	Clk mockable.Clock
	Log log.Logger
}

func (vm *TestVM) Clock() *mockable.Clock {
	return &vm.Clk
}

func (vm *TestVM) Logger() log.Logger {
	return vm.Log
}
