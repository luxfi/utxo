// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package utxo

import (
	"errors"
	"sync"
)

// ParseUTXOFunc reconstructs a *UTXO from its ZAP wire envelope. The
// concrete implementation lives in luxfi/node (or any consumer that
// imports all the fx packages it needs to dispatch on the inner Output
// TypeKind+ShapeKind discriminator). The root utxo package can't
// import fx packages directly (cycle), so the consumer registers a
// factory at boot.
//
// ZAP wire bytes are the canonical input. No codec.Manager — the same
// bytes flow on the wire, on disk (via zapdb), and into the parser.
type ParseUTXOFunc func(wireBytes []byte) (*UTXO, error)

var (
	parseUTXOOnce sync.Once
	parseUTXO     ParseUTXOFunc

	// ErrParseUTXONotRegistered is returned by ParseUTXO before the
	// consumer has called RegisterParseUTXO. Each program (luxd, cli,
	// tests, etc.) must register exactly once at boot.
	ErrParseUTXONotRegistered = errors.New("utxo: ParseUTXO not registered — caller must invoke RegisterParseUTXO at boot")
)

// RegisterParseUTXO registers the fx-aware factory. Idempotent — only
// the first call wins; subsequent calls are no-ops. This matches the
// "register once at process boot" pattern and prevents accidental
// override at test time.
func RegisterParseUTXO(fn ParseUTXOFunc) {
	parseUTXOOnce.Do(func() {
		parseUTXO = fn
	})
}

// ParseUTXO reconstructs a *UTXO from its ZAP wire envelope using the
// registered factory. Returns ErrParseUTXONotRegistered if no factory
// has been registered.
func ParseUTXO(wireBytes []byte) (*UTXO, error) {
	if parseUTXO == nil {
		return nil, ErrParseUTXONotRegistered
	}
	return parseUTXO(wireBytes)
}
