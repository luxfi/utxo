// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package wire is the cross-VM ZAP-native wire format for the fxs
// (feature-extension) primitives and UTXO envelopes shared across
// every Lux VM (P-chain platformvm, X-chain xvm, EVM atomic-import).
//
// As of LP-023, the UTXO, TransferableOutput, and TransferableInput
// shapes are generated from the canonical schema at
// github.com/luxfi/proto/schemas/utxo/utxo.zap (relative path:
// ../../proto/schemas/utxo/utxo.zap from this package). Hand-rolled
// accessor files (utxo.go, transferable_*.go) are being phased out in
// favor of the generated *_zap.go output.
//
// Regenerate the *_zap.go files after editing the schema:
//
//	go generate ./...
//
// See proto/schemas/README.md for the schema-layout convention.
package wire

//go:generate zapgen ../../proto/schemas/utxo/utxo.zap
