// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsafx

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luxfi/formatting"
	"github.com/luxfi/ids"
)

var (
	ErrNilOutputOwners     = errors.New("nil ML-DSA output owners")
	ErrNilPublicKey        = errors.New("nil ML-DSA public key")
	ErrThresholdExceeded   = errors.New("threshold exceeds number of addresses")
	ErrOutputNotSpendable  = errors.New("output not yet spendable")
	ErrInvalidPubKeyLength = errors.New("invalid ML-DSA public key length")
)

// OutputOwners describes who can spend an output locked with ML-DSA keys.
// This is the post-quantum alternative to secp256k1fx.OutputOwners.
//
// Spending requires [Threshold] signatures from the [Addrs] public keys.
// All addresses are ML-DSA public keys (1312, 1952, or 2592 bytes depending on level).
type OutputOwners struct {
	// Level indicates the ML-DSA parameter set for all addresses
	Level SecurityLevel `serialize:"true" json:"securityLevel"`
	// Locktime is the Unix timestamp after which this output can be spent
	Locktime uint64 `serialize:"true" json:"locktime"`
	// Threshold is the number of signatures required to spend
	Threshold uint32 `serialize:"true" json:"threshold"`
	// Addrs are the ML-DSA public keys that can sign to spend
	// Must be sorted in lexicographic order
	Addrs [][]byte `serialize:"true" json:"addresses"`
}

// Verify validates the output owners structure
func (out *OutputOwners) Verify() error {
	if out == nil {
		return ErrNilOutputOwners
	}

	if out.Threshold > uint32(len(out.Addrs)) {
		return ErrThresholdExceeded
	}

	expectedPKLen := out.Level.PubKeyLen()
	if expectedPKLen == 0 {
		return ErrInvalidSecLevel
	}

	for i, addr := range out.Addrs {
		if len(addr) != expectedPKLen {
			return fmt.Errorf("%w: address %d has length %d, expected %d for %s",
				ErrInvalidPubKeyLength, i, len(addr), expectedPKLen, out.Level)
		}
	}

	// Verify sorted order
	for i := 1; i < len(out.Addrs); i++ {
		if string(out.Addrs[i-1]) >= string(out.Addrs[i]) {
			return fmt.Errorf("addresses not sorted at index %d", i)
		}
	}

	return nil
}

// Addresses returns short IDs derived from the ML-DSA public keys
func (out *OutputOwners) Addresses() []ids.ShortID {
	addrs := make([]ids.ShortID, len(out.Addrs))
	for i, pk := range out.Addrs {
		// Hash the public key to get a 20-byte address
		addr, _ := ids.ToShortID(pk)
		addrs[i] = addr
	}
	return addrs
}

// MarshalJSON marshals the output owners to JSON
func (out *OutputOwners) MarshalJSON() ([]byte, error) {
	addrs := make([]string, len(out.Addrs))
	for i, addr := range out.Addrs {
		addrStr, err := formatting.Encode(formatting.HexNC, addr)
		if err != nil {
			return nil, fmt.Errorf("couldn't encode address %d: %w", i, err)
		}
		addrs[i] = addrStr
	}

	return json.Marshal(map[string]interface{}{
		"securityLevel": out.Level.String(),
		"locktime":      out.Locktime,
		"threshold":     out.Threshold,
		"addresses":     addrs,
	})
}

// NewOutputOwners creates a new ML-DSA output owners
func NewOutputOwners(level SecurityLevel, locktime uint64, threshold uint32, addrs [][]byte) (*OutputOwners, error) {
	out := &OutputOwners{
		Level:     level,
		Locktime:  locktime,
		Threshold: threshold,
		Addrs:     addrs,
	}
	if err := out.Verify(); err != nil {
		return nil, err
	}
	return out, nil
}
