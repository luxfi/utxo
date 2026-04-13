// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsafx

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/formatting"
	"github.com/luxfi/ids"
)

var (
	ErrNilOutputOwners     = errors.New("nil SLH-DSA output owners")
	ErrNilPublicKey        = errors.New("nil SLH-DSA public key")
	ErrThresholdExceeded   = errors.New("threshold exceeds number of addresses")
	ErrOutputUnoptimized   = errors.New("output representation should be optimized")
	ErrOutputNotSpendable  = errors.New("output not yet spendable")
	ErrInvalidPubKeyLength = errors.New("invalid SLH-DSA public key length")
)

// OutputOwners describes who can spend an output locked with SLH-DSA keys.
type OutputOwners struct {
	// Level indicates the SLH-DSA parameter set for all addresses
	Level SecurityLevel `serialize:"true" json:"securityLevel"`
	// Locktime is the Unix timestamp after which this output can be spent
	Locktime uint64 `serialize:"true" json:"locktime"`
	// Threshold is the number of signatures required to spend
	Threshold uint32 `serialize:"true" json:"threshold"`
	// Addrs are the SLH-DSA public keys that can sign to spend
	Addrs [][]byte `serialize:"true" json:"addresses"`
}

// Verify validates the output owners structure
func (out *OutputOwners) Verify() error {
	if out == nil {
		return ErrNilOutputOwners
	}

	switch {
	case out.Threshold > uint32(len(out.Addrs)):
		return ErrThresholdExceeded
	case out.Threshold == 0 && len(out.Addrs) > 0:
		return ErrOutputUnoptimized
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

// Addresses returns short IDs derived from the SLH-DSA public keys.
// Public keys are hashed via SHA256+RIPEMD160 to produce 20-byte addresses.
func (out *OutputOwners) Addresses() []ids.ShortID {
	addrs := make([]ids.ShortID, len(out.Addrs))
	for i, pk := range out.Addrs {
		addrBytes := hash.PubkeyBytesToAddress(pk)
		addr, err := ids.ToShortID(addrBytes)
		if err != nil {
			panic(fmt.Sprintf("hash160 produced wrong length: %v", err))
		}
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

// Equals returns true if the provided owners create the same condition
func (out *OutputOwners) Equals(other *OutputOwners) bool {
	if out == other {
		return true
	}
	if out == nil || other == nil || out.Level != other.Level ||
		out.Locktime != other.Locktime || out.Threshold != other.Threshold ||
		len(out.Addrs) != len(other.Addrs) {
		return false
	}
	for i, addr := range out.Addrs {
		if string(addr) != string(other.Addrs[i]) {
			return false
		}
	}
	return true
}
