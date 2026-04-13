// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256r1fx

import (
	"errors"

	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
	"github.com/luxfi/vm/components/verify"
)

var (
	ErrNilOutput            = errors.New("nil output")
	ErrOutputUnspendable    = errors.New("output is unspendable")
	ErrOutputUnoptimized    = errors.New("output representation should be optimized")
	ErrAddrsNotSortedUnique = errors.New("addresses not sorted and unique")
)

// OutputOwners describes who can spend an output locked with P-256 keys.
// Addrs are 20-byte short IDs derived from the 64-byte P-256 public keys
// via hash.PubkeyBytesToAddress.
type OutputOwners struct {
	verify.IsNotState `serialize:"-" json:"-"`

	Locktime  uint64        `serialize:"true" json:"locktime"`
	Threshold uint32        `serialize:"true" json:"threshold"`
	Addrs     []ids.ShortID `serialize:"true" json:"addresses"`
}

func (out *OutputOwners) Verify() error {
	switch {
	case out == nil:
		return ErrNilOutput
	case out.Threshold > uint32(len(out.Addrs)):
		return ErrOutputUnspendable
	case out.Threshold == 0 && len(out.Addrs) > 0:
		return ErrOutputUnoptimized
	case !isSortedAndUniqueShortIDs(out.Addrs):
		return ErrAddrsNotSortedUnique
	default:
		return nil
	}
}

// Addresses returns the addresses that manage this output
func (out *OutputOwners) Addresses() [][]byte {
	addrs := make([][]byte, len(out.Addrs))
	for i, addr := range out.Addrs {
		addrs[i] = addr.Bytes()
	}
	return addrs
}

// AddressesSet returns addresses as a set
func (out *OutputOwners) AddressesSet() set.Set[ids.ShortID] {
	return set.Of(out.Addrs...)
}

// Equals returns true if the provided owners create the same condition
func (out *OutputOwners) Equals(other *OutputOwners) bool {
	if out == other {
		return true
	}
	if out == nil || other == nil || out.Locktime != other.Locktime ||
		out.Threshold != other.Threshold || len(out.Addrs) != len(other.Addrs) {
		return false
	}
	for i, addr := range out.Addrs {
		if addr != other.Addrs[i] {
			return false
		}
	}
	return true
}

// Sort sorts the addresses lexicographically
func (out *OutputOwners) Sort() {
	sortShortIDs(out.Addrs)
}

func isSortedAndUniqueShortIDs(addrs []ids.ShortID) bool {
	for i := 1; i < len(addrs); i++ {
		if addrs[i-1].Compare(addrs[i]) >= 0 {
			return false
		}
	}
	return true
}

func sortShortIDs(addrs []ids.ShortID) {
	for i := 1; i < len(addrs); i++ {
		for j := i; j > 0 && addrs[j-1].Compare(addrs[j]) > 0; j-- {
			addrs[j-1], addrs[j] = addrs[j], addrs[j-1]
		}
	}
}
