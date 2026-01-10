// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1fx

import (
	"cmp"
	"slices"
)

func sortByCompare[T interface{ Compare(T) int }](s []T) {
	slices.SortFunc(s, func(a, b T) int {
		return a.Compare(b)
	})
}

func isSortedAndUniqueByCompare[T interface{ Compare(T) int }](s []T) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1].Compare(s[i]) >= 0 {
			return false
		}
	}
	return true
}

func isSortedAndUniqueOrdered[T cmp.Ordered](s []T) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}
