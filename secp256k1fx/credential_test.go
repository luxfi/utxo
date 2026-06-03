// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1fx

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/vm/components/verify"
)

func TestCredentialVerify(t *testing.T) {
	cred := Credential{}
	require.NoError(t, cred.Verify())
}

func TestCredentialVerifyNil(t *testing.T) {
	cred := (*Credential)(nil)
	err := cred.Verify()
	require.ErrorIs(t, err, ErrNilCredential)
}

// Legacy linearcodec wire-format test deleted with the codec rip.
// ZAP-native wire round-trip is covered in wire_test.go.

func TestCredentialNotState(t *testing.T) {
	intf := interface{}(&Credential{})
	_, ok := intf.(verify.State)
	require.False(t, ok)
}
