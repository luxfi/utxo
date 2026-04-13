// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schnorrfx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCredentialVerify(t *testing.T) {
	require := require.New(t)
	cred := &Credential{
		Sigs:    [][SigLen]byte{{}},
		PubKeys: [][]byte{make([]byte, PubKeyLen)},
	}
	require.NoError(cred.Verify())
}

func TestCredentialVerifyNil(t *testing.T) {
	var cred *Credential
	require.ErrorIs(t, cred.Verify(), ErrNilCredential)
}

func TestCredentialVerifyEmpty(t *testing.T) {
	cred := &Credential{}
	require.ErrorIs(t, cred.Verify(), ErrEmptyCredential)
}

func TestCredentialJSON(t *testing.T) {
	require := require.New(t)
	var sig [SigLen]byte
	for i := range sig {
		sig[i] = byte(i)
	}
	pk := make([]byte, PubKeyLen)
	for i := range pk {
		pk[i] = byte(i + 1)
	}
	cred := &Credential{
		Sigs:    [][SigLen]byte{sig},
		PubKeys: [][]byte{pk},
	}
	data, err := cred.MarshalJSON()
	require.NoError(err)
	require.Contains(string(data), "signatures")
	require.Contains(string(data), "publicKeys")
}
