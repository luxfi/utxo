// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519fx

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCredentialVerify(t *testing.T) {
	require := require.New(t)

	var sig [SigLen]byte
	cred := &Credential{
		Sigs: [][SigLen]byte{sig},
	}
	require.NoError(cred.Verify())
}

func TestCredentialVerifyNil(t *testing.T) {
	var cred *Credential
	require.ErrorIs(t, cred.Verify(), ErrNilCredential)
}

func TestCredentialVerifyMultipleSigs(t *testing.T) {
	require := require.New(t)

	var sig1, sig2 [SigLen]byte
	cred := &Credential{
		Sigs: [][SigLen]byte{sig1, sig2},
	}
	require.NoError(cred.Verify())
}

func TestCredentialWithPubKeys(t *testing.T) {
	require := require.New(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err)

	var sig [SigLen]byte
	cred := &Credential{
		Sigs:    [][SigLen]byte{sig},
		PubKeys: [][]byte{pub},
	}
	require.NoError(cred.Verify())
	require.Len(cred.PubKeys, 1)
	require.Equal(PubKeyLen, len(cred.PubKeys[0]))
}

// Regression: Finding 6 -- Empty Sigs slice must be rejected
func TestCredential_RejectEmptySigs(t *testing.T) {
	cred := &Credential{
		Sigs: [][SigLen]byte{},
	}
	require.ErrorIs(t, cred.Verify(), ErrEmptyCredential)
}
