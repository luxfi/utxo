// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256r1fx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

func TestCredentialWithPubKeys(t *testing.T) {
	require := require.New(t)

	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(err)

	pk := pubKeyBytes(&sk.PublicKey)

	var sig [SigLen]byte
	cred := &Credential{
		Sigs:    [][SigLen]byte{sig},
		PubKeys: [][]byte{pk},
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
