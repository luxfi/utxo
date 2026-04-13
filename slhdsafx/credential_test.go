// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsafx

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/crypto/slhdsa"
)

func TestCredentialVerify(t *testing.T) {
	require := require.New(t)

	sig := make([]byte, SLH192fSigLen)
	cred := &Credential{
		Level: SecLevelSLH192f,
		Sigs:  [][]byte{sig},
	}
	require.NoError(cred.Verify())
}

func TestCredentialVerifyNil(t *testing.T) {
	var cred *Credential
	require.ErrorIs(t, cred.Verify(), ErrNilCredential)
}

func TestCredentialVerifyWrongSigLen(t *testing.T) {
	sig := make([]byte, 100) // wrong length
	cred := &Credential{
		Level: SecLevelSLH192f,
		Sigs:  [][]byte{sig},
	}
	require.ErrorIs(t, cred.Verify(), ErrMismatchedSecLevel)
}

func TestCredentialVerifyBadSecLevel(t *testing.T) {
	cred := &Credential{
		Level: SecurityLevel(99),
		Sigs:  [][]byte{make([]byte, 100)},
	}
	require.ErrorIs(t, cred.Verify(), ErrInvalidSecLevel)
}

func TestCredentialVerifyMultipleSigs(t *testing.T) {
	require := require.New(t)

	sig1 := make([]byte, SLH192fSigLen)
	sig2 := make([]byte, SLH192fSigLen)
	cred := &Credential{
		Level: SecLevelSLH192f,
		Sigs:  [][]byte{sig1, sig2},
	}
	require.NoError(cred.Verify())
}

func TestCredentialVerifySLH128f(t *testing.T) {
	require := require.New(t)

	sig := make([]byte, SLH128fSigLen)
	cred := &Credential{
		Level: SecLevelSLH128f,
		Sigs:  [][]byte{sig},
	}
	require.NoError(cred.Verify())
}

func TestCredentialVerifySLH256f(t *testing.T) {
	require := require.New(t)

	sig := make([]byte, SLH256fSigLen)
	cred := &Credential{
		Level: SecLevelSLH256f,
		Sigs:  [][]byte{sig},
	}
	require.NoError(cred.Verify())
}

func TestNewCredential192f(t *testing.T) {
	require := require.New(t)

	sk, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_192f)
	require.NoError(err)

	msg := []byte("test")
	sig, err := sk.Sign(rand.Reader, msg, nil)
	require.NoError(err)

	cred, err := NewCredential192f([][]byte{sig})
	require.NoError(err)
	require.Equal(SecLevelSLH192f, cred.Level)
	require.Len(cred.Sigs, 1)
}

func TestCredentialJSON(t *testing.T) {
	require := require.New(t)

	sig := make([]byte, SLH192fSigLen)
	for i := range sig {
		sig[i] = byte(i % 256)
	}
	cred := &Credential{
		Level: SecLevelSLH192f,
		Sigs:  [][]byte{sig},
	}

	data, err := cred.MarshalJSON()
	require.NoError(err)

	var decoded Credential
	require.NoError(decoded.UnmarshalJSON(data))
	require.Equal(SecLevelSLH192f, decoded.Level)
	require.Len(decoded.Sigs, 1)
	require.Equal(sig, decoded.Sigs[0])
}
