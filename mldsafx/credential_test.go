// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsafx

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/crypto/mldsa"
)

func TestCredentialVerify(t *testing.T) {
	require := require.New(t)

	sig := make([]byte, MLDSA65SigLen)
	cred := &Credential{
		Level: SecLevelMLDSA65,
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
		Level: SecLevelMLDSA65,
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

	sig1 := make([]byte, MLDSA65SigLen)
	sig2 := make([]byte, MLDSA65SigLen)
	cred := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{sig1, sig2},
	}
	require.NoError(cred.Verify())
}

func TestCredentialVerifyMLDSA44(t *testing.T) {
	require := require.New(t)

	sig := make([]byte, MLDSA44SigLen)
	cred := &Credential{
		Level: SecLevelMLDSA44,
		Sigs:  [][]byte{sig},
	}
	require.NoError(cred.Verify())
}

func TestCredentialVerifyMLDSA87(t *testing.T) {
	require := require.New(t)

	sig := make([]byte, MLDSA87SigLen)
	cred := &Credential{
		Level: SecLevelMLDSA87,
		Sigs:  [][]byte{sig},
	}
	require.NoError(cred.Verify())
}

func TestNewCredential65(t *testing.T) {
	require := require.New(t)

	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(err)

	msg := []byte("test")
	sig, err := sk.Sign(rand.Reader, msg, nil)
	require.NoError(err)

	cred, err := NewCredential65([][]byte{sig})
	require.NoError(err)
	require.Equal(SecLevelMLDSA65, cred.Level)
	require.Len(cred.Sigs, 1)
}

func TestCredentialJSON(t *testing.T) {
	require := require.New(t)

	sig := make([]byte, MLDSA65SigLen)
	for i := range sig {
		sig[i] = byte(i % 256)
	}
	cred := &Credential{
		Level: SecLevelMLDSA65,
		Sigs:  [][]byte{sig},
	}

	data, err := cred.MarshalJSON()
	require.NoError(err)

	var decoded Credential
	require.NoError(decoded.UnmarshalJSON(data))
	require.Equal(SecLevelMLDSA65, decoded.Level)
	require.Len(decoded.Sigs, 1)
	require.Equal(sig, decoded.Sigs[0])
}
