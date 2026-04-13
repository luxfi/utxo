// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package schnorrfx provides BIP-340 Schnorr credentials for UTXO spending on
// X-Chain. Used for Bitcoin Taproot-compatible signing.
//
// Fixed sizes (BIP-340):
//   - X-only public key: 32 bytes
//   - Signature: 64 bytes
//
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
package schnorrfx

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luxfi/formatting"
)

const (
	PubKeyLen = 32 // BIP-340 x-only pubkey
	SigLen    = 64 // BIP-340 Schnorr signature
)

var (
	ErrNilCredential    = errors.New("nil Schnorr credential")
	ErrEmptyCredential  = errors.New("empty Schnorr credential")
	ErrInvalidSignature = errors.New("invalid Schnorr signature")
	ErrWrongSigLen      = errors.New("Schnorr signature wrong length")
)

// Credential contains BIP-340 Schnorr signatures for spending UTXOs.
// BIP-340 verification requires the x-only public key, so the credential
// carries (sig, pubkey) pairs.
type Credential struct {
	Sigs    [][SigLen]byte `serialize:"true" json:"signatures"`
	PubKeys [][]byte       `serialize:"true" json:"publicKeys"`
}

// Verify validates the credential structure.
func (cr *Credential) Verify() error {
	if cr == nil {
		return ErrNilCredential
	}
	if len(cr.Sigs) == 0 {
		return ErrEmptyCredential
	}
	return nil
}

// MarshalJSON marshals the credential to JSON with hex-encoded signatures
func (cr *Credential) MarshalJSON() ([]byte, error) {
	sigs := make([]string, len(cr.Sigs))
	for i, sig := range cr.Sigs {
		sigStr, err := formatting.Encode(formatting.HexNC, sig[:])
		if err != nil {
			return nil, fmt.Errorf("couldn't encode signature %d: %w", i, err)
		}
		sigs[i] = sigStr
	}
	pks := make([]string, len(cr.PubKeys))
	for i, pk := range cr.PubKeys {
		pkStr, err := formatting.Encode(formatting.HexNC, pk)
		if err != nil {
			return nil, fmt.Errorf("couldn't encode pubkey %d: %w", i, err)
		}
		pks[i] = pkStr
	}
	return json.Marshal(map[string]interface{}{
		"signatures": sigs,
		"publicKeys": pks,
	})
}
