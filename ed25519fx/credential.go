// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ed25519fx provides Ed25519 credentials for UTXO spending on X-Chain.
//
// Ed25519 is a high-performance EdDSA signature scheme over Curve25519.
// It is the native signature scheme for Solana, Cardano, NEAR, Polkadot,
// and many other ecosystems.
//
// Fixed sizes:
//   - Public key: 32 bytes
//   - Signature: 64 bytes
package ed25519fx

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luxfi/formatting"
)

const (
	PubKeyLen = ed25519.PublicKeySize // 32
	SigLen    = ed25519.SignatureSize // 64
)

var (
	ErrNilCredential    = errors.New("nil Ed25519 credential")
	ErrEmptyCredential  = errors.New("empty Ed25519 credential")
	ErrInvalidSignature = errors.New("invalid Ed25519 signature")
	ErrWrongSigLen      = errors.New("Ed25519 signature wrong length")
)

// Credential contains Ed25519 signatures for spending UTXOs.
// Unlike secp256k1, Ed25519 cannot recover the public key from a signature,
// so the credential must carry the public keys alongside the signatures.
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

	return json.Marshal(map[string]interface{}{
		"signatures": sigs,
	})
}
