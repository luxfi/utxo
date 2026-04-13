// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package secp256r1fx provides P-256 (NIST secp256r1) ECDSA credentials
// for UTXO spending on X-Chain.
//
// P-256 is the curve used by Apple Secure Enclave, WebAuthn/FIDO2,
// Android Keystore, TPM 2.0, and most hardware security modules.
//
// Fixed sizes:
//   - Public key: 64 bytes (uncompressed X||Y, no 0x04 prefix)
//   - Signature: 64 bytes (R||S, each 32 bytes big-endian zero-padded)
//
// Like Ed25519, P-256 ECDSA cannot recover the public key from the
// signature alone (unlike secp256k1 which has recovery). So the
// credential carries pubkeys alongside signatures.
package secp256r1fx

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luxfi/formatting"
)

const (
	// PubKeyLen is the uncompressed P-256 public key size (X||Y, 32+32 bytes)
	PubKeyLen = 64
	// SigLen is the P-256 ECDSA signature size (R||S, 32+32 bytes)
	SigLen = 64
)

var (
	ErrNilCredential    = errors.New("nil P-256 credential")
	ErrEmptyCredential  = errors.New("empty P-256 credential")
	ErrInvalidSignature = errors.New("invalid P-256 signature")
)

// Credential contains P-256 ECDSA signatures for spending UTXOs.
// PubKeys must be provided because P-256 ECDSA cannot recover the
// public key from the signature.
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
