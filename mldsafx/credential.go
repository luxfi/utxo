// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mldsafx provides ML-DSA (Module-Lattice Digital Signature Algorithm)
// credentials for post-quantum secure UTXO spending on X-Chain.
//
// ML-DSA is a NIST FIPS 204 standardized signature scheme that provides
// security against both classical and quantum computer attacks.
//
// This package supports three security levels:
//   - ML-DSA-44: 128-bit security (NIST Level 2), smallest signatures
//   - ML-DSA-65: 192-bit security (NIST Level 3), balanced
//   - ML-DSA-87: 256-bit security (NIST Level 5), highest security
//
// Usage: This credential type is OPTIONAL for X-Chain UTXOs.
// Consensus rules allow both secp256k1fx and mldsafx credentials.
// Wallets choose which signature type to use. Nodes validate both.
package mldsafx

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luxfi/formatting"
	"github.com/luxfi/ids"
)

// Security level constants
const (
	// ML-DSA-44 (NIST Level 2, 128-bit security)
	MLDSA44PubKeyLen = 1312
	MLDSA44SigLen    = 2420

	// ML-DSA-65 (NIST Level 3, 192-bit security) - DEFAULT
	MLDSA65PubKeyLen = 1952
	MLDSA65SigLen    = 3309

	// ML-DSA-87 (NIST Level 5, 256-bit security)
	MLDSA87PubKeyLen = 2592
	MLDSA87SigLen    = 4627
)

// ID is the unique identifier for this Fx
var ID = ids.ID{'m', 'l', 'd', 's', 'a', 'f', 'x'}

var (
	ErrNilCredential      = errors.New("nil ML-DSA credential")
	ErrInvalidSignature   = errors.New("invalid ML-DSA signature")
	ErrInvalidSecLevel    = errors.New("invalid ML-DSA security level")
	ErrSignatureTooShort  = errors.New("ML-DSA signature too short")
	ErrMismatchedSecLevel = errors.New("signature length doesn't match security level")
)

// SecurityLevel indicates the ML-DSA parameter set
type SecurityLevel uint8

const (
	// SecLevelMLDSA44 is 128-bit security (smallest signatures)
	SecLevelMLDSA44 SecurityLevel = iota
	// SecLevelMLDSA65 is 192-bit security (recommended default)
	SecLevelMLDSA65
	// SecLevelMLDSA87 is 256-bit security (highest security)
	SecLevelMLDSA87
)

// SignatureLen returns the signature length for this security level
func (s SecurityLevel) SignatureLen() int {
	switch s {
	case SecLevelMLDSA44:
		return MLDSA44SigLen
	case SecLevelMLDSA65:
		return MLDSA65SigLen
	case SecLevelMLDSA87:
		return MLDSA87SigLen
	default:
		return 0
	}
}

// PubKeyLen returns the public key length for this security level
func (s SecurityLevel) PubKeyLen() int {
	switch s {
	case SecLevelMLDSA44:
		return MLDSA44PubKeyLen
	case SecLevelMLDSA65:
		return MLDSA65PubKeyLen
	case SecLevelMLDSA87:
		return MLDSA87PubKeyLen
	default:
		return 0
	}
}

// String returns the human-readable name
func (s SecurityLevel) String() string {
	switch s {
	case SecLevelMLDSA44:
		return "ML-DSA-44"
	case SecLevelMLDSA65:
		return "ML-DSA-65"
	case SecLevelMLDSA87:
		return "ML-DSA-87"
	default:
		return "unknown"
	}
}

// Credential contains ML-DSA signatures for spending UTXOs.
// This is an OPTIONAL credential type - both secp256k1fx and mldsafx
// are valid for spending X-Chain UTXOs.
//
// Wire format:
//   - SecurityLevel: 1 byte (0=44, 1=65, 2=87)
//   - NumSigs: varint
//   - Sigs: [][]byte (variable length based on security level)
type Credential struct {
	// Level indicates the ML-DSA parameter set (44, 65, or 87)
	Level SecurityLevel `serialize:"true" json:"securityLevel"`
	// Sigs contains the ML-DSA signatures
	// Length depends on Level: 2420 (44), 3309 (65), or 4627 (87) bytes each
	Sigs [][]byte `serialize:"true" json:"signatures"`
}

// Verify validates the credential structure (not the cryptographic validity).
// Cryptographic verification is done separately by the verifier.
func (cr *Credential) Verify() error {
	if cr == nil {
		return ErrNilCredential
	}

	expectedLen := cr.Level.SignatureLen()
	if expectedLen == 0 {
		return ErrInvalidSecLevel
	}

	for i, sig := range cr.Sigs {
		if len(sig) != expectedLen {
			return fmt.Errorf("%w: signature %d has length %d, expected %d for %s",
				ErrMismatchedSecLevel, i, len(sig), expectedLen, cr.Level)
		}
	}

	return nil
}

// MarshalJSON marshals the credential to JSON with hex-encoded signatures
func (cr *Credential) MarshalJSON() ([]byte, error) {
	sigs := make([]string, len(cr.Sigs))
	for i, sig := range cr.Sigs {
		sigStr, err := formatting.Encode(formatting.HexNC, sig)
		if err != nil {
			return nil, fmt.Errorf("couldn't encode signature %d: %w", i, err)
		}
		sigs[i] = sigStr
	}

	return json.Marshal(map[string]interface{}{
		"securityLevel": cr.Level.String(),
		"signatures":    sigs,
	})
}

// UnmarshalJSON unmarshals JSON into the credential
func (cr *Credential) UnmarshalJSON(b []byte) error {
	var raw struct {
		SecurityLevel string   `json:"securityLevel"`
		Signatures    []string `json:"signatures"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	// Parse security level
	switch raw.SecurityLevel {
	case "ML-DSA-44", "44":
		cr.Level = SecLevelMLDSA44
	case "ML-DSA-65", "65":
		cr.Level = SecLevelMLDSA65
	case "ML-DSA-87", "87":
		cr.Level = SecLevelMLDSA87
	default:
		return fmt.Errorf("%w: %s", ErrInvalidSecLevel, raw.SecurityLevel)
	}

	// Decode signatures
	cr.Sigs = make([][]byte, len(raw.Signatures))
	for i, sigStr := range raw.Signatures {
		sig, err := formatting.Decode(formatting.HexNC, sigStr)
		if err != nil {
			return fmt.Errorf("couldn't decode signature %d: %w", i, err)
		}
		cr.Sigs[i] = sig
	}

	return nil
}

// NewCredential creates a new ML-DSA credential at the specified security level
func NewCredential(level SecurityLevel, sigs [][]byte) (*Credential, error) {
	cr := &Credential{
		Level: level,
		Sigs:  sigs,
	}
	if err := cr.Verify(); err != nil {
		return nil, err
	}
	return cr, nil
}

// NewCredential65 creates a credential using the recommended ML-DSA-65 level
func NewCredential65(sigs [][]byte) (*Credential, error) {
	return NewCredential(SecLevelMLDSA65, sigs)
}
