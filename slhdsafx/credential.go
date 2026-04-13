// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package slhdsafx provides SLH-DSA (FIPS 205) hash-based post-quantum
// credentials for high-assurance UTXO spending on X-Chain.
//
// SLH-DSA is a stateless hash-based signature scheme that provides
// security against both classical and quantum computer attacks.
// Hash-based signatures have the strongest security assumptions of any PQ scheme.
//
// This package supports six parameter sets across three security levels:
//   - SHA2-128f / SHAKE-128f: 128-bit security, fast signing
//   - SHA2-192f / SHAKE-192f: 192-bit security, balanced (default)
//   - SHA2-256f / SHAKE-256f: 256-bit security, highest security
//
// "f" (fast) variants are used over "s" (small) because UTXO spending
// prioritizes signing latency over signature size.
package slhdsafx

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/formatting"
)

// Signature and public key sizes from FIPS 205 specification.
const (
	// SHA2-128f (NIST Level 1, fast)
	SLH128fPubKeyLen = 32
	SLH128fSigLen    = 17088

	// SHA2-192f (NIST Level 3, fast) - DEFAULT
	SLH192fPubKeyLen = 48
	SLH192fSigLen    = 35664

	// SHA2-256f (NIST Level 5, fast)
	SLH256fPubKeyLen = 64
	SLH256fSigLen    = 49856
)

var (
	ErrNilCredential      = errors.New("nil SLH-DSA credential")
	ErrEmptyCredential    = errors.New("empty SLH-DSA credential")
	ErrInvalidSignature   = errors.New("invalid SLH-DSA signature")
	ErrInvalidSecLevel    = errors.New("invalid SLH-DSA security level")
	ErrSignatureTooShort  = errors.New("SLH-DSA signature too short")
	ErrMismatchedSecLevel = errors.New("signature length doesn't match security level")
)

// SecurityLevel indicates the SLH-DSA parameter set
type SecurityLevel uint8

const (
	// SecLevelSLH128f is 128-bit security with fast signing
	SecLevelSLH128f SecurityLevel = iota
	// SecLevelSLH192f is 192-bit security with fast signing (recommended default)
	SecLevelSLH192f
	// SecLevelSLH256f is 256-bit security with fast signing
	SecLevelSLH256f
)

// SignatureLen returns the signature length for this security level
func (s SecurityLevel) SignatureLen() int {
	switch s {
	case SecLevelSLH128f:
		return SLH128fSigLen
	case SecLevelSLH192f:
		return SLH192fSigLen
	case SecLevelSLH256f:
		return SLH256fSigLen
	default:
		return 0
	}
}

// PubKeyLen returns the public key length for this security level
func (s SecurityLevel) PubKeyLen() int {
	switch s {
	case SecLevelSLH128f:
		return SLH128fPubKeyLen
	case SecLevelSLH192f:
		return SLH192fPubKeyLen
	case SecLevelSLH256f:
		return SLH256fPubKeyLen
	default:
		return 0
	}
}

// slhdsaMode converts SecurityLevel to slhdsa.Mode
func (s SecurityLevel) slhdsaMode() slhdsa.Mode {
	switch s {
	case SecLevelSLH128f:
		return slhdsa.SHA2_128f
	case SecLevelSLH192f:
		return slhdsa.SHA2_192f
	case SecLevelSLH256f:
		return slhdsa.SHA2_256f
	default:
		return slhdsa.SHA2_192f
	}
}

// String returns the human-readable name
func (s SecurityLevel) String() string {
	switch s {
	case SecLevelSLH128f:
		return "SLH-DSA-SHA2-128f"
	case SecLevelSLH192f:
		return "SLH-DSA-SHA2-192f"
	case SecLevelSLH256f:
		return "SLH-DSA-SHA2-256f"
	default:
		return "unknown"
	}
}

// Credential contains SLH-DSA signatures for spending UTXOs.
type Credential struct {
	// Level indicates the SLH-DSA parameter set
	Level SecurityLevel `serialize:"true" json:"securityLevel"`
	// Sigs contains the SLH-DSA signatures (variable length based on Level)
	Sigs [][]byte `serialize:"true" json:"signatures"`
}

// Verify validates the credential structure (not cryptographic validity).
func (cr *Credential) Verify() error {
	if cr == nil {
		return ErrNilCredential
	}
	if len(cr.Sigs) == 0 {
		return ErrEmptyCredential
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

	switch raw.SecurityLevel {
	case "SLH-DSA-SHA2-128f", "128f":
		cr.Level = SecLevelSLH128f
	case "SLH-DSA-SHA2-192f", "192f":
		cr.Level = SecLevelSLH192f
	case "SLH-DSA-SHA2-256f", "256f":
		cr.Level = SecLevelSLH256f
	default:
		return fmt.Errorf("%w: %s", ErrInvalidSecLevel, raw.SecurityLevel)
	}

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

// NewCredential creates a new SLH-DSA credential at the specified security level
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

// NewCredential192f creates a credential using the recommended SLH-DSA-SHA2-192f level
func NewCredential192f(sigs [][]byte) (*Credential, error) {
	return NewCredential(SecLevelSLH192f, sigs)
}
