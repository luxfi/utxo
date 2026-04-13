// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256r1fx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	"github.com/luxfi/keychain"
	"github.com/luxfi/math/set"
	"github.com/luxfi/vm/components/verify"
)

var (
	errCantSpend = errors.New("unable to spend this UTXO")

	_ keychain.Signer   = (*p256Signer)(nil)
	_ keychain.Keychain = (*Keychain)(nil)
)

// pubKeyBytes returns the uncompressed P-256 public key as 64 bytes (X||Y)
func pubKeyBytes(pk *ecdsa.PublicKey) []byte {
	xBytes := pk.X.Bytes()
	yBytes := pk.Y.Bytes()
	buf := make([]byte, PubKeyLen)
	copy(buf[32-len(xBytes):32], xBytes)
	copy(buf[64-len(yBytes):64], yBytes)
	return buf
}

// signP256 signs a message with P-256 ECDSA and returns R||S (64 bytes)
func signP256(sk *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	digest := hash.ComputeHash256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, sk, digest)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, SigLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig, nil
}

// p256Signer wraps a P-256 private key to implement keychain.Signer
type p256Signer struct {
	key *ecdsa.PrivateKey
}

func (s *p256Signer) SignHash(h []byte) ([]byte, error) {
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, h)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, SigLen)
	rBytes := r.Bytes()
	sBytes := ss.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig, nil
}

func (s *p256Signer) Sign(msg []byte) ([]byte, error) {
	return signP256(s.key, msg)
}

func (s *p256Signer) Address() ids.ShortID {
	pkBytes := pubKeyBytes(&s.key.PublicKey)
	addressBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, _ := ids.ToShortID(addressBytes)
	return addr
}

// Keychain is a collection of P-256 keys that can be used to spend outputs
type Keychain struct {
	addrToKeyIndex map[ids.ShortID]int

	Addrs set.Set[ids.ShortID]
	Keys  []*ecdsa.PrivateKey
}

// NewKeychain returns a new keychain containing [keys]
func NewKeychain(keys ...*ecdsa.PrivateKey) *Keychain {
	kc := &Keychain{
		addrToKeyIndex: make(map[ids.ShortID]int),
		Addrs:          make(set.Set[ids.ShortID]),
	}
	for _, key := range keys {
		kc.Add(key)
	}
	return kc
}

// Add a new key to the key chain
func (kc *Keychain) Add(key *ecdsa.PrivateKey) {
	pkBytes := pubKeyBytes(&key.PublicKey)
	addressBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, _ := ids.ToShortID(addressBytes)

	if _, ok := kc.addrToKeyIndex[addr]; !ok {
		kc.addrToKeyIndex[addr] = len(kc.Keys)
		kc.Keys = append(kc.Keys, key)
		kc.Addrs.Add(addr)
	}
}

// Get a key from the keychain. Returns keychain.Signer.
func (kc Keychain) Get(id ids.ShortID) (keychain.Signer, bool) {
	if i, ok := kc.addrToKeyIndex[id]; ok {
		return &p256Signer{key: kc.Keys[i]}, true
	}
	return nil, false
}

// Addresses returns the set of addresses this keychain manages
func (kc Keychain) Addresses() set.Set[ids.ShortID] {
	return kc.Addrs
}

// New generates a new P-256 key pair and adds it to the keychain
func (kc *Keychain) New() (*ecdsa.PrivateKey, error) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kc.Add(sk)
	return sk, nil
}

// Spend attempts to create an input for the given output
func (kc *Keychain) Spend(out verify.Verifiable, time uint64) (verify.Verifiable, []*ecdsa.PrivateKey, error) {
	switch out := out.(type) {
	case *MintOutput:
		if sigIndices, keys, able := kc.Match(&out.OutputOwners, time); able {
			return &Input{
				SigIndices: sigIndices,
			}, keys, nil
		}
		return nil, nil, errCantSpend
	case *TransferOutput:
		if sigIndices, keys, able := kc.Match(&out.OutputOwners, time); able {
			return &TransferInput{
				Amt: out.Amt,
				Input: Input{
					SigIndices: sigIndices,
				},
			}, keys, nil
		}
		return nil, nil, errCantSpend
	}
	return nil, nil, fmt.Errorf("can't spend UTXO because it is unexpected type %T", out)
}

// Match attempts to match a list of addresses up to the provided threshold
func (kc *Keychain) Match(owners *OutputOwners, time uint64) ([]uint32, []*ecdsa.PrivateKey, bool) {
	if time < owners.Locktime {
		return nil, nil, false
	}
	sigs := make([]uint32, 0, owners.Threshold)
	keys := make([]*ecdsa.PrivateKey, 0, owners.Threshold)
	for i := uint32(0); i < uint32(len(owners.Addrs)) && uint32(len(keys)) < owners.Threshold; i++ {
		if idx, exists := kc.addrToKeyIndex[owners.Addrs[i]]; exists {
			sigs = append(sigs, i)
			keys = append(keys, kc.Keys[idx])
		}
	}
	return sigs, keys, uint32(len(keys)) == owners.Threshold
}

// verifyP256 verifies a P-256 ECDSA signature (R||S) against a hash and pubkey (X||Y)
func verifyP256(digest []byte, sigBytes [SigLen]byte, pkBytes []byte) bool {
	if len(pkBytes) != PubKeyLen {
		return false
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	x := new(big.Int).SetBytes(pkBytes[:32])
	y := new(big.Int).SetBytes(pkBytes[32:])

	if !elliptic.P256().IsOnCurve(x, y) {
		return false
	}

	pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	return ecdsa.Verify(pk, digest, r, s)
}
