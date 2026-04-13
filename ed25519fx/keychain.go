// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519fx

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	"github.com/luxfi/keychain"
	"github.com/luxfi/math/set"
	"github.com/luxfi/vm/components/verify"
)

var (
	errCantSpend = errors.New("unable to spend this UTXO")

	_ keychain.Signer   = (*ed25519Signer)(nil)
	_ keychain.Keychain = (*Keychain)(nil)
)

// ed25519Signer wraps an Ed25519 private key to implement keychain.Signer
type ed25519Signer struct {
	key ed25519.PrivateKey
}

func (s *ed25519Signer) SignHash(h []byte) ([]byte, error) {
	return ed25519.Sign(s.key, h), nil
}

func (s *ed25519Signer) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.key, msg), nil
}

func (s *ed25519Signer) Address() ids.ShortID {
	pkBytes := s.key.Public().(ed25519.PublicKey)
	addressBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, _ := ids.ToShortID(addressBytes)
	return addr
}

// Keychain is a collection of Ed25519 keys that can be used to spend outputs
type Keychain struct {
	addrToKeyIndex map[ids.ShortID]int

	Addrs set.Set[ids.ShortID]
	Keys  []ed25519.PrivateKey
}

// NewKeychain returns a new keychain containing [keys]
func NewKeychain(keys ...ed25519.PrivateKey) *Keychain {
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
func (kc *Keychain) Add(key ed25519.PrivateKey) {
	pkBytes := key.Public().(ed25519.PublicKey)
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
		return &ed25519Signer{key: kc.Keys[i]}, true
	}
	return nil, false
}

// Addresses returns the set of addresses this keychain manages
func (kc Keychain) Addresses() set.Set[ids.ShortID] {
	return kc.Addrs
}

// New generates a new Ed25519 key pair and adds it to the keychain
func (kc *Keychain) New() (ed25519.PrivateKey, error) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	kc.Add(sk)
	return sk, nil
}

// Spend attempts to create an input for the given output
func (kc *Keychain) Spend(out verify.Verifiable, time uint64) (verify.Verifiable, []ed25519.PrivateKey, error) {
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
func (kc *Keychain) Match(owners *OutputOwners, time uint64) ([]uint32, []ed25519.PrivateKey, bool) {
	if time < owners.Locktime {
		return nil, nil, false
	}
	sigs := make([]uint32, 0, owners.Threshold)
	keys := make([]ed25519.PrivateKey, 0, owners.Threshold)
	for i := uint32(0); i < uint32(len(owners.Addrs)) && uint32(len(keys)) < owners.Threshold; i++ {
		if idx, exists := kc.addrToKeyIndex[owners.Addrs[i]]; exists {
			sigs = append(sigs, i)
			keys = append(keys, kc.Keys[idx])
		}
	}
	return sigs, keys, uint32(len(keys)) == owners.Threshold
}
