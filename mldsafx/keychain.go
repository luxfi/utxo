// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsafx

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
	"github.com/luxfi/keychain"
	"github.com/luxfi/math/set"
	"github.com/luxfi/vm/components/verify"
)

var (
	errCantSpend = errors.New("unable to spend this UTXO")

	_ keychain.Signer   = (*mldsaSigner)(nil)
	_ keychain.Keychain = (*Keychain)(nil)
)

// mldsaSigner wraps an ML-DSA private key to implement keychain.Signer
type mldsaSigner struct {
	key *mldsa.PrivateKey
}

func (s *mldsaSigner) SignHash(h []byte) ([]byte, error) {
	// ML-DSA signs messages directly, not hashes. Use the hash as the message.
	return s.key.Sign(rand.Reader, h, nil)
}

func (s *mldsaSigner) Sign(msg []byte) ([]byte, error) {
	return s.key.Sign(rand.Reader, msg, nil)
}

func (s *mldsaSigner) Address() ids.ShortID {
	pkBytes := s.key.PublicKey.Bytes()
	addressBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, _ := ids.ToShortID(addressBytes)
	return addr
}

// Keychain is a collection of ML-DSA keys that can be used to spend outputs
type Keychain struct {
	addrToKeyIndex map[ids.ShortID]int

	Addrs set.Set[ids.ShortID]
	Keys  []*mldsa.PrivateKey
}

// NewKeychain returns a new keychain containing [keys]
func NewKeychain(keys ...*mldsa.PrivateKey) *Keychain {
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
func (kc *Keychain) Add(key *mldsa.PrivateKey) {
	pkBytes := key.PublicKey.Bytes()
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
		return &mldsaSigner{key: kc.Keys[i]}, true
	}
	return nil, false
}

// Addresses returns the set of addresses this keychain manages
func (kc Keychain) Addresses() set.Set[ids.ShortID] {
	return kc.Addrs
}

// New generates a new ML-DSA-65 key pair and adds it to the keychain
func (kc *Keychain) New() (*mldsa.PrivateKey, error) {
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		return nil, err
	}
	kc.Add(sk)
	return sk, nil
}

// Spend attempts to create an input for the given output
func (kc *Keychain) Spend(out verify.Verifiable, time uint64) (verify.Verifiable, []*mldsa.PrivateKey, error) {
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
func (kc *Keychain) Match(owners *OutputOwners, time uint64) ([]uint32, []*mldsa.PrivateKey, bool) {
	if time < owners.Locktime {
		return nil, nil, false
	}
	sigs := make([]uint32, 0, owners.Threshold)
	keys := make([]*mldsa.PrivateKey, 0, owners.Threshold)
	for i := uint32(0); i < uint32(len(owners.Addrs)) && uint32(len(keys)) < owners.Threshold; i++ {
		// Derive address from stored public key
		addressBytes := hash.PubkeyBytesToAddress(owners.Addrs[i])
		addr, err := ids.ToShortID(addressBytes)
		if err != nil {
			continue
		}
		if idx, exists := kc.addrToKeyIndex[addr]; exists {
			sigs = append(sigs, i)
			keys = append(keys, kc.Keys[idx])
		}
	}
	return sigs, keys, uint32(len(keys)) == owners.Threshold
}

// get returns the raw private key for the given address
func (kc Keychain) get(id ids.ShortID) (*mldsa.PrivateKey, bool) {
	if i, ok := kc.addrToKeyIndex[id]; ok {
		return kc.Keys[i], true
	}
	return nil, false
}
