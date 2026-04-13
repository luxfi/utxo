// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schnorrfx

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	"github.com/luxfi/keychain"
	"github.com/luxfi/math/set"
	"github.com/luxfi/vm/components/verify"
)

var (
	errCantSpend = errors.New("unable to spend this UTXO")

	_ keychain.Signer   = (*schnorrSigner)(nil)
	_ keychain.Keychain = (*Keychain)(nil)
)

// schnorrSigner wraps a btcec private key to implement keychain.Signer
// using BIP-340 Schnorr signing over the UTXO domain-separated tagged hash.
type schnorrSigner struct {
	key *btcec.PrivateKey
}

func (s *schnorrSigner) SignHash(h []byte) ([]byte, error) {
	sig, err := schnorr.Sign(s.key, h)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func (s *schnorrSigner) Sign(msg []byte) ([]byte, error) {
	digest := taggedDigest(utxoSignCtx, msg)
	sig, err := schnorr.Sign(s.key, digest)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func (s *schnorrSigner) Address() ids.ShortID {
	pkBytes := schnorr.SerializePubKey(s.key.PubKey())
	addressBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, err := ids.ToShortID(addressBytes)
	if err != nil {
		panic(fmt.Sprintf("hash160 produced wrong length: %v", err))
	}
	return addr
}

// Keychain is a collection of BIP-340 Schnorr keys
type Keychain struct {
	addrToKeyIndex map[ids.ShortID]int

	Addrs set.Set[ids.ShortID]
	Keys  []*btcec.PrivateKey
}

// NewKeychain returns a new keychain containing [keys]
func NewKeychain(keys ...*btcec.PrivateKey) *Keychain {
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
func (kc *Keychain) Add(key *btcec.PrivateKey) {
	pkBytes := schnorr.SerializePubKey(key.PubKey())
	addressBytes := hash.PubkeyBytesToAddress(pkBytes)
	addr, err := ids.ToShortID(addressBytes)
	if err != nil {
		panic(fmt.Sprintf("hash160 produced wrong length: %v", err))
	}

	if _, ok := kc.addrToKeyIndex[addr]; !ok {
		kc.addrToKeyIndex[addr] = len(kc.Keys)
		kc.Keys = append(kc.Keys, key)
		kc.Addrs.Add(addr)
	}
}

// Get a key from the keychain. Returns keychain.Signer.
func (kc Keychain) Get(id ids.ShortID) (keychain.Signer, bool) {
	if i, ok := kc.addrToKeyIndex[id]; ok {
		return &schnorrSigner{key: kc.Keys[i]}, true
	}
	return nil, false
}

// Addresses returns the set of addresses this keychain manages
func (kc Keychain) Addresses() set.Set[ids.ShortID] {
	return kc.Addrs
}

// New generates a new BIP-340 keypair and adds it to the keychain
func (kc *Keychain) New() (*btcec.PrivateKey, error) {
	sk, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	kc.Add(sk)
	return sk, nil
}

// Spend attempts to create an input for the given output
func (kc *Keychain) Spend(out verify.Verifiable, time uint64) (verify.Verifiable, []*btcec.PrivateKey, error) {
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
func (kc *Keychain) Match(owners *OutputOwners, time uint64) ([]uint32, []*btcec.PrivateKey, bool) {
	if time < owners.Locktime {
		return nil, nil, false
	}
	sigs := make([]uint32, 0, owners.Threshold)
	keys := make([]*btcec.PrivateKey, 0, owners.Threshold)
	for i := uint32(0); i < uint32(len(owners.Addrs)) && uint32(len(keys)) < owners.Threshold; i++ {
		if idx, exists := kc.addrToKeyIndex[owners.Addrs[i]]; exists {
			sigs = append(sigs, i)
			keys = append(keys, kc.Keys[idx])
		}
	}
	return sigs, keys, uint32(len(keys)) == owners.Threshold
}
