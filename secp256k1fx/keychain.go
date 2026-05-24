// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1fx

import (
	"errors"
	"fmt"
	"strings"

	gethcommon "github.com/luxfi/geth/common"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/formatting"
	"github.com/luxfi/ids"
	"github.com/luxfi/keychain"
	"github.com/luxfi/math/set"
	"github.com/luxfi/vm/components/verify"
)

var (
	errCantSpend = errors.New("unable to spend this UTXO")

	// Compile-time assertions that luxSigner implements keychain.Signer
	_ keychain.Signer = (*luxSigner)(nil)

	// Compile-time assertion that Keychain implements keychain.Keychain
	_ keychain.Keychain = (*Keychain)(nil)
)

// luxSigner wraps a secp256k1.PrivateKey to implement wallet/keychain.Signer
type luxSigner struct {
	key *secp256k1.PrivateKey
}

func (s *luxSigner) SignHash(hash []byte) ([]byte, error) {
	return s.key.SignHash(hash)
}

func (s *luxSigner) Sign(msg []byte) ([]byte, error) {
	return s.key.Sign(msg)
}

func (s *luxSigner) Address() ids.ShortID {
	pk := s.key.PublicKey()
	pkBytes := pk.Bytes()
	addressBytes := secp256k1.PubkeyBytesToAddress(pkBytes)
	addr, _ := ids.ToShortID(addressBytes)
	return addr
}

// AddressBytes returns the address as bytes (for keychain.Signer interface)
func (s *luxSigner) AddressBytes() []byte {
	pk := s.key.PublicKey()
	pkBytes := pk.Bytes()
	return secp256k1.PubkeyBytesToAddress(pkBytes)
}

// Keychain is a collection of keys that can be used to spend outputs
type Keychain struct {
	luxAddrToKeyIndex    map[ids.ShortID]int
	keccakAddrToKeyIndex map[gethcommon.Address]int

	// These can be used to iterate over. However, they should not be modified
	// externally.
	//
	// KeccakAddrs holds the 20-byte addresses derived as
	// Keccak256(uncompressed_secp256k1_pubkey)[12:] — the conventional
	// EVM-runtime address format consumed by Lux C-Chain, Partner EVM,
	// Hanzo EVM, Polygon, BSC, etc. The derivation is a primitive
	// (Keccak + secp256k1), not Ethereum-specific.
	//
	// EthAddrs is the same underlying set retained as a Deprecated
	// alias so downstream callers (mpc, cli, kms, state) don't break
	// in one wave. Reads via either field return identical data.
	//
	// Deprecated: use KeccakAddrs.
	Addrs       set.Set[ids.ShortID]
	KeccakAddrs set.Set[gethcommon.Address]
	EthAddrs    set.Set[gethcommon.Address] // Deprecated: same map as KeccakAddrs
	Keys        []*secp256k1.PrivateKey
}

// NewKeychain returns a new keychain containing [keys]
func NewKeychain(keys ...*secp256k1.PrivateKey) *Keychain {
	keccakAddrs := make(set.Set[gethcommon.Address])
	kc := &Keychain{
		luxAddrToKeyIndex:    make(map[ids.ShortID]int),
		keccakAddrToKeyIndex: make(map[gethcommon.Address]int),
		Addrs:                make(set.Set[ids.ShortID]),
		// KeccakAddrs and EthAddrs share the SAME underlying map so
		// Adds via either field are visible from both. set.Set is a
		// map type (reference semantics), so the two struct fields
		// hold the same map header.
		KeccakAddrs: keccakAddrs,
		EthAddrs:    keccakAddrs,
	}
	for _, key := range keys {
		kc.Add(key)
	}
	return kc
}

// Add a new key to the key chain
func (kc *Keychain) Add(key *secp256k1.PrivateKey) {
	pk := key.PublicKey()
	// Convert public key to Lux address using hash160
	pkBytes := pk.Bytes()
	addressBytes := secp256k1.PubkeyBytesToAddress(pkBytes)
	luxAddr, _ := ids.ToShortID(addressBytes)

	if _, ok := kc.luxAddrToKeyIndex[luxAddr]; !ok {
		kc.luxAddrToKeyIndex[luxAddr] = len(kc.Keys)
		cryptoAddr := secp256k1.PubkeyToAddress(*pk.ToECDSA())
		keccakAddr := gethcommon.Address(cryptoAddr)
		kc.keccakAddrToKeyIndex[keccakAddr] = len(kc.Keys)
		kc.Keys = append(kc.Keys, key)
		kc.Addrs.Add(luxAddr)
		// One write — both KeccakAddrs and EthAddrs see it since they
		// share the underlying map.
		kc.KeccakAddrs.Add(keccakAddr)
	}
}

// Get a key from the keychain and return whether the key existed.
// Returns keychain.Signer to implement keychain.Keychain
func (kc Keychain) Get(id ids.ShortID) (keychain.Signer, bool) {
	signer, exists := kc.get(id)
	if !exists {
		return nil, false
	}
	return &luxSigner{key: signer}, true
}

// GetByKeccak gets a key from the keychain by its 20-byte Keccak-
// derived address (the EVM-runtime address format consumed by any
// EVM-compatible chain). Returns keychain.Signer for wallet
// operations.
func (kc Keychain) GetByKeccak(addr gethcommon.Address) (keychain.Signer, bool) {
	if i, ok := kc.keccakAddrToKeyIndex[addr]; ok {
		return &luxSigner{key: kc.Keys[i]}, true
	}
	return nil, false
}

// GetEth is the deprecated alias for GetByKeccak.
//
// Deprecated: use GetByKeccak.
func (kc Keychain) GetEth(addr gethcommon.Address) (keychain.Signer, bool) {
	return kc.GetByKeccak(addr)
}

// AddressSet returns a set of addresses this keychain manages
func (kc Keychain) AddressSet() set.Set[ids.ShortID] {
	return kc.Addrs
}

// Addresses returns a set of addresses this keychain manages (implements keychain.Keychain)
func (kc Keychain) Addresses() set.Set[ids.ShortID] {
	return kc.Addrs
}

// AddressList returns a list of addresses this keychain manages
func (kc Keychain) AddressList() []ids.ShortID {
	return kc.List()
}

// List returns all addresses in the keychain (implements keychain.Keychain)
func (kc Keychain) List() []ids.ShortID {
	addrs := make([]ids.ShortID, 0, kc.Addrs.Len())
	for addr := range kc.Addrs {
		addrs = append(addrs, addr)
	}
	return addrs
}

// KeccakAddresses returns the set of 20-byte Keccak-derived addresses
// this keychain manages — the EVM-runtime address format consumed by
// any EVM-compatible chain (Lux C-Chain, Partner EVM, etc.).
//
// Naming: the derivation primitive (Keccak256 of secp256k1 pubkey)
// is what the set carries; the name reflects the value, not the
// downstream brand that happens to consume it. See PrivateKey
// docstring in luxfi/crypto/secp256k1/keys.go for the rationale.
func (kc Keychain) KeccakAddresses() set.Set[gethcommon.Address] {
	return kc.KeccakAddrs
}

// EthAddresses is the deprecated alias for KeccakAddresses.
//
// Deprecated: use KeccakAddresses.
func (kc Keychain) EthAddresses() set.Set[gethcommon.Address] {
	return kc.KeccakAddresses()
}

// New returns a newly generated private key
func (kc *Keychain) New() (*secp256k1.PrivateKey, error) {
	sk, err := secp256k1.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	kc.Add(sk)
	return sk, nil
}

// Spend attempts to create an input
func (kc *Keychain) Spend(out verify.Verifiable, time uint64) (verify.Verifiable, []*secp256k1.PrivateKey, error) {
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
func (kc *Keychain) Match(owners *OutputOwners, time uint64) ([]uint32, []*secp256k1.PrivateKey, bool) {
	if time < owners.Locktime {
		return nil, nil, false
	}
	sigs := make([]uint32, 0, owners.Threshold)
	keys := make([]*secp256k1.PrivateKey, 0, owners.Threshold)
	for i := uint32(0); i < uint32(len(owners.Addrs)) && uint32(len(keys)) < owners.Threshold; i++ {
		if key, exists := kc.get(owners.Addrs[i]); exists {
			sigs = append(sigs, i)
			keys = append(keys, key)
		}
	}
	return sigs, keys, uint32(len(keys)) == owners.Threshold
}

// PrefixedString returns the key chain as a string representation with [prefix]
// added before every line.
func (kc *Keychain) PrefixedString(prefix string) string {
	sb := strings.Builder{}
	format := fmt.Sprintf("%%sKey[%s]: Key: %%s Address: %%s\n",
		formatting.IntFormat(len(kc.Keys)-1))
	for i, key := range kc.Keys {
		// We assume that the maximum size of a byte slice that
		// can be stringified is at least the length of a SECP256K1 private key
		keyStr, _ := formatting.Encode(formatting.HexNC, key.Bytes())
		sb.WriteString(fmt.Sprintf(format,
			prefix,
			i,
			keyStr,
			key.PublicKey().Address(),
		))
	}

	return strings.TrimSuffix(sb.String(), "\n")
}

func (kc *Keychain) String() string {
	return kc.PrefixedString("")
}

// to avoid internals type assertions
func (kc Keychain) get(id ids.ShortID) (*secp256k1.PrivateKey, bool) {
	if i, ok := kc.luxAddrToKeyIndex[id]; ok {
		return kc.Keys[i], true
	}
	return nil, false
}
