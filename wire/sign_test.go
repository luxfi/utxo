// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/crypto/secp256k1"
)

func TestSignSecp256k1_RoundTrip(t *testing.T) {
	// Generate a couple of test keys.
	k1, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	k2, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}

	// Pretend we have an unsigned tx blob (in production this would be a
	// zap_native-encoded UnsignedTx with a TxKind discriminator at offset 0).
	unsigned := bytes.Repeat([]byte("UNSIGNED-TX-BYTES "), 16)

	// Two inputs: input 0 needs (k1, k2) co-signers; input 1 needs k2 alone.
	signers := [][]*secp256k1.PrivateKey{
		{k1, k2},
		{k2},
	}

	signedTxBytes, err := SignSecp256k1(unsigned, signers)
	if err != nil {
		t.Fatalf("SignSecp256k1: %v", err)
	}

	got, err := WrapSignedTx(signedTxBytes)
	if err != nil {
		t.Fatalf("WrapSignedTx: %v", err)
	}
	if !bytes.Equal(got.UnsignedBytes(), unsigned) {
		t.Fatalf("UnsignedBytes mismatch")
	}
	if got.CredentialCount() != 2 {
		t.Fatalf("CredentialCount: got %d, want 2", got.CredentialCount())
	}

	all, err := got.AllCredentials()
	if err != nil {
		t.Fatalf("AllCredentials: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("AllCredentials len: got %d, want 2", len(all))
	}

	// Validate the signatures recover the right pubkey.
	txHash := hash.ComputeHash256(unsigned)

	// Input 0: 2 sigs (k1, k2).
	cred0 := all[0]
	if cred0.SignatureCount(secp256k1.SignatureLen) != 2 {
		t.Fatalf("cred0 sig count: got %d, want 2", cred0.SignatureCount(secp256k1.SignatureLen))
	}
	sig0_0 := cred0.SignatureAt(0, secp256k1.SignatureLen)
	pk0_0, err := secp256k1.RecoverPublicKeyFromHash(txHash, sig0_0)
	if err != nil {
		t.Fatalf("recover sig0_0: %v", err)
	}
	if !bytes.Equal(pk0_0.Bytes(), k1.PublicKey().Bytes()) {
		t.Errorf("sig0_0 pubkey mismatch")
	}
	sig0_1 := cred0.SignatureAt(1, secp256k1.SignatureLen)
	pk0_1, err := secp256k1.RecoverPublicKeyFromHash(txHash, sig0_1)
	if err != nil {
		t.Fatalf("recover sig0_1: %v", err)
	}
	if !bytes.Equal(pk0_1.Bytes(), k2.PublicKey().Bytes()) {
		t.Errorf("sig0_1 pubkey mismatch")
	}

	// Input 1: 1 sig (k2).
	cred1 := all[1]
	if cred1.SignatureCount(secp256k1.SignatureLen) != 1 {
		t.Fatalf("cred1 sig count: got %d, want 1", cred1.SignatureCount(secp256k1.SignatureLen))
	}
	sig1_0 := cred1.SignatureAt(0, secp256k1.SignatureLen)
	pk1_0, err := secp256k1.RecoverPublicKeyFromHash(txHash, sig1_0)
	if err != nil {
		t.Fatalf("recover sig1_0: %v", err)
	}
	if !bytes.Equal(pk1_0.Bytes(), k2.PublicKey().Bytes()) {
		t.Errorf("sig1_0 pubkey mismatch")
	}
}
