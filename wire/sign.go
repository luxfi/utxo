// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"fmt"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/crypto/secp256k1"
)

// SignSecp256k1 is the ZAP-native replacement for the legacy
// `txs.Tx.Sign(c codec.Manager, ...)` method. It takes the unsigned tx
// bytes (already ZAP-encoded by the txs.zap_native build path) plus a
// list of signer groups (one group per input, like the legacy API), and
// returns a fully-formed SignedTx wire envelope.
//
// The signing target is hash(unsignedBytes) — same as the legacy Sign.
// Each signer group produces one Credential whose Signatures field is
// the concatenation of all per-key secp256k1 signatures.
//
// This is the canonical secp256k1fx signing entry point. For multi-fx
// signing (mixing secp256k1 + ML-DSA + Ed25519 credentials), build the
// per-input credentials individually with NewCredential and pass them
// directly to NewSignedTx.
//
// Returns:
//   - signedTxBytes: the canonical wire envelope (SignedTx{unsigned, creds})
//   - err: a typed error from secp256k1.PrivateKey.SignHash on failure
func SignSecp256k1(unsignedBytes []byte, signers [][]*secp256k1.PrivateKey) ([]byte, error) {
	txHash := hash.ComputeHash256(unsignedBytes)

	credentials := make([][]byte, 0, len(signers))
	for groupIdx, keys := range signers {
		// Each input may have multiple co-signers; concatenate their
		// secp256k1.SignatureLen-byte signatures into the credential.
		sigsConcat := make([]byte, 0, len(keys)*secp256k1.SignatureLen)
		for keyIdx, key := range keys {
			sig, err := key.SignHash(txHash)
			if err != nil {
				return nil, fmt.Errorf(
					"wire.SignSecp256k1: group %d key %d: %w",
					groupIdx, keyIdx, err,
				)
			}
			if len(sig) != secp256k1.SignatureLen {
				return nil, fmt.Errorf(
					"wire.SignSecp256k1: group %d key %d: sig length %d != %d",
					groupIdx, keyIdx, len(sig), secp256k1.SignatureLen,
				)
			}
			sigsConcat = append(sigsConcat, sig...)
		}
		cred := NewCredential(CredentialInput{
			TypeKind:      TypeKindSecp256k1,
			SecurityLevel: 0,
			Signatures:    sigsConcat,
		})
		credentials = append(credentials, cred)
	}

	return NewSignedTx(SignedTxInput{
		UnsignedBytes: unsignedBytes,
		Credentials:   credentials,
	}), nil
}
