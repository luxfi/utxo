// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package bls12381fx provides BLS12-381 aggregate-signature verification for
// attestation / quorum-object UTXOs on X-Chain.
//
// This Fx is intentionally SPECIALIZED and does NOT support normal retail
// spends. Its purpose is to encode quorum decisions as on-chain records:
//
//   - Validator attestations (e.g. "this block hash was signed by >= N/M validators")
//   - Light-client checkpoints
//   - Cross-chain message commitments that carry a BLS aggregate sig
//   - Quorum-signed oracle reports
//
// Design constraints vs value-transferring Fx:
//
//   - No TransferOutput / TransferInput types. Attempts to use this Fx
//     for VerifyTransfer return ErrNotTransferable by design.
//   - The only output type is AttestationOutput, which is write-only.
//     Once created, it becomes a permanent record.
//   - Credentials carry a single 96-byte aggregated signature and a signer
//     bitmap. No per-signer signatures.
//
// Wallets and retail frontends MUST NOT expose this Fx for user spend flows.
// Its use is restricted to consensus-adjacent operations (see ~/work/lux/warp
// for cross-chain attestation semantics, ~/work/lux/consensus for validator
// quorum signing).
//
// Sizes (BLS12-381 on luxfi/crypto/bls):
//   - Compressed G1 public key: 48 bytes
//   - Compressed G2 aggregate signature: 96 bytes
package bls12381fx
