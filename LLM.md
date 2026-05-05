# LLM.md — luxfi/utxo

## Overview

Go module: `github.com/luxfi/utxo`

The UTXO library + **signature Fx plugin system** for Lux X-Chain. Each Fx plugin implements one signature scheme. X-Chain consensus dispatches by Fx ID — any registered curve can spend UTXOs.

## X-Chain = Universal Multi-Curve Settlement Layer

X-Chain supports multiple signature schemes simultaneously. This lets anyone from any ecosystem settle value natively by signing with their own curve. No bridge contracts, no wrapped tokens.

## Fx Plugin Roadmap

| Package | Scheme | Use Case | Status |
|---------|--------|----------|--------|
| `secp256k1fx` | secp256k1 ECDSA | Ethereum, Bitcoin, Cosmos | ✓ complete |
| `nftfx` | NFT extension | Non-fungible tokens | ✓ complete |
| `propertyfx` | Property attestations | Attestation outputs | ✓ complete |
| `mldsafx` | ML-DSA-65 (FIPS 204) | PQ single-signer, Lux native | complete |
| `slhdsafx` | SLH-DSA-SHA2-192f (FIPS 205) | Hash-based PQ, treasury/governance | complete |
| `ed25519fx` | Ed25519 | Solana, Cardano, NEAR, Polkadot | complete |
| `secp256r1fx` | P-256 (NIST secp256r1) | Apple Secure Enclave, WebAuthn, TPM | complete |
| `sr25519fx` | Sr25519 Schnorr | Polkadot/Substrate | TODO |
| `schnorrfx` | BIP-340 Schnorr | Bitcoin Taproot | TODO |
| `cggmp21fx` | CGGMP21 threshold ECDSA | Verify classical threshold sigs (MPC custody) | TODO |
| `frostfx` | FROST threshold Schnorr | Verify Bitcoin Taproot threshold sigs | TODO |
| `ringtailfx` | Ringtail threshold (PQ) | Verify PQ threshold sigs from M-Chain (LP-134) | TODO |
| `ringfx` | LSAG ring signatures | Sender anonymity (Monero-style) | TODO |
| `kemfx` | ML-KEM-768 | Stealth addresses, encrypted memos | TODO |

**Threshold signing architecture:** X-Chain Fx plugins VERIFY threshold signatures. The actual threshold signing ceremonies happen on M-Chain — the MPC runtime carved out of the legacy T-Chain monolith per LP-134 (Lux Chain Topology). So `cggmp21fx`/`frostfx`/`ringtailfx` are verifier plugins that accept the final aggregated sig — the keygen + signing rounds run as ceremonies on M-Chain via `chains/thresholdvm` in MPC mode. The legacy "T-Chain" name now refers only to `teleportvm` (LP-6332), which is unrelated.

**Not implementing:** `thresholdmldsafx` (threshold ML-DSA). No FIPS standard exists yet. Use `ringtailfx` for PQ threshold signing — Ringtail is the real standardized PQ threshold primitive.

## Fx Interface

```go
type Fx interface {
    Initialize(vm interface{}) error
    VerifyTransfer(tx, in, cred, utxo) error
    VerifyCredentials(tx, in, cred) error
    VerifyPermission(tx, in, cred, owner) error
}
```

Each Fx implements signature verification for its scheme. A transaction's `Credentials` field carries per-input signatures; X-Chain dispatches by the Fx ID attached to each output's owner type.

## Mixed-Curve Multisig

A single UTXO's `OutputOwners` can reference pubkeys from different Fx plugins. Examples:
- 2-of-3: Ed25519 (user) + ML-DSA (backup) + SLH-DSA (cold storage)
- Time-locked recovery: secp256k1 (primary) OR ML-DSA after timelock
- Cross-ecosystem multisig: Solana Ed25519 + Ethereum secp256k1 jointly control a UTXO

## Structure

```
utxo/
├── addresses.go
├── api.go
├── asset.go
├── atomic_utxo_manager.go
├── atomic_utxos.go
├── base_tx.go
├── context.go
├── flow_checker.go
├── lux.go
├── metadata.go
├── secp256k1fx/      ✓ classical ECDSA (secp256k1)
├── nftfx/            ✓ NFTs
├── propertyfx/       ✓ attestations
├── mldsafx/          ✓ ML-DSA-65 PQ signing (FIPS 204)
├── slhdsafx/         ✓ SLH-DSA hash-based PQ (FIPS 205)
├── ed25519fx/        ✓ Ed25519 (Solana/Cardano/NEAR/Polkadot)
└── secp256r1fx/      ✓ P-256 ECDSA (WebAuthn/Secure Enclave/TPM)
```

## Related

- `~/work/lux/crypto/` — PQ primitives (ML-DSA, SLH-DSA, ML-KEM, Ringtail, etc.)
- `~/work/lux/precompile/` — EVM precompiles that wrap each Fx's verifier so C-Chain contracts can verify any curve
- `~/work/lux/node/vms/xvm/` — X-Chain VM that consumes these Fx plugins
- `~/work/lux/papers/lp-105-quasar-consensus.tex` — Quasar three-layer consensus
