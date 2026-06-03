# utxo ZAP-keystone migration

## Activation

2025-12-25T16:20:00-08:00 (unix 1766708400). New final Lux network — predates
every block. No backwards compat, no env-var gate, no codec shim.

## Goal

Replace `github.com/luxfi/codec`-based serialization with ZAP-native wire
schemas so that `luxfi/node`'s `vms/platformvm/txs/codec.go` and
`vms/xvm/txs/codec.go` can be deleted. The fxs' `Initialize(vm)` registration
with `vm.CodecRegistry()` is the last codec.Manager dependency in the fxs
plugin system; once we provide a static ZAP schema per primitive, the
registration is dead code.

## Audit — current codec dependencies

### Module-level

`github.com/luxfi/utxo` go.mod requires `github.com/luxfi/codec v1.1.4`.
Consumed transitively by `github.com/luxfi/vm` for `verify.State`.

### Files importing `luxfi/codec`

Root package (`luxfi/utxo`):
- `api.go` — `codec.Manager`/`codec.Marshal` for JSON UTXO responses
- `atomic_utxos.go` — `codec.Manager` for cross-chain export/import
- `flow_checker.go` — `codec.Manager` passed through to verify
- `transferables.go` — `codec.Manager` in `SortTransferableOutputs`,
  `IsSortedTransferableOutputs`, `VerifyTx`
- `utxo_state.go` — `codec.Manager.{Marshal,Unmarshal}` for disk encoding,
  references the package-level `codecVersion` constant

Per-fx (`secp256k1fx`, `mldsafx`, `slhdsafx`, `ed25519fx`, `secp256r1fx`,
`schnorrfx`, `bls12381fx`):
- `vm.go` — `codec.Registry` on the `VM` interface (the test surface for
  the codec.Manager passed in by the host VM)
- `fx.go` — `Initialize(vm)` calls `vm.CodecRegistry().RegisterType(...)`
  for every primitive type the fx owns. Tests + benchmarks construct a
  `linearcodec.NewDefault()` to satisfy the registration call.

External consumers — 204 Go files in `luxfi/node` import
`github.com/luxfi/utxo`, of which 116 reference the polymorphic typed Go
fields directly (`*secp256k1fx.TransferOutput`, etc.). The migration
strategy below avoids cascading into all 116.

### UTXO struct

The polymorphic field is `UTXO.Out verify.State` (where `verify.State` is
an interface in `github.com/luxfi/vm/components/verify`). It is set to a
concrete type from one of the fx packages: `*secp256k1fx.TransferOutput`,
`*secp256k1fx.MintOutput`, `*bls12381fx.AttestationOutput`, etc.

### fx packages

Each fx has:
- `transfer_output.go` / `transfer_input.go` — value-bearing primitives
- `mint_output.go` / `mint_operation.go` — mint authority primitives
- `credential.go` — signature container
- `output_owners.go` — owner group (threshold + addrs)

`bls12381fx` is attestation-only (no transfer/mint); it has
`AttestationOutput`, `AttestationInput`, `Credential`. `nftfx` and
`propertyfx` are operation-only (no value primitives).

## Strategy — Option 2 chosen

Option 1 (UTXO.Out → []byte envelope, every consumer Wrap*Output on
read) cascades through ~116 consumer files in `luxfi/node` alone, with
more in `luxfi/wallet` / `luxfi/cli` / `luxfi/genesis`. That is too
broad an edit set for a single landing.

**Option 2** (dual representation) is the chosen path:

- Keep the typed Go field for in-memory consumers (no breakage of the
  116 files).
- Add a new `github.com/luxfi/utxo/wire` package that provides ZAP-native
  wire schemas + zero-copy accessors mirroring
  `github.com/luxfi/node/vms/wire`.
- Per-fx, add `wire_*.go` files exposing `(value T).Bytes() []byte` (Go
  type → wire envelope) and `Wrap*(b []byte) (T, error)` (wire envelope
  → Go type). The Go type is the in-memory representation; the wire
  envelope is the on-wire representation. Marshal/Unmarshal go through
  these.
- Drop the `Initialize(vm)` codec.Manager registration. The wire schema
  is static at compile time — there is nothing to register.
- Wire over the `codec.Manager` call sites at the root package (e.g.
  `utxo_state.go`, `transferables.go`) to use the new `wire.UTXO` etc.
  directly.
- Delete the `codec.Registry` field from each fx's `VM` interface (it is
  used only by `Initialize`).

The hard cut is that the `Initialize(vm)` chain is gone — the fxs are
configured statically, not via a registration callback. The host VM
gives the fx a `Logger()` and a `Clock()` (the only other VM methods);
no codec on the wire.

## Files created

`github.com/luxfi/utxo/wire/`:

- `discriminator.go` — TypeKind + ShapeKind constants, envelope prefix
  read/write helpers
- `utxo.go` — UTXO wire schema
- `transfer_output.go` / `transfer_input.go` — cross-fx classical schemas
- `mint_output.go` / `mint_operation.go` — cross-fx schemas
- `credential.go` — cross-fx schema (TypeKind names fx, supports
  pubkey-recoverable and pubkey-carrying credentials)
- `output_owners.go` — cross-fx owner schema (20-byte ShortID addresses)
- `pchain_owner.go` — P-chain warp owner subset of OutputOwners
- `attestation.go` — AttestationOutput + AttestationInput for bls12381fx
- `pq_output_owners.go` — PQ-fx OutputOwners with variable-length pubkeys
  (mldsafx, slhdsafx — addresses are full PQ pubkeys, not 20-byte hashes)
- `pq_transfer_output.go` — PQ-fx TransferOutput
- `pq_mint_output.go` — PQ-fx MintOutput
- `signed_tx.go` — outer envelope (unsigned bytes + credentials)
- `sign.go` — `SignSecp256k1(unsignedBytes, signers)` for the classical
  fx signing entry point
- `wire_test.go` / `pq_test.go` / `sign_test.go` — round-trip tests

Per-fx `wire.go` files providing `Bytes()` + `Wrap*` adapters between
the in-memory Go type and the wire envelope. The schemas use the same
TypeKind discriminator from `wire/discriminator.go` so a TransferOutput
parsed off the wire knows its owning fx without a dispatch table.

Files created per fx:

- `secp256k1fx/wire.go` + `secp256k1fx/wire_test.go`
- `ed25519fx/wire.go` + `ed25519fx/wire_test.go`
- `secp256r1fx/wire.go` + `secp256r1fx/wire_test.go`
- `schnorrfx/wire.go` + `schnorrfx/wire_test.go`
- `mldsafx/wire.go` + `mldsafx/wire_test.go`
- `slhdsafx/wire.go` + `slhdsafx/wire_test.go`
- `bls12381fx/wire.go` + `bls12381fx/wire_test.go`

Root package:

- `utxo_wire.go` — `UTXO.WireBytes()` builds the outer envelope by
  calling the polymorphic `Out`'s `Bytes()`; `WrapUTXOBytes(b)` parses
  the outer envelope and returns a `wire.UTXO` accessor. The inner
  output envelope must be parsed by the caller through the
  appropriate fx package's `WrapTransferOutput` / `WrapMintOutput` /
  `WrapAttestationOutput` — the root package cannot import the fx
  packages (would be a cycle).
- `utxo_wire_test.go` — round-trip test exercising the full
  UTXO → wire → fx parse → equality dispatch.

## Files NOT yet deleted (next cut)

The following still reference `luxfi/codec` and remain pending the
downstream agents' coordinated cut:

- `utxo_state.go` — `utxoState.codec codec.Manager` for disk encoding.
  Replace with `WireBytes()` / `WrapUTXOBytes` after the consumer
  agents' state migrations land.
- `atomic_utxos.go` — `atomicUTXOManager.codec codec.Manager` for
  cross-chain UTXO export/import.
- `transferables.go` — `codec.Manager` in `SortTransferableOutputs`,
  `IsSortedTransferableOutputs`, `VerifyTx`.
- `flow_checker.go` — `codec.Manager` passed through to verify.
- `api.go` — uses `codec.Uint32` / `codec.Uint64` (JSON-quote wrapper
  types, NOT `codec.Manager`); these are orthogonal to the codec
  rip and can stay.
- Per-fx `vm.go` — `codec.Registry` on the `VM` interface; used only by
  the per-fx `Initialize(vm)` to call `vm.CodecRegistry().RegisterType(...)`.
  Once consumers stop calling `Initialize`, both go away.
- Per-fx `fx.go` `Initialize(vm)` — calls `vm.CodecRegistry().RegisterType`
  for every primitive. Drop after consumers stop calling Initialize.

These are the second-cut targets; this first commit gets the wire/
package + per-fx adapters in so the downstream agents can pin a SHA
and start their migrations.

## Coordination

Three parallel agents are landing:

- `platformvm/warp` ZAP migration — consumes our `wire.OutputOwners` and
  `wire.PChainOwner`.
- `platformvm/state` ZAP migration — consumes our `wire.UTXO` for the
  state's persisted UTXOs.
- `xvm` ZAP migration — consumes our `wire.UTXO` for the X-chain state +
  every fxs `wire.*Output`/`wire.*Input`/`wire.Credential` schema.

When they land they pin a SHA from this branch. They do not modify the
typed Go field paths in `luxfi/utxo` — those remain for the 116 callers
that still hold typed references.

## Test plan

1. `cd ~/work/lux/utxo && GOWORK=off go build ./...`
2. `cd ~/work/lux/utxo && GOWORK=off go test ./... -count=1 -timeout=10m`
3. Round-trip test per fx primitive + per cross-fx schema (in
   `wire/wire_test.go` + per-fx `wire_test.go`).
4. Verify `luxfi/codec` is gone from go.mod after the final cleanup
   (after consumers have migrated; for the first cut we keep the dep
   alive since `utxo_state.go` still goes through the legacy codec
   pending downstream coordination).

## Commit + tag

First cut commits the wire/ package + per-fx wire_*.go adapters; the
`Initialize(vm)` chain stays in place pending the downstream agents'
coordinated cut. Subsequent cuts will remove the codec.Manager
references in `utxo_state.go`, `transferables.go`, `atomic_utxos.go`
once the agents have switched their state to call `wire.NewUTXO` /
`wire.WrapUTXO`.

The commit SHA from this first cut is what the downstream agents pin.
