# Final codec rip — `luxfi/utxo`

Activation 2025-12-25T16:20:00-08:00. No backwards compat, no shim, no
env var. The wire is ZAP. Delete the legacy.

## Surface to delete

### Per-fx `vm.go` (8 files)

Drop `CodecRegistry() codec.Registry` from the `VM` interface. Drop the
`Codec` field from `TestVM` and its `CodecRegistry()` accessor. Drop the
`luxfi/codec` import. Files:

- `secp256k1fx/vm.go`
- `mldsafx/vm.go`
- `slhdsafx/vm.go`
- `ed25519fx/vm.go`
- `secp256r1fx/vm.go`
- `schnorrfx/vm.go`
- `bls12381fx/fx.go` (VM interface lives in fx.go for this package)

### Per-fx `fx.go` Initialize (9 files)

Drop the `c := fx.VM.CodecRegistry()` block + the `RegisterType` chain.
The wire schema is static at compile time; nothing to register. Each
`Initialize` keeps the VM cast + logger init and otherwise becomes a
no-op. Files:

- `secp256k1fx/fx.go`
- `mldsafx/fx.go`
- `slhdsafx/fx.go`
- `ed25519fx/fx.go`
- `secp256r1fx/fx.go`
- `schnorrfx/fx.go`
- `bls12381fx/fx.go`
- `nftfx/fx.go` — embeds `secp256k1fx.Fx`, has its own RegisterType chain
- `propertyfx/fx.go` — embeds `secp256k1fx.Fx`, has its own RegisterType chain

### Root package

- `api.go` — replace `codec.Uint32` / `codec.Uint64` with `jsonutil.Uint32` /
  `jsonutil.Uint64` (new package) or unqualified `uint32`/`uint64` with
  hand-rolled JSON. Cleanest: replicate the JSON-string-quoted types
  locally in `utxo/jsonutil/`.
- `atomic_utxos.go` — drop `codec codec.Manager` field + ctor param;
  parse cross-chain bytes through `wire.WrapUTXO(b)`.
- `flow_checker.go` — replace `wrappers.Errs` with an inline 5-line
  `errs` struct or move to `utxo/internal/errs/`. Drop the
  `luxfi/codec/wrappers` import.
- `transferables.go` — drop `c codec.Manager` from
  `SortTransferableOutputs`, `IsSortedTransferableOutputs`, `VerifyTx`.
  Sort key is now `out.Bytes()` (the ZAP wire envelope returned by the
  `wireSerializable` interface). `Verify` is unchanged.
- `utxo_state.go` — drop `codec codec.Manager` field + ctor params;
  encode/decode through `utxo.WireBytes()` / `utxo.WrapUTXOBytes()`.

### `wire/discriminator.go`

Doc-comment-only reference. Comment text is correct historical context;
no import statement. Leave it.

## Activation invariant

The new network's genesis is at unix 1766708400. Every block produced
after that point uses ZAP-native UTXO encoding. No legacy codec UTXOs
exist on disk or on the wire.

## Cascade

After this lands, every `luxd` caller of:

- `lux.SortTransferableOutputs(outs, Codec)` → `lux.SortTransferableOutputs(outs)`
- `lux.IsSortedTransferableOutputs(outs, Codec)` → `lux.IsSortedTransferableOutputs(outs)`
- `lux.VerifyTx(fee, feeAsset, ins, outs, Codec)` → `lux.VerifyTx(fee, feeAsset, ins, outs)`
- `lux.GetAtomicUTXOs(sm, codec, ...)` → `lux.GetAtomicUTXOs(sm, ...)`
- `lux.NewAtomicUTXOManager(sm, codec)` → `lux.NewAtomicUTXOManager(sm)`
- `lux.NewUTXOState(db, codec, track)` → `lux.NewUTXOState(db, track)`
- `lux.NewMeteredUTXOState(db, codec, metrics, track)` → `lux.NewMeteredUTXOState(db, metrics, track)`

needs the codec arg dropped. Plus every fx.Initialize callsite no
longer needs `vm.CodecRegistry()` to do anything.

## Order of operations

1. Define `utxo/jsonutil/uint.go` with `Uint32`/`Uint64` JSON-string types.
2. Patch `api.go` to use `jsonutil`.
3. Patch `flow_checker.go` to inline a tiny errs collector.
4. Patch `transferables.go` to use `wireSerializable.Bytes()` as sort key.
5. Patch `atomic_utxos.go` to use `wire.WrapUTXO(b)`.
6. Patch `utxo_state.go` to use `utxo.WireBytes()` / `WrapUTXOBytes`.
7. Patch every fx's `vm.go` to drop `CodecRegistry()` + `Codec` field.
8. Patch every fx's `fx.go` `Initialize` to drop the registration chain.
9. Patch every fx's tests to drop `Codec: linearcodec.NewDefault()` + the
   `linearcodec` import.
10. Build + test in tree.
11. `go mod edit -droprequire=github.com/luxfi/codec` + tidy.
12. Cascade through `luxd` consumer files.
