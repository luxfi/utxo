# utxo_schema.zap moved

The cross-VM UTXO + TransferableIn/Out ZAP schema previously at

    github.com/luxfi/utxo/wire/utxo_schema.zap

now lives at

    github.com/luxfi/proto/schemas/utxo/utxo.zap

Generated `*_zap.go` siblings remain colocated with this package
(see `doc.go` for the updated `//go:generate zapgen` directive).
