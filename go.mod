module github.com/luxfi/utxo

go 1.25.5

require (
	github.com/luxfi/address v1.0.1
	github.com/luxfi/cache v1.2.0
	github.com/luxfi/codec v1.1.3
	github.com/luxfi/consensus v1.22.53
	github.com/luxfi/constants v1.4.3
	github.com/luxfi/crypto v1.17.39
	github.com/luxfi/database v1.17.38
	github.com/luxfi/formatting v1.0.1
	github.com/luxfi/geth v1.16.69
	github.com/luxfi/ids v1.2.9
	github.com/luxfi/keychain v1.0.1
	github.com/luxfi/log v1.3.0
	github.com/luxfi/math v1.2.3
	github.com/luxfi/metric v1.4.10
	github.com/luxfi/timer v1.0.1
	github.com/luxfi/utils v1.1.1
	github.com/luxfi/vm v1.0.16
	github.com/stretchr/testify v1.11.1
	go.uber.org/mock v0.6.0
)

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251230134950-44c893854e3f // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.6 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/gorilla/rpc v1.2.1 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/luxfi/compress v0.0.2 // indirect
	github.com/luxfi/concurrent v0.0.2 // indirect
	github.com/luxfi/container v0.0.2 // indirect
	github.com/luxfi/math/big v0.1.0 // indirect
	github.com/luxfi/mock v0.1.0 // indirect
	github.com/luxfi/rpc v1.0.0 // indirect
	github.com/luxfi/sampler v1.0.0 // indirect
	github.com/luxfi/sdk v1.16.42 // indirect
	github.com/luxfi/tls v1.0.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/melbahja/goph v1.4.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/sftp v1.13.5 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/posthog/posthog-go v1.8.2 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/exp v0.0.0-20251219203646-944ab1f22d93 // indirect
	golang.org/x/sys v0.39.0 // indirect
	gonum.org/v1/gonum v0.16.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/luxfi/log => ../log

replace github.com/luxfi/consensus => ../consensus

replace github.com/luxfi/api => ../api
