// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package utxo

import (
	"github.com/luxfi/codec"
	"github.com/luxfi/formatting"
	"github.com/luxfi/ids"
)

// Index is an address and an associated UTXO.
// Marks a starting or stopping point when fetching UTXOs. Used for pagination.
type Index struct {
	Address string `json:"address"` // The address as a string
	UTXO    string `json:"utxo"`    // The UTXO ID as a string
}

// GetUTXOsArgs are arguments for passing into GetUTXOs.
// Gets the UTXOs that reference at least one address in [Addresses].
// Returns at most [limit] addresses.
// If specified, [SourceChain] is the chain where the atomic UTXOs were exported from. If empty,
// or the Chain ID of this VM is specified, then GetUTXOs fetches the native UTXOs.
// If [limit] == 0 or > [maxUTXOsToFetch], fetches up to [maxUTXOsToFetch].
// [StartIndex] defines where to start fetching UTXOs (for pagination.)
// UTXOs fetched are from addresses equal to or greater than [StartIndex.Address]
// For address [StartIndex.Address], only UTXOs with IDs greater than [StartIndex.UTXO] will be returned.
// If [StartIndex] is omitted, gets all UTXOs.
// If GetUTXOs is called multiple times, with our without [StartIndex], it is not guaranteed
// that returned UTXOs are unique. That is, the same UTXO may appear in the response of multiple calls.
type GetUTXOsArgs struct {
	Addresses   []string            `json:"addresses"`
	SourceChain string              `json:"sourceChain"`
	Limit       codec.Uint32        `json:"limit"`
	StartIndex  Index               `json:"startIndex"`
	Encoding    formatting.Encoding `json:"encoding"`
}

// GetUTXOsReply defines the GetUTXOs replies returned from the API
// JSON field names match RPC conventions for compatibility across services.
type GetUTXOsReply struct {
	// Number of UTXOs returned
	NumFetched codec.Uint64 `json:"numFetched"`
	// The UTXOs
	UTXOs []string `json:"utxos"`
	// The last UTXO that was returned, and the address it corresponds to.
	// Used for pagination. To get the rest of the UTXOs, call GetUTXOs
	// again and set [StartIndex] to this value.
	EndIndex Index `json:"endIndex"`
	// Encoding specifies the encoding format the UTXOs are returned in
	Encoding formatting.Encoding `json:"encoding"`
}

// JSONTxID contains the ID of a transaction.
// This is duplicated here for UTXO tooling convenience.
type JSONTxID struct {
	TxID ids.ID `json:"txID"`
}
