// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package utxo

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// A UTXOID is what a balance answer is made of, and its TxID is an ids.ID —
// [32]byte, which is bytes_fixed[32] on the ZAP wire and what a DERIVED codec
// refuses to carry. zap_gen.go is why it crosses at all; this is that it
// arrives whole, and that the JSON mainnet answers on did not move.
func TestTheIDCrossesAndTheJSONDoesNotMove(t *testing.T) {
	require := require.New(t)

	sent := UTXOID{TxID: ids.ID{0: 0xf0, 15: 0x5a, 31: 0x0d}, OutputIndex: 7}

	enc, err := sent.MarshalZAP()
	require.NoError(err)
	var back UTXOID
	require.NoError(back.UnmarshalZAP(enc))
	require.Equal(sent.TxID, back.TxID)
	require.Equal(sent.OutputIndex, back.OutputIndex)

	// The same answer through a shape carrying the same tags and no codec.
	// encoding/json reads tags and knows nothing about MarshalZAP, so the two
	// have to be one set of bytes.
	is, err := json.Marshal(sent)
	require.NoError(err)
	was, err := json.Marshal(struct {
		TxID        ids.ID `json:"txID"`
		OutputIndex uint32 `json:"outputIndex"`
	}{sent.TxID, sent.OutputIndex})
	require.NoError(err)
	require.Equal(string(was), string(is))
}
