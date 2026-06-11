// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import "github.com/luxfi/zap"

// XVMBaseTx is the X-chain BaseTx wire envelope. It is the ZAP-native
// replacement for the reflection-encoded `xvm/txs.BaseTx` (which embedded
// `utxo.BaseTx` with `serialize:"true"` tags and round-tripped through
// pcodecs.Manager).
//
// Fields:
//
//	NetworkID    uint32  — network this chain lives on
//	BlockchainID 32B     — chain id (replay-protection)
//	Outs         []TransferableOutput  (each carries its own fx TypeKind)
//	Ins          []TransferableInput   (each carries its own fx TypeKind)
//	Memo         bytes   — arbitrary, up to MaxMemoSize on the verifier
//
// Outs/Ins are variable-stride byte envelopes (each carries its own
// TypeKind+ShapeKind+ZAP message of independent length). The list is
// encoded as `Count uint32 + Bytes (concatenated envelopes)` — the same
// pattern SignedTx uses for its Credentials list. Walking is O(i)
// because each ZAP envelope carries its own length in the wire header.
//
// Fixed-section layout (size 68 bytes; 4 + 32 + 4 + 8 + 4 + 8 + 8):
//
//	NetworkID    uint32 @ 0
//	BlockchainID 32B    @ 4
//	OutsCount    uint32 @ 36
//	OutsBytes    bytes  @ 40   (8 bytes — relOffset + length)
//	InsCount     uint32 @ 48
//	InsBytes     bytes  @ 52   (8 bytes — relOffset + length)
//	Memo         bytes  @ 60   (8 bytes — relOffset + length)
const (
	OffsetXVMBaseTx_NetworkID    = 0  // uint32
	OffsetXVMBaseTx_BlockchainID = 4  // 32B
	OffsetXVMBaseTx_OutsCount    = 36 // uint32
	OffsetXVMBaseTx_OutsBytes    = 40 // bytes (8 bytes)
	OffsetXVMBaseTx_InsCount     = 48 // uint32
	OffsetXVMBaseTx_InsBytes     = 52 // bytes (8 bytes)
	OffsetXVMBaseTx_Memo         = 60 // bytes (8 bytes)
	SizeXVMBaseTx                = 68
)

// XVMBaseTx is the zero-copy typed accessor.
//
// READ-ONLY: every accessor aliases the underlying ZAP buffer. Mutation
// corrupts any TxID = hash(buffer) computed downstream. Use append(
// []byte(nil), ...) to take ownership when handing bytes to another
// goroutine.
type XVMBaseTx struct {
	b   []byte
	msg *zap.Message
	obj zap.Object
}

// NetworkID returns the network id.
func (t XVMBaseTx) NetworkID() uint32 {
	return t.obj.Uint32(OffsetXVMBaseTx_NetworkID)
}

// BlockchainID returns the 32-byte chain id.
func (t XVMBaseTx) BlockchainID() [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = t.obj.Uint8(OffsetXVMBaseTx_BlockchainID + i)
	}
	return out
}

// OutsCount returns the number of transferable outputs.
func (t XVMBaseTx) OutsCount() uint32 {
	return t.obj.Uint32(OffsetXVMBaseTx_OutsCount)
}

// OutsBytes returns the concatenated TransferableOutput envelopes blob.
// Each entry is a self-describing wire envelope; see OutAt for the
// index walk.
//
// READ-ONLY: aliases the underlying buffer.
func (t XVMBaseTx) OutsBytes() []byte {
	return t.obj.Bytes(OffsetXVMBaseTx_OutsBytes)
}

// OutAt parses the i'th TransferableOutput envelope.
func (t XVMBaseTx) OutAt(i uint32) (TransferOutput, error) {
	env, err := nthEnvelope(t.OutsBytes(), t.OutsCount(), i)
	if err != nil {
		return TransferOutput{}, err
	}
	return WrapTransferOutput(env)
}

// InsCount returns the number of transferable inputs.
func (t XVMBaseTx) InsCount() uint32 {
	return t.obj.Uint32(OffsetXVMBaseTx_InsCount)
}

// InsBytes returns the concatenated TransferableInput envelopes blob.
//
// READ-ONLY: aliases the underlying buffer.
func (t XVMBaseTx) InsBytes() []byte {
	return t.obj.Bytes(OffsetXVMBaseTx_InsBytes)
}

// InAt parses the i'th TransferableInput envelope.
func (t XVMBaseTx) InAt(i uint32) (TransferInput, error) {
	env, err := nthEnvelope(t.InsBytes(), t.InsCount(), i)
	if err != nil {
		return TransferInput{}, err
	}
	return WrapTransferInput(env)
}

// Memo returns the memo bytes.
//
// READ-ONLY: aliases the underlying buffer.
func (t XVMBaseTx) Memo() []byte {
	return t.obj.Bytes(OffsetXVMBaseTx_Memo)
}

// Bytes returns the full wire envelope (2-byte discriminator prefix +
// ZAP message). Stable across calls — backed by the originally-parsed
// buffer. ZAP-native: no marshal step, no allocation.
func (t XVMBaseTx) Bytes() []byte {
	return t.b
}

// IsZero reports whether the accessor wraps a parsed message.
func (t XVMBaseTx) IsZero() bool { return t.msg == nil }

// WrapXVMBaseTx parses an XVM BaseTx wire envelope into a typed accessor.
//
// Returns ErrShortEnvelope when the buffer is shorter than the 2-byte
// discriminator prefix; ErrWrongShapeKind when the prefix names a
// non-XVMBaseTx shape.
func WrapXVMBaseTx(b []byte) (XVMBaseTx, error) {
	_, sk, zapBytes, err := readEnvelopePrefix(b)
	if err != nil {
		return XVMBaseTx{}, err
	}
	if sk != ShapeKindXVMBaseTx {
		return XVMBaseTx{}, ErrWrongShapeKind
	}
	msg, err := zap.Parse(zapBytes)
	if err != nil {
		return XVMBaseTx{}, err
	}
	return XVMBaseTx{b: b, msg: msg, obj: msg.Root()}, nil
}

// XVMBaseTxInput is the constructor input. Outs/Ins are already-built
// TransferableOutput / TransferableInput envelopes (from
// NewTransferOutput / NewTransferInput) — the constructor concatenates
// them verbatim.
type XVMBaseTxInput struct {
	NetworkID    uint32
	BlockchainID [32]byte
	Outs         [][]byte
	Ins          [][]byte
	Memo         []byte
}

// NewXVMBaseTx builds an XVM BaseTx wire envelope.
func NewXVMBaseTx(in XVMBaseTxInput) []byte {
	outsTotal := 0
	for _, o := range in.Outs {
		outsTotal += len(o)
	}
	insTotal := 0
	for _, i := range in.Ins {
		insTotal += len(i)
	}
	outsBlob := make([]byte, 0, outsTotal)
	for _, o := range in.Outs {
		outsBlob = append(outsBlob, o...)
	}
	insBlob := make([]byte, 0, insTotal)
	for _, i := range in.Ins {
		insBlob = append(insBlob, i...)
	}

	capEstimate := zap.HeaderSize + SizeXVMBaseTx + outsTotal + insTotal + len(in.Memo) + 64
	b := zap.NewBuilder(capEstimate)

	ob := b.StartObject(SizeXVMBaseTx)
	ob.SetUint32(OffsetXVMBaseTx_NetworkID, in.NetworkID)
	for i := 0; i < 32; i++ {
		ob.SetUint8(OffsetXVMBaseTx_BlockchainID+i, in.BlockchainID[i])
	}
	ob.SetUint32(OffsetXVMBaseTx_OutsCount, uint32(len(in.Outs)))
	ob.SetBytes(OffsetXVMBaseTx_OutsBytes, outsBlob)
	ob.SetUint32(OffsetXVMBaseTx_InsCount, uint32(len(in.Ins)))
	ob.SetBytes(OffsetXVMBaseTx_InsBytes, insBlob)
	ob.SetBytes(OffsetXVMBaseTx_Memo, in.Memo)
	ob.FinishAsRoot()
	return writeEnvelopePrefix(TypeKindReserved, ShapeKindXVMBaseTx, b.Finish())
}

// nthEnvelope returns the i'th envelope from a concatenated blob of
// (TypeKind+ShapeKind+ZAP message) wire envelopes. The per-envelope ZAP
// header carries the envelope's own length so the walk is O(i).
//
// This mirrors SignedTx.CredentialAt's parser — same wire convention.
func nthEnvelope(blob []byte, count uint32, i uint32) ([]byte, error) {
	if i >= count {
		return nil, ErrWrongShapeKind
	}
	cursor := 0
	for k := uint32(0); k <= i; k++ {
		if cursor+EnvelopePrefix > len(blob) {
			return nil, ErrShortEnvelope
		}
		zapStart := cursor + EnvelopePrefix
		if zapStart+zap.HeaderSize > len(blob) {
			return nil, ErrShortEnvelope
		}
		// ZAP header Size is little-endian uint32 at offset 12.
		zapSize := int(blob[zapStart+12]) |
			int(blob[zapStart+13])<<8 |
			int(blob[zapStart+14])<<16 |
			int(blob[zapStart+15])<<24
		envEnd := zapStart + zapSize
		if envEnd > len(blob) {
			return nil, ErrShortEnvelope
		}
		if k == i {
			return blob[cursor:envEnd], nil
		}
		cursor = envEnd
	}
	return nil, ErrWrongShapeKind
}
