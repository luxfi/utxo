// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package utxo

import (
	"github.com/luxfi/runtime"
	"github.com/luxfi/vm/components/verify"
)

var (
	_ verify.State    = (*TestState)(nil)
	_ TransferableOut = (*TestTransferable)(nil)
	_ Addressable     = (*TestAddressable)(nil)
)

type TestState struct {
	verify.IsState `serialize:"-" json:"-"`

	Err error `serialize:"-" json:"-"`
}

func (*TestState) InitRuntime(*runtime.Runtime) {}

func (v *TestState) Verify() error {
	return v.Err
}

type TestTransferable struct {
	TestState

	Val uint64 `serialize:"true"`
}

func (*TestTransferable) InitRuntime(*runtime.Runtime) {}

func (t *TestTransferable) Amount() uint64 {
	return t.Val
}

func (*TestTransferable) Cost() (uint64, error) {
	return 0, nil
}

type TestAddressable struct {
	TestTransferable `serialize:"true"`

	Addrs [][]byte `serialize:"true"`
}

func (a *TestAddressable) Addresses() [][]byte {
	return a.Addrs
}

// Bytes satisfies the wireSerializable contract that UTXO.WireBytes requires.
// Test-only — returns an opaque envelope keyed on Val + concatenated addrs.
// Production fxs primitives produce the real (TypeKind+ShapeKind+ZAP) envelope.
func (a *TestAddressable) Bytes() []byte {
	out := make([]byte, 0, 8+len(a.Addrs)*32)
	for i := 0; i < 8; i++ {
		out = append(out, byte(a.Val>>(i*8)))
	}
	for _, addr := range a.Addrs {
		out = append(out, addr...)
	}
	return out
}
