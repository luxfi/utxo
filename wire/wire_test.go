// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"bytes"
	"testing"

	"github.com/luxfi/ids"
)

func TestDiscriminator_Prefix(t *testing.T) {
	tk, sk, zapBytes, err := readEnvelopePrefix([]byte{0x01, 0x02, 0xAA, 0xBB})
	if err != nil {
		t.Fatalf("readEnvelopePrefix: %v", err)
	}
	if tk != TypeKindSecp256k1 {
		t.Errorf("TypeKind: got %x, want %x", tk, TypeKindSecp256k1)
	}
	if sk != ShapeKindTransferInput {
		t.Errorf("ShapeKind: got %x, want %x", sk, ShapeKindTransferInput)
	}
	if !bytes.Equal(zapBytes, []byte{0xAA, 0xBB}) {
		t.Errorf("zapBytes: got %x, want %x", zapBytes, []byte{0xAA, 0xBB})
	}

	// Too-short buffer rejected.
	if _, _, _, err := readEnvelopePrefix([]byte{0x01}); err != ErrShortEnvelope {
		t.Errorf("short buffer: got err=%v, want ErrShortEnvelope", err)
	}
}

func TestOutputOwners_RoundTrip(t *testing.T) {
	addrs := []ids.ShortID{
		{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
	}
	in := OutputOwnersInput{
		Locktime:  1234567890,
		Threshold: 2,
		Addresses: addrs,
	}
	envelope := NewOutputOwners(in)

	got, err := WrapOutputOwners(envelope)
	if err != nil {
		t.Fatalf("WrapOutputOwners: %v", err)
	}
	if got.Locktime() != in.Locktime {
		t.Errorf("Locktime: got %d, want %d", got.Locktime(), in.Locktime)
	}
	if got.Threshold() != in.Threshold {
		t.Errorf("Threshold: got %d, want %d", got.Threshold(), in.Threshold)
	}
	addrList := got.AddressList()
	if addrList.Len() != len(addrs) {
		t.Fatalf("AddressList.Len: got %d, want %d", addrList.Len(), len(addrs))
	}
	for i, want := range addrs {
		if addrList.At(i) != want {
			t.Errorf("AddressList[%d]: got %x, want %x", i, addrList.At(i), want)
		}
	}
	if err := got.SyntacticVerify(); err != nil {
		t.Errorf("SyntacticVerify: %v", err)
	}
}

func TestOutputOwners_SyntacticVerify(t *testing.T) {
	addr := ids.ShortID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	cases := []struct {
		name string
		in   OutputOwnersInput
		want error
	}{
		{"empty addrs", OutputOwnersInput{Threshold: 1}, ErrOwnerAddrsEmpty},
		{"zero threshold", OutputOwnersInput{Threshold: 0, Addresses: []ids.ShortID{addr}}, ErrOwnerThresholdZero},
		{"threshold exceeds", OutputOwnersInput{Threshold: 2, Addresses: []ids.ShortID{addr}}, ErrOwnerThresholdExceedsAddrs},
		{"zero addr", OutputOwnersInput{Threshold: 1, Addresses: []ids.ShortID{{}}}, ErrOwnerAddrZero},
		{"valid", OutputOwnersInput{Threshold: 1, Addresses: []ids.ShortID{addr}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envelope := NewOutputOwners(tc.in)
			o, err := WrapOutputOwners(envelope)
			if err != nil {
				t.Fatalf("WrapOutputOwners: %v", err)
			}
			got := o.SyntacticVerify()
			if got != tc.want {
				t.Errorf("SyntacticVerify: got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPChainOwner_RoundTrip(t *testing.T) {
	addrs := []ids.ShortID{
		{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
	}
	in := PChainOwnerInput{Threshold: 1, Addresses: addrs}
	envelope := NewPChainOwner(in)

	got, err := WrapPChainOwner(envelope)
	if err != nil {
		t.Fatalf("WrapPChainOwner: %v", err)
	}
	if got.Threshold() != in.Threshold {
		t.Errorf("Threshold: got %d, want %d", got.Threshold(), in.Threshold)
	}
	if got.AddressList().Len() != len(addrs) {
		t.Errorf("AddressList.Len: got %d, want %d", got.AddressList().Len(), len(addrs))
	}
	if err := got.SyntacticVerify(); err != nil {
		t.Errorf("SyntacticVerify: %v", err)
	}
}

func TestUTXO_RoundTrip(t *testing.T) {
	// Build an inner TransferOutput first.
	addr := ids.ShortID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	innerOutput := NewTransferOutput(TransferOutputInput{
		TypeKind:  TypeKindSecp256k1,
		Amount:    1_000_000,
		Locktime:  0,
		Threshold: 1,
		Addresses: []ids.ShortID{addr},
	})

	txID := ids.ID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	assetID := ids.ID{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	in := UTXOInput{
		TxID:        txID,
		OutputIndex: 7,
		AssetID:     assetID,
		Output:      innerOutput,
	}
	envelope := NewUTXO(in)

	got, err := WrapUTXO(envelope)
	if err != nil {
		t.Fatalf("WrapUTXO: %v", err)
	}
	if got.TxID() != txID {
		t.Errorf("TxID: got %x, want %x", got.TxID(), txID)
	}
	if got.OutputIndex() != 7 {
		t.Errorf("OutputIndex: got %d, want 7", got.OutputIndex())
	}
	if got.AssetID() != assetID {
		t.Errorf("AssetID: got %x, want %x", got.AssetID(), assetID)
	}
	outBytes := got.OutputBytes()
	if !bytes.Equal(outBytes, innerOutput) {
		t.Errorf("OutputBytes mismatch")
	}
	tk, sk := got.OutputDiscriminator()
	if tk != TypeKindSecp256k1 {
		t.Errorf("OutputDiscriminator TypeKind: got %x, want %x", tk, TypeKindSecp256k1)
	}
	if sk != ShapeKindTransferOutput {
		t.Errorf("OutputDiscriminator ShapeKind: got %x, want %x", sk, ShapeKindTransferOutput)
	}

	// Round-trip the inner output.
	innerGot, err := WrapTransferOutput(outBytes)
	if err != nil {
		t.Fatalf("WrapTransferOutput inner: %v", err)
	}
	if innerGot.Amount() != 1_000_000 {
		t.Errorf("inner Amount: got %d, want 1_000_000", innerGot.Amount())
	}
}

func TestTransferOutput_AllFxs(t *testing.T) {
	addr := ids.ShortID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	for _, tk := range []TypeKind{
		TypeKindSecp256k1, TypeKindMLDSA, TypeKindSLHDSA,
		TypeKindEd25519, TypeKindSecp256r1, TypeKindSchnorr,
	} {
		t.Run(tk.String(), func(t *testing.T) {
			in := TransferOutputInput{
				TypeKind:  tk,
				Amount:    42,
				Locktime:  100,
				Threshold: 1,
				Addresses: []ids.ShortID{addr},
			}
			envelope := NewTransferOutput(in)
			got, err := WrapTransferOutput(envelope)
			if err != nil {
				t.Fatalf("WrapTransferOutput: %v", err)
			}
			if got.TypeKind() != tk {
				t.Errorf("TypeKind: got %x, want %x", got.TypeKind(), tk)
			}
			if got.Amount() != 42 {
				t.Errorf("Amount: got %d, want 42", got.Amount())
			}
			if got.Locktime() != 100 {
				t.Errorf("Locktime: got %d, want 100", got.Locktime())
			}
			if got.Threshold() != 1 {
				t.Errorf("Threshold: got %d, want 1", got.Threshold())
			}
		})
	}
}

func TestTransferInput_RoundTrip(t *testing.T) {
	in := TransferInputInput{
		TypeKind:   TypeKindSecp256k1,
		Amount:     500,
		SigIndices: []uint32{0, 2, 5, 7},
	}
	envelope := NewTransferInput(in)
	got, err := WrapTransferInput(envelope)
	if err != nil {
		t.Fatalf("WrapTransferInput: %v", err)
	}
	if got.Amount() != 500 {
		t.Errorf("Amount: got %d, want 500", got.Amount())
	}
	if got.SigIndicesLen() != 4 {
		t.Errorf("SigIndicesLen: got %d, want 4", got.SigIndicesLen())
	}
	sigs := got.SigIndices()
	if len(sigs) != 4 {
		t.Fatalf("SigIndices len: got %d, want 4", len(sigs))
	}
	want := []uint32{0, 2, 5, 7}
	for i, w := range want {
		if sigs[i] != w {
			t.Errorf("SigIndices[%d]: got %d, want %d", i, sigs[i], w)
		}
	}
}

func TestMintOutput_RoundTrip(t *testing.T) {
	addr := ids.ShortID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	in := MintOutputInput{
		TypeKind:  TypeKindMLDSA,
		Locktime:  9999,
		Threshold: 1,
		Addresses: []ids.ShortID{addr},
	}
	envelope := NewMintOutput(in)
	got, err := WrapMintOutput(envelope)
	if err != nil {
		t.Fatalf("WrapMintOutput: %v", err)
	}
	if got.TypeKind() != TypeKindMLDSA {
		t.Errorf("TypeKind: got %x, want %x", got.TypeKind(), TypeKindMLDSA)
	}
	if got.Locktime() != 9999 {
		t.Errorf("Locktime: got %d, want 9999", got.Locktime())
	}
	if got.Threshold() != 1 {
		t.Errorf("Threshold: got %d, want 1", got.Threshold())
	}
	if err := got.SyntacticVerify(); err != nil {
		t.Errorf("SyntacticVerify: %v", err)
	}
}

func TestCredential_RoundTrip_Classical(t *testing.T) {
	// 2 secp256k1 sigs of 65 bytes each.
	sigs := make([]byte, 0, 130)
	for i := 0; i < 130; i++ {
		sigs = append(sigs, byte(i))
	}
	in := CredentialInput{
		TypeKind:      TypeKindSecp256k1,
		SecurityLevel: 0,
		Signatures:    sigs,
	}
	envelope := NewCredential(in)
	got, err := WrapCredential(envelope)
	if err != nil {
		t.Fatalf("WrapCredential: %v", err)
	}
	if got.TypeKind() != TypeKindSecp256k1 {
		t.Errorf("TypeKind: got %x, want %x", got.TypeKind(), TypeKindSecp256k1)
	}
	if got.SecurityLevel() != 0 {
		t.Errorf("SecurityLevel: got %d, want 0", got.SecurityLevel())
	}
	if !bytes.Equal(got.SignatureBytes(), sigs) {
		t.Errorf("SignatureBytes mismatch")
	}
	if got.SignatureCount(65) != 2 {
		t.Errorf("SignatureCount(65): got %d, want 2", got.SignatureCount(65))
	}
	sig0 := got.SignatureAt(0, 65)
	if !bytes.Equal(sig0, sigs[:65]) {
		t.Errorf("SignatureAt(0,65) mismatch")
	}
	sig1 := got.SignatureAt(1, 65)
	if !bytes.Equal(sig1, sigs[65:]) {
		t.Errorf("SignatureAt(1,65) mismatch")
	}
}

func TestCredential_RoundTrip_PQ(t *testing.T) {
	// Simulate 1 ML-DSA-65 signature (3309 bytes).
	const mlDSA65SigLen = 3309
	sigs := make([]byte, mlDSA65SigLen)
	for i := range sigs {
		sigs[i] = byte(i)
	}
	in := CredentialInput{
		TypeKind:      TypeKindMLDSA,
		SecurityLevel: 1, // ML-DSA-65
		Signatures:    sigs,
	}
	envelope := NewCredential(in)
	got, err := WrapCredential(envelope)
	if err != nil {
		t.Fatalf("WrapCredential: %v", err)
	}
	if got.TypeKind() != TypeKindMLDSA {
		t.Errorf("TypeKind: got %x, want %x", got.TypeKind(), TypeKindMLDSA)
	}
	if got.SecurityLevel() != 1 {
		t.Errorf("SecurityLevel: got %d, want 1", got.SecurityLevel())
	}
	if got.SignatureCount(mlDSA65SigLen) != 1 {
		t.Errorf("SignatureCount: got %d, want 1", got.SignatureCount(mlDSA65SigLen))
	}
}

func TestMintOperation_RoundTrip(t *testing.T) {
	addr := ids.ShortID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	mintOut := NewMintOutput(MintOutputInput{
		TypeKind:  TypeKindSecp256k1,
		Locktime:  0,
		Threshold: 1,
		Addresses: []ids.ShortID{addr},
	})
	transferOut := NewTransferOutput(TransferOutputInput{
		TypeKind:  TypeKindSecp256k1,
		Amount:    100,
		Locktime:  0,
		Threshold: 1,
		Addresses: []ids.ShortID{addr},
	})
	in := MintOperationInput{
		TypeKind:       TypeKindSecp256k1,
		SigIndices:     []uint32{0},
		MintOutput:     mintOut,
		TransferOutput: transferOut,
	}
	envelope := NewMintOperation(in)
	got, err := WrapMintOperation(envelope)
	if err != nil {
		t.Fatalf("WrapMintOperation: %v", err)
	}
	if got.TypeKind() != TypeKindSecp256k1 {
		t.Errorf("TypeKind: got %x, want %x", got.TypeKind(), TypeKindSecp256k1)
	}
	if len(got.SigIndices()) != 1 {
		t.Errorf("SigIndices.len: got %d, want 1", len(got.SigIndices()))
	}
	mo, err := WrapMintOutput(got.MintOutputBytes())
	if err != nil {
		t.Fatalf("WrapMintOutput inner: %v", err)
	}
	if mo.Threshold() != 1 {
		t.Errorf("inner MintOutput Threshold: got %d, want 1", mo.Threshold())
	}
	to, err := WrapTransferOutput(got.TransferOutputBytes())
	if err != nil {
		t.Fatalf("WrapTransferOutput inner: %v", err)
	}
	if to.Amount() != 100 {
		t.Errorf("inner TransferOutput Amount: got %d, want 100", to.Amount())
	}
}

func TestAttestationOutput_RoundTrip(t *testing.T) {
	pk1 := make([]byte, BLS12381PubKeyLen)
	pk2 := make([]byte, BLS12381PubKeyLen)
	for i := range pk1 {
		pk1[i] = byte(i)
	}
	for i := range pk2 {
		pk2[i] = byte(0xFF - i)
	}
	in := AttestationOutputInput{
		AttestedHash: [BLS12381AttestedHashLen]byte{1, 2, 3},
		Threshold:    2,
		PubKeys:      [][]byte{pk1, pk2},
	}
	envelope := NewAttestationOutput(in)
	got, err := WrapAttestationOutput(envelope)
	if err != nil {
		t.Fatalf("WrapAttestationOutput: %v", err)
	}
	hash := got.AttestedHash()
	if hash[0] != 1 || hash[1] != 2 || hash[2] != 3 {
		t.Errorf("AttestedHash[:3]: got %v, want [1 2 3]", hash[:3])
	}
	if got.Threshold() != 2 {
		t.Errorf("Threshold: got %d, want 2", got.Threshold())
	}
	pks := got.PubKeys()
	if len(pks) != 2 {
		t.Fatalf("PubKeys len: got %d, want 2", len(pks))
	}
	if !bytes.Equal(pks[0], pk1) {
		t.Errorf("PubKeys[0] mismatch")
	}
	if !bytes.Equal(pks[1], pk2) {
		t.Errorf("PubKeys[1] mismatch")
	}
}

func TestAttestationInput_RoundTrip(t *testing.T) {
	bitmap := []byte{0x05, 0x80} // bits 0, 2, 15 set
	in := AttestationInputInput{SignerBitmap: bitmap}
	envelope := NewAttestationInput(in)
	got, err := WrapAttestationInput(envelope)
	if err != nil {
		t.Fatalf("WrapAttestationInput: %v", err)
	}
	if !bytes.Equal(got.SignerBitmap(), bitmap) {
		t.Errorf("SignerBitmap: got %x, want %x", got.SignerBitmap(), bitmap)
	}
}

func TestSignedTx_RoundTrip(t *testing.T) {
	// Build two credentials.
	cred1 := NewCredential(CredentialInput{
		TypeKind:      TypeKindSecp256k1,
		SecurityLevel: 0,
		Signatures:    bytes.Repeat([]byte{0xAA}, 65),
	})
	cred2 := NewCredential(CredentialInput{
		TypeKind:      TypeKindSecp256k1,
		SecurityLevel: 0,
		Signatures:    bytes.Repeat([]byte{0xBB}, 65),
	})

	unsigned := []byte("imagine this is a TxKind-prefixed zap_native unsigned tx blob ...")

	in := SignedTxInput{
		UnsignedBytes: unsigned,
		Credentials:   [][]byte{cred1, cred2},
	}
	envelope := NewSignedTx(in)
	got, err := WrapSignedTx(envelope)
	if err != nil {
		t.Fatalf("WrapSignedTx: %v", err)
	}
	if !bytes.Equal(got.UnsignedBytes(), unsigned) {
		t.Errorf("UnsignedBytes mismatch")
	}
	if got.CredentialCount() != 2 {
		t.Errorf("CredentialCount: got %d, want 2", got.CredentialCount())
	}

	all, err := got.AllCredentials()
	if err != nil {
		t.Fatalf("AllCredentials: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("AllCredentials len: got %d, want 2", len(all))
	}
	if all[0].TypeKind() != TypeKindSecp256k1 {
		t.Errorf("cred[0].TypeKind: got %x, want %x", all[0].TypeKind(), TypeKindSecp256k1)
	}
	sig0 := all[0].SignatureAt(0, 65)
	if !bytes.Equal(sig0, bytes.Repeat([]byte{0xAA}, 65)) {
		t.Errorf("cred[0] sig mismatch")
	}
	sig1 := all[1].SignatureAt(0, 65)
	if !bytes.Equal(sig1, bytes.Repeat([]byte{0xBB}, 65)) {
		t.Errorf("cred[1] sig mismatch")
	}

	// CredentialAt(i) for individual access.
	c0, err := got.CredentialAt(0)
	if err != nil {
		t.Fatalf("CredentialAt(0): %v", err)
	}
	if c0.TypeKind() != TypeKindSecp256k1 {
		t.Errorf("CredentialAt(0).TypeKind: got %x, want %x", c0.TypeKind(), TypeKindSecp256k1)
	}
}

// TypeKind.String — small helper for diagnostic test output.
func (t TypeKind) String() string {
	switch t {
	case TypeKindReserved:
		return "TypeKindReserved"
	case TypeKindSecp256k1:
		return "TypeKindSecp256k1"
	case TypeKindMLDSA:
		return "TypeKindMLDSA"
	case TypeKindSLHDSA:
		return "TypeKindSLHDSA"
	case TypeKindEd25519:
		return "TypeKindEd25519"
	case TypeKindSecp256r1:
		return "TypeKindSecp256r1"
	case TypeKindSchnorr:
		return "TypeKindSchnorr"
	case TypeKindBLS12381:
		return "TypeKindBLS12381"
	default:
		return "TypeKindUnknown"
	}
}
