package crypto

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
)

func pemBlock(blockType string, value any) []byte {
	der, err := asn1.Marshal(value)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func privatePEM(t *testing.T, algorithm algorithmIdentifier, version int, choice asn1.RawValue) []byte {
	t.Helper()
	inner, err := asn1.Marshal(choice)
	if err != nil {
		t.Fatal(err)
	}
	return pemBlock("PRIVATE KEY", privateKeyInfo{Version: version, Algorithm: algorithm, PrivateKey: inner})
}

func TestMLDSAStandardKeyFormatsRoundTrip(t *testing.T) {
	d, err := ml_dsa_87.NewMLDSA87FromHexSeed(strings.Repeat("12", ml_dsa_87.SEED_BYTES))
	if err != nil {
		t.Fatal(err)
	}
	pk := d.GetPK()
	publicPEM, err := MarshalMLDSAPublicKeyPEM(pk[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(publicPEM, []byte("-----BEGIN PUBLIC KEY-----\n")) {
		t.Fatalf("unexpected public key label: %q", publicPEM[:40])
	}
	parsedPK, err := ParseMLDSAPublicKeyPEM(publicPEM)
	if err != nil || !bytes.Equal(parsedPK, pk[:]) {
		t.Fatalf("public key round trip failed: %v", err)
	}

	seed := bytes.Repeat([]byte{0x12}, ml_dsa_87.SEED_BYTES)
	privatePEM, err := MarshalMLDSAPrivateKeyPEM(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(privatePEM, []byte("-----BEGIN PRIVATE KEY-----\n")) {
		t.Fatalf("unexpected private key label: %q", privatePEM[:40])
	}
	parsedSeed, expanded, err := ParseMLDSAPrivateKeyPEM(privatePEM)
	if err != nil || !bytes.Equal(parsedSeed, seed) || expanded != nil {
		t.Fatalf("private key round trip failed: seed=%x expanded=%d err=%v", parsedSeed, len(expanded), err)
	}
	if DetectAlgorithmFromPEM(string(publicPEM)) != AlgorithmMLDSA || DetectAlgorithmFromPEM(string(privatePEM)) != AlgorithmMLDSA {
		t.Fatal("standard ML-DSA key algorithm was not detected from its OID")
	}
}

func TestMLDSAPublicKeyFormatRejectsMalformedInput(t *testing.T) {
	if _, err := MarshalMLDSAPublicKeyPEM([]byte{1}); err == nil {
		t.Fatal("expected public key length error")
	}
	cases := [][]byte{
		[]byte("not pem"),
		append(pemBlock("PUBLIC KEY", subjectPublicKeyInfo{Algorithm: algorithmIdentifier{Algorithm: oidMLDSA87}}), []byte("trailing")...),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0xff}}),
		pemBlock("PUBLIC KEY", subjectPublicKeyInfo{Algorithm: algorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}, PublicKey: asn1.BitString{Bytes: make([]byte, ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES), BitLength: ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES * 8}}),
		pemBlock("PUBLIC KEY", subjectPublicKeyInfo{Algorithm: algorithmIdentifier{Algorithm: oidMLDSA87, Parameters: asn1.RawValue{FullBytes: []byte{0x05, 0x00}}}, PublicKey: asn1.BitString{Bytes: make([]byte, ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES), BitLength: ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES * 8}}),
		pemBlock("PUBLIC KEY", subjectPublicKeyInfo{Algorithm: algorithmIdentifier{Algorithm: oidMLDSA87}, PublicKey: asn1.BitString{Bytes: []byte{1}, BitLength: 8}}),
	}
	for i, input := range cases {
		if _, err := ParseMLDSAPublicKeyPEM(input); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestMLDSAPrivateKeyChoicesAndRejections(t *testing.T) {
	if _, err := MarshalMLDSAPrivateKeyPEM([]byte{1}); err == nil {
		t.Fatal("expected seed length error")
	}
	seed := bytes.Repeat([]byte{0x23}, ml_dsa_87.SEED_BYTES)
	d, err := ml_dsa_87.NewMLDSA87FromSeed(*(*[ml_dsa_87.SEED_BYTES]uint8)(seed))
	if err != nil {
		t.Fatal(err)
	}
	sk := d.GetSK()
	algorithm := algorithmIdentifier{Algorithm: oidMLDSA87}

	expandedPEM := privatePEM(t, algorithm, 0, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: sk[:]})
	parsedSeed, parsedExpanded, err := ParseMLDSAPrivateKeyPEM(expandedPEM)
	if err != nil || parsedSeed != nil || !bytes.Equal(parsedExpanded, sk[:]) {
		t.Fatalf("expanded key parse failed: %v", err)
	}
	bothDER, err := asn1.Marshal(struct {
		Seed        []byte
		ExpandedKey []byte
	}{seed, sk[:]})
	if err != nil {
		t.Fatal(err)
	}
	bothPEM := privatePEM(t, algorithm, 0, asn1.RawValue{FullBytes: bothDER})
	parsedSeed, parsedExpanded, err = ParseMLDSAPrivateKeyPEM(bothPEM)
	if err != nil || !bytes.Equal(parsedSeed, seed) || !bytes.Equal(parsedExpanded, sk[:]) {
		t.Fatalf("combined key parse failed: %v", err)
	}

	inconsistent := append([]byte(nil), sk[:]...)
	inconsistent[0] ^= 1
	badBothDER, _ := asn1.Marshal(struct {
		Seed        []byte
		ExpandedKey []byte
	}{seed, inconsistent})

	cases := [][]byte{
		[]byte("not pem"),
		append(privatePEM(t, algorithm, 0, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: seed}), []byte("trailing")...),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0xff}}),
		privatePEM(t, algorithm, 1, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: seed}),
		privatePEM(t, algorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}, 0, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: seed}),
		privatePEM(t, algorithmIdentifier{Algorithm: oidMLDSA87, Parameters: asn1.RawValue{FullBytes: []byte{0x05, 0x00}}}, 0, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: seed}),
		pemBlock("PRIVATE KEY", privateKeyInfo{Version: 0, Algorithm: algorithm, PrivateKey: []byte{0xff}}),
		privatePEM(t, algorithm, 0, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: []byte{1}}),
		privatePEM(t, algorithm, 0, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte{1}}),
		privatePEM(t, algorithm, 0, asn1.RawValue{FullBytes: []byte{0x30, 0x00}}),
		privatePEM(t, algorithm, 0, asn1.RawValue{FullBytes: badBothDER}),
		privatePEM(t, algorithm, 0, asn1.RawValue{Tag: asn1.TagInteger, Bytes: []byte{1}}),
	}
	for i, input := range cases {
		if _, _, err := ParseMLDSAPrivateKeyPEM(input); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}
