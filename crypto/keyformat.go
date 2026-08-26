package crypto

import (
	"bytes"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
)

// oidMLDSA87 is id-ml-dsa-87 from RFC 9881.
var oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type privateKeyInfo struct {
	Version    int
	Algorithm  algorithmIdentifier
	PrivateKey []byte
}

// MarshalMLDSAPublicKeyPEM encodes an ML-DSA-87 public key as the RFC 9881
// SubjectPublicKeyInfo carried by the RFC 7468 PUBLIC KEY textual format.
func MarshalMLDSAPublicKeyPEM(publicKey []byte) ([]byte, error) {
	if len(publicKey) != ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES {
		return nil, fmt.Errorf("invalid ML-DSA-87 public key length: got %d, want %d", len(publicKey), ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES)
	}
	der, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{Algorithm: oidMLDSA87},
		PublicKey: asn1.BitString{Bytes: publicKey, BitLength: len(publicKey) * 8},
	})
	if err != nil {
		//coverage:ignore reason=defensive-unreachable
		//rationale: the fixed ASN.1 structure contains only values accepted by encoding/asn1
		return nil, fmt.Errorf("encode ML-DSA-87 public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParseMLDSAPublicKeyPEM decodes an RFC 9881 ML-DSA-87 SubjectPublicKeyInfo.
func ParseMLDSAPublicKeyPEM(data []byte) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("not a single RFC 7468 PUBLIC KEY block")
	}
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(block.Bytes, &spki)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid SubjectPublicKeyInfo")
	}
	if !spki.Algorithm.Algorithm.Equal(oidMLDSA87) || len(spki.Algorithm.Parameters.FullBytes) != 0 {
		return nil, errors.New("public key is not parameter-free ML-DSA-87")
	}
	if spki.PublicKey.BitLength != ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES*8 || len(spki.PublicKey.Bytes) != ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES {
		return nil, errors.New("invalid ML-DSA-87 public key length")
	}
	return append([]byte(nil), spki.PublicKey.Bytes...), nil
}

// MarshalMLDSAPrivateKeyPEM encodes the recommended RFC 9881 seed-only
// ML-DSA-87 private-key representation inside PKCS#8 OneAsymmetricKey.
func MarshalMLDSAPrivateKeyPEM(seed []byte) ([]byte, error) {
	if len(seed) != ml_dsa_87.SEED_BYTES {
		return nil, fmt.Errorf("invalid ML-DSA-87 seed length: got %d, want %d", len(seed), ml_dsa_87.SEED_BYTES)
	}
	inner, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: seed})
	if err != nil {
		//coverage:ignore reason=defensive-unreachable
		//rationale: the fixed primitive context-specific ASN.1 value is always marshalable
		return nil, fmt.Errorf("encode ML-DSA-87 seed: %w", err)
	}
	der, err := asn1.Marshal(privateKeyInfo{
		Version:    0,
		Algorithm:  algorithmIdentifier{Algorithm: oidMLDSA87},
		PrivateKey: inner,
	})
	if err != nil {
		//coverage:ignore reason=defensive-unreachable
		//rationale: the fixed ASN.1 structure contains only values accepted by encoding/asn1
		return nil, fmt.Errorf("encode ML-DSA-87 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseMLDSAPrivateKeyPEM decodes all three RFC 9881 private-key choices. It
// returns the seed when present and the expanded key when present.
func ParseMLDSAPrivateKeyPEM(data []byte) (seed, expandedKey []byte, err error) {
	block, trailing := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, nil, errors.New("not a single RFC 7468 PRIVATE KEY block")
	}
	var info privateKeyInfo
	rest, err := asn1.Unmarshal(block.Bytes, &info)
	if err != nil || len(rest) != 0 || info.Version != 0 {
		return nil, nil, errors.New("invalid OneAsymmetricKey")
	}
	if !info.Algorithm.Algorithm.Equal(oidMLDSA87) || len(info.Algorithm.Parameters.FullBytes) != 0 {
		return nil, nil, errors.New("private key is not parameter-free ML-DSA-87")
	}

	var choice asn1.RawValue
	rest, err = asn1.Unmarshal(info.PrivateKey, &choice)
	if err != nil || len(rest) != 0 {
		return nil, nil, errors.New("invalid ML-DSA-87 private-key choice")
	}
	switch {
	case choice.Class == asn1.ClassContextSpecific && choice.Tag == 0 && !choice.IsCompound:
		if len(choice.Bytes) != ml_dsa_87.SEED_BYTES {
			return nil, nil, errors.New("invalid ML-DSA-87 seed length")
		}
		seed = append([]byte(nil), choice.Bytes...)
	case choice.Class == asn1.ClassUniversal && choice.Tag == asn1.TagOctetString:
		if len(choice.Bytes) != ml_dsa_87.CRYPTO_SECRET_KEY_BYTES {
			return nil, nil, errors.New("invalid ML-DSA-87 expanded key length")
		}
		expandedKey = append([]byte(nil), choice.Bytes...)
	case choice.Class == asn1.ClassUniversal && choice.Tag == asn1.TagSequence && choice.IsCompound:
		var both struct {
			Seed        []byte
			ExpandedKey []byte
		}
		rest, err = asn1.Unmarshal(choice.FullBytes, &both)
		if err != nil || len(rest) != 0 || len(both.Seed) != ml_dsa_87.SEED_BYTES || len(both.ExpandedKey) != ml_dsa_87.CRYPTO_SECRET_KEY_BYTES {
			return nil, nil, errors.New("invalid ML-DSA-87 combined private key")
		}
		d, keyErr := ml_dsa_87.NewMLDSA87FromSeed(*(*[ml_dsa_87.SEED_BYTES]uint8)(both.Seed))
		if keyErr != nil {
			//coverage:ignore reason=statistically-unreachable
			//rationale: go-qrllib deterministically expands every correctly sized ML-DSA-87 seed
			return nil, nil, fmt.Errorf("expand ML-DSA-87 seed: %w", keyErr)
		}
		derived := d.GetSK()
		if subtle.ConstantTimeCompare(derived[:], both.ExpandedKey) != 1 {
			return nil, nil, errors.New("inconsistent ML-DSA-87 seed and expanded key")
		}
		seed = append([]byte(nil), both.Seed...)
		expandedKey = append([]byte(nil), both.ExpandedKey...)
	default:
		return nil, nil, errors.New("unsupported ML-DSA-87 private-key choice")
	}
	return seed, expandedKey, nil
}
