package services

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"github.com/pki-vault/server/internal/db/repository"
)

func ParsePrivateKey(der []byte) (key crypto.PrivateKey, keyType string, err error) {
	key, err = x509.ParsePKCS1PrivateKey(der)
	if err == nil {
		return key, string(repository.PrivateKeyTypeRSA), nil
	}

	key, err = x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, string(repository.PrivateKeyTypeRSA), nil
		case *ecdsa.PrivateKey:
			return key, string(repository.PrivateKeyTypeECDSA), nil
		case ed25519.PrivateKey:
			return key, string(repository.PrivateKeyTypeED25519), nil
		default:
			return nil, "", errors.New("unable to find key type")
		}
	}

	key, err = x509.ParseECPrivateKey(der)
	if err == nil {
		switch key := key.(type) {
		case *ecdsa.PrivateKey:
			return key, string(repository.PrivateKeyTypeECDSA), nil
		default:
			return nil, "", errors.New("unable to find key type")
		}
	}

	return nil, "", errors.New("unable to find key type")
}

func ComputePublicKeyTypeSpecificHashFromPrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return computePublicKeyTypeSpecificHash(privateKey.(*rsa.PrivateKey).Public())
	case *ecdsa.PrivateKey:
		return computePublicKeyTypeSpecificHash(privateKey.(*ecdsa.PrivateKey).Public())
	case ed25519.PrivateKey:
		return computePublicKeyTypeSpecificHash(privateKey.(ed25519.PrivateKey).Public())
	default:
		return nil, errors.New("given data is no supported private key")
	}
}

func computePublicKeyTypeSpecificHash(publicKey any) ([]byte, error) {
	var pubKeyHash []byte
	switch publicKey.(type) {
	case *rsa.PublicKey:
		pubKeyBytes := make([]byte, 0)
		pubKeyBytes = append(pubKeyBytes, publicKey.(*rsa.PublicKey).N.Bytes()...)
		pubKeyBytes = append(pubKeyBytes, byte(publicKey.(*rsa.PublicKey).E))
		pubKeyHash = computePublicKeyHash(pubKeyBytes)
	case *ecdsa.PublicKey:
		pubKeyBytes := make([]byte, 0)
		pubKeyBytes = append(pubKeyBytes, publicKey.(*ecdsa.PublicKey).X.Bytes()...)
		pubKeyBytes = append(pubKeyBytes, publicKey.(*ecdsa.PublicKey).Y.Bytes()...)
		pubKeyHash = computePublicKeyHash(pubKeyBytes)
	case ed25519.PublicKey:
		pubKeyHash = computePublicKeyHash(publicKey.(ed25519.PublicKey))
	default:
		return nil, errors.New("given data is no supported private key")
	}
	return pubKeyHash, nil
}
