package services

import (
	"crypto/sha512"
	"crypto/x509/pkix"
)

func ComputeSubjectOrIssuerHash(name pkix.Name) []byte {
	return computeSha512Hash([]byte(name.String()))
}

func ComputeBytesHash(data []byte) []byte {
	return computeSha512Hash(data)
}

func computePublicKeyHash(data []byte) []byte {
	return computeSha512Hash(data)
}

func computeSha512Hash(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}
