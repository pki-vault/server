package repository

//go:generate mockgen -destination=../../mocks/db/private_key.go -source private_key.go

import (
	"context"
	"github.com/google/uuid"
	"time"
)

type PrivateKeyType string

// Enum values for PrivateKeyType
const (
	PrivateKeyTypeRSA     PrivateKeyType = "RSA"
	PrivateKeyTypeECDSA   PrivateKeyType = "ECDSA"
	PrivateKeyTypeED25519 PrivateKeyType = "ED25519"
)

// X509PrivateKeyDao serves as an abstraction for all the different per database private key structs.
type X509PrivateKeyDao struct {
	ID            uuid.UUID
	Type          PrivateKeyType
	PemBlockType  string
	BytesHash     []byte
	Bytes         []byte
	PublicKeyHash []byte
	CreatedAt     time.Time
}

func NewX509PrivateKeyDao(ID uuid.UUID, Type PrivateKeyType, pemBlockType string, bytesHash []byte, bytes []byte, pubKeyHash []byte, createdAt time.Time) *X509PrivateKeyDao {
	return &X509PrivateKeyDao{ID: ID, Type: Type, PemBlockType: pemBlockType, BytesHash: bytesHash, Bytes: bytes, PublicKeyHash: pubKeyHash, CreatedAt: createdAt}
}

type PrivateKeyRepository interface {
	GetOrCreate(ctx context.Context, privKey *X509PrivateKeyDao) (*X509PrivateKeyDao, error)
	FindByIDs(ctx context.Context, ids []uuid.UUID) ([]*X509PrivateKeyDao, error)
	FindByPublicKeyHash(ctx context.Context, pubKeyHash []byte) (privKey *X509PrivateKeyDao, exists bool, err error)
}
