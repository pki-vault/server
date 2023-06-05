package service

//go:generate mockgen -destination=../mocks/services/x509_private_key.go -source x509_private_key.go

import (
	"context"
	"encoding/pem"
	"fmt"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/db/repository"
	"time"
)

type X509PrivateKeyDto struct {
	ID            uuid.UUID `binding:"required" validate:"required" json:"id" toml:"id" yaml:"id"`
	PemPrivateKey string    `binding:"required" validate:"required" json:"private_key" toml:"private_key" yaml:"private_key"`
	CreatedAt     time.Time `binding:"required" validate:"required" json:"created_at" toml:"created_at" yaml:"created_at"`
}

type X509PrivateKeyService interface {
	GetOrCreate(ctx context.Context, request *CreatePrivateKeyRequest) (*X509PrivateKeyDto, error)
	FindByIDs(ctx context.Context, ids []uuid.UUID) ([]*X509PrivateKeyDto, error)
}

func NewX509PrivateKeyDto(ID uuid.UUID, pemPrivateKey string, createdAt time.Time) *X509PrivateKeyDto {
	return &X509PrivateKeyDto{ID: ID, PemPrivateKey: pemPrivateKey, CreatedAt: createdAt}
}

type CreatePrivateKeyRequest struct {
	PrivateKey *pem.Block
}

type DefaultX509PrivateKeyService struct {
	certRepo repository.PrivateKeyRepository
	clock    clockwork.Clock
}

func NewDefaultX509PrivateKeyService(certRepo repository.PrivateKeyRepository, clock clockwork.Clock) *DefaultX509PrivateKeyService {
	return &DefaultX509PrivateKeyService{certRepo: certRepo, clock: clock}
}

func (x *DefaultX509PrivateKeyService) GetOrCreate(ctx context.Context, request *CreatePrivateKeyRequest) (*X509PrivateKeyDto, error) {
	key, keyType, err := ParsePrivateKey(request.PrivateKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %w", err)
	}
	pubKeyHash, err := ComputePublicKeyTypeSpecificHashFromPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("could not compute public key hash from private key: %w", err)
	}

	fetchedOrCreatedCert, err := x.certRepo.GetOrCreate(ctx, repository.NewX509PrivateKeyDao(
		uuid.New(),
		repository.PrivateKeyType(keyType),
		request.PrivateKey.Type,
		ComputeBytesHash(request.PrivateKey.Bytes),
		request.PrivateKey.Bytes,
		pubKeyHash,
		x.clock.Now(),
	))
	if err != nil {
		return nil, err
	}

	return privateKeyDaoToDto(fetchedOrCreatedCert), nil
}

func (x *DefaultX509PrivateKeyService) FindByIDs(ctx context.Context, ids []uuid.UUID) ([]*X509PrivateKeyDto, error) {
	certs, err := x.certRepo.FindByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	dtos := make([]*X509PrivateKeyDto, len(certs))
	for i, cert := range certs {
		dtos[i] = privateKeyDaoToDto(cert)
	}

	return dtos, nil
}

func privateKeyDaoToDto(privKey *repository.X509PrivateKeyDao) *X509PrivateKeyDto {
	if privKey == nil {
		return nil
	}
	return NewX509PrivateKeyDto(
		privKey.ID,
		string(pem.EncodeToMemory(&pem.Block{
			Type:    privKey.PemBlockType,
			Headers: nil,
			Bytes:   privKey.Bytes,
		})),
		privKey.CreatedAt,
	)
}
