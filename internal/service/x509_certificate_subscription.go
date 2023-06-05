package service

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/db/repository"
	"time"
)

type X509CertificateSubscriptionDto struct {
	ID                uuid.UUID `binding:"required" validate:"required" json:"id" toml:"id" yaml:"id"`
	SANs              []string  `binding:"required" validate:"required" json:"sans" toml:"sans" yaml:"sans"`
	IncludePrivateKey bool      `binding:"required" validate:"required" json:"include_private_key" toml:"include_private_key" yaml:"include_private_key"`
	CreatedAt         time.Time `binding:"required" validate:"required" json:"created_at" toml:"created_at" yaml:"created_at"`
}

type CreateX509CertificateSubscriptionDto struct {
	SubjectAltNames   []string
	IncludePrivateKey bool
}

func NewCreateX509CertificateSubscriptionDto(subjectAltNames []string, includePrivateKey bool) *CreateX509CertificateSubscriptionDto {
	return &CreateX509CertificateSubscriptionDto{SubjectAltNames: subjectAltNames, IncludePrivateKey: includePrivateKey}
}

type X509CertificateSubscriptionService struct {
	repository repository.X509CertificateSubscriptionRepository
	clock      clockwork.Clock
}

func NewX509CertificateSubscriptionService(
	repository repository.X509CertificateSubscriptionRepository, clock clockwork.Clock,
) *X509CertificateSubscriptionService {
	return &X509CertificateSubscriptionService{repository: repository, clock: clock}
}

func (x *X509CertificateSubscriptionService) Create(
	ctx context.Context, request *CreateX509CertificateSubscriptionDto,
) (*X509CertificateSubscriptionDto, error) {
	createdSubscription, err := x.repository.Create(ctx, repository.NewX509CertificateSubscriptionDao(
		uuid.New(),
		request.SubjectAltNames,
		request.IncludePrivateKey,
		x.clock.Now(),
	))
	if err != nil {
		return nil, err
	}
	return certificateSubscriptionDaoToDto(createdSubscription), nil
}

func (x *X509CertificateSubscriptionService) FindByIDs(
	ctx context.Context, IDs []uuid.UUID,
) ([]*X509CertificateSubscriptionDto, error) {
	foundSubscriptions, err := x.repository.FindByIDs(ctx, IDs)
	if err != nil {
		return nil, err
	}
	return certificateSubscriptionDaoListToDtoList(foundSubscriptions), nil
}

func (x *X509CertificateSubscriptionService) Exists(ctx context.Context, IDs []uuid.UUID) (notExistingIDs []uuid.UUID, err error) {
	fetchedSubs, err := x.repository.FindByIDs(ctx, IDs)
	if err != nil {
		return nil, fmt.Errorf("unable find subscriptions by ids: %w", err)
	}

outerLoop:
	for _, id := range IDs {
		for _, sub := range fetchedSubs {
			if id == sub.ID {
				continue outerLoop
			}
		}
		notExistingIDs = append(notExistingIDs, id)
	}

	return notExistingIDs, nil
}

func (x *X509CertificateSubscriptionService) Delete(ctx context.Context, subID uuid.UUID) (rowsDeleted int64, err error) {
	return x.repository.Delete(ctx, subID)
}

func certificateSubscriptionDaoListToDtoList(dao []*repository.X509CertificateSubscriptionDao) []*X509CertificateSubscriptionDto {
	dtos := make([]*X509CertificateSubscriptionDto, len(dao))
	for i, certificateDao := range dao {
		dtos[i] = certificateSubscriptionDaoToDto(certificateDao)
	}
	return dtos
}

func certificateSubscriptionDaoToDto(dao *repository.X509CertificateSubscriptionDao) *X509CertificateSubscriptionDto {
	return &X509CertificateSubscriptionDto{
		ID:                dao.ID,
		SANs:              dao.SubjectAltNames,
		IncludePrivateKey: dao.IncludePrivateKey,
		CreatedAt:         dao.CreatedAt,
	}
}
