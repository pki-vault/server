package repository

//go:generate mockgen -destination=../../mocks/db/x509_certificate_subscription.go -source x509_certificate_subscription.go

import (
	"context"
	"github.com/google/uuid"
	"time"
)

// X509CertificateSubscriptionDao serves as an abstraction for all the different per database x509 Certificate subscription structs.
type X509CertificateSubscriptionDao struct {
	ID                uuid.UUID `binding:"required" validate:"required" json:"id" toml:"id" yaml:"id"`
	SubjectAltNames   []string  `binding:"required" validate:"required" json:"subject_alternative_names" toml:"subject_alternative_names" yaml:"subject_alternative_names"`
	IncludePrivateKey bool      `binding:"required" validate:"required" json:"include_private_key" toml:"include_private_key" yaml:"include_private_key"`
	CreatedAt         time.Time `binding:"required" validate:"required" json:"created_at" toml:"created_at" yaml:"created_at"`
}

func NewX509CertificateSubscriptionDao(ID uuid.UUID, subjectAltNames []string, includePrivateKey bool, createdAt time.Time) *X509CertificateSubscriptionDao {
	return &X509CertificateSubscriptionDao{ID: ID, SubjectAltNames: subjectAltNames, IncludePrivateKey: includePrivateKey, CreatedAt: createdAt}
}

type X509CertificateSubscriptionRepository interface {
	Create(ctx context.Context, cert *X509CertificateSubscriptionDao) (*X509CertificateSubscriptionDao, error)
	FindByIDs(ctx context.Context, publicIDs []uuid.UUID) ([]*X509CertificateSubscriptionDao, error)
	Delete(ctx context.Context, subID uuid.UUID) (rowsDeleted int64, err error)
}
