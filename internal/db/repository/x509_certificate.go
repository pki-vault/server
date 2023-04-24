package repository

//go:generate mockgen -destination=../../mocks/db/x509_certificate.go -source x509_certificate.go

import (
	"context"
	"github.com/google/uuid"
	"time"
)

// X509CertificateDao serves as an abstraction for all the different per database x509 cert structs.
type X509CertificateDao struct {
	ID                  uuid.UUID
	CommonName          string
	SubjectAltNames     []string
	IssuerHash          []byte
	SubjectHash         []byte
	BytesHash           []byte
	Bytes               []byte
	PublicKeyHash       []byte
	ParentCertificateID *uuid.UUID
	PrivateKeyID        *uuid.UUID
	NotBefore           time.Time
	NotAfter            time.Time
	CreatedAt           time.Time
}

func NewX509CertificateDao(ID uuid.UUID, commonName string, subjectAltNames []string, issuerHash []byte, subjectHash []byte, bytesHash []byte, bytes []byte, pubKeyHash []byte, parentCertID *uuid.UUID, privKeyID *uuid.UUID, notBefore time.Time, notAfter time.Time, createdAt time.Time) *X509CertificateDao {
	if subjectAltNames == nil {
		subjectAltNames = []string{}
	}
	return &X509CertificateDao{ID: ID, CommonName: commonName, SubjectAltNames: subjectAltNames, IssuerHash: issuerHash, SubjectHash: subjectHash, BytesHash: bytesHash, Bytes: bytes, PublicKeyHash: pubKeyHash, ParentCertificateID: parentCertID, PrivateKeyID: privKeyID, NotBefore: notBefore, NotAfter: notAfter, CreatedAt: createdAt}
}

type X509CertificateRepository interface {
	GetOrCreate(ctx context.Context, cert *X509CertificateDao) (*X509CertificateDao, error)
	Update(ctx context.Context, cert *X509CertificateDao) (updatedCert *X509CertificateDao, updated bool, err error)
	FindByIssuerHashAndNoParentSet(ctx context.Context, issuerHash []byte) ([]*X509CertificateDao, error)
	FindByPublicKeyHashAndNoPrivateKeySet(ctx context.Context, pubKeyHash []byte) ([]*X509CertificateDao, error)
	FindBySubjectHash(ctx context.Context, subjectHash []byte) ([]*X509CertificateDao, error)
	FindAllByByteHashes(ctx context.Context, byteHashes []*[]byte) ([]*X509CertificateDao, error)
	FindLatestActiveBySANsAndCreatedAtAfter(ctx context.Context, subjectAltNames []string, sinceAfter time.Time) ([]*X509CertificateDao, error)
	FindCertificateChain(ctx context.Context, startCertId uuid.UUID) ([]*X509CertificateDao, error)
}
