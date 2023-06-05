package service

import (
	"context"
	"encoding/pem"
	"errors"
	"github.com/google/uuid"
	"github.com/pki-vault/server/internal/db/repository"
	"sync"
	"time"
)

type X509CertificateDto struct {
	ID                  uuid.UUID  `binding:"required" validate:"required" json:"id" toml:"id" yaml:"id"`
	CommonName          string     `binding:"required" validate:"required" json:"common_name" toml:"common_name" yaml:"common_name"`
	SubjectAltNames     []string   `binding:"required" validate:"required" json:"sans" toml:"sans" yaml:"sans"`
	CertificatePem      string     `binding:"required" validate:"required" json:"certificate" toml:"certificate" yaml:"certificate"`
	ParentCertificateID *uuid.UUID `json:"parent_certificate_id,omitempty" toml:"parent_certificate_id" yaml:"parent_certificate_id,omitempty"`
	PrivateKeyID        *uuid.UUID `json:"private_key_id,omitempty" toml:"private_key_id" yaml:"private_key_id,omitempty"`
	NotBefore           time.Time  `binding:"required" validate:"required" json:"not_before" toml:"not_before" yaml:"not_before"`
	NotAfter            time.Time  `binding:"required" validate:"required" json:"not_after" toml:"not_after" yaml:"not_after"`
	CreatedAt           time.Time  `binding:"required" validate:"required" json:"created_at" toml:"created_at" yaml:"created_at"`
}

func NewX509CertificateDto(ID uuid.UUID, commonName string, subjectAltNames []string, certPem string, parentCertID *uuid.UUID, privKeyID *uuid.UUID, notBefore time.Time, notAfter time.Time, createdAt time.Time) *X509CertificateDto {
	return &X509CertificateDto{ID: ID, CommonName: commonName, SubjectAltNames: subjectAltNames, CertificatePem: certPem, ParentCertificateID: parentCertID, PrivateKeyID: privKeyID, NotBefore: notBefore, NotAfter: notAfter, CreatedAt: createdAt}
}

type X509CertificateService struct {
	certRepo       repository.X509CertificateRepository
	subService     *X509CertificateSubscriptionService
	privKeyService *DefaultX509PrivateKeyService
}

func NewX509CertificateService(
	certRepo repository.X509CertificateRepository, subService *X509CertificateSubscriptionService,
	privKeyService *DefaultX509PrivateKeyService,
) *X509CertificateService {
	return &X509CertificateService{certRepo: certRepo, subService: subService, privKeyService: privKeyService}
}

type getUpdatesResultStruct struct {
	certs []*X509CertificateDto
	err   error
}

// GetUpdates returns the latest active certificate for each subscription.
// Also includes the private key for a certificate if it exists and is configured in the subscription.
func (x *X509CertificateService) GetUpdates(
	ctx context.Context, subIDs []uuid.UUID, after time.Time, includeCertChainIfExists bool,
) ([]*X509CertificateDto, []*X509PrivateKeyDto, error) {
	subs, err := x.subService.FindByIDs(ctx, subIDs)
	if err != nil {
		return nil, nil, err
	}

	// Check if we found all subs
	for _, id := range subIDs {
		foundSub := false
		for _, subscription := range subs {
			if id == subscription.ID {
				foundSub = true
				break
			}
		}
		if !foundSub {
			return nil, nil, errors.New("at least one subscription not found")
		}
	}

	var wg sync.WaitGroup
	certResults := make(chan getUpdatesResultStruct, len(subs))

	for _, sub := range subs {
		wg.Add(1)
		sub := sub
		go func() {
			defer wg.Done()
			certificates, err := x.getLatestSubscriptionCertificates(ctx, sub, after, includeCertChainIfExists)
			certResults <- getUpdatesResultStruct{err: err, certs: certificates}
		}()
	}

	wg.Wait()
	close(certResults)

	var certDtos []*X509CertificateDto
	var privKeyIDs []uuid.UUID
	for result := range certResults {
		if result.err != nil {
			return nil, nil, result.err
		}
	outerCertLoop:
		for _, resultCert := range result.certs {
			// Skip duplicate certificates
			for _, certificate := range certDtos {
				if certificate.ID == resultCert.ID {
					continue outerCertLoop
				}
			}
			certDtos = append(certDtos, resultCert)
		}

		for _, cert := range result.certs {
			if cert.PrivateKeyID != nil {
				privKeyIDs = append(privKeyIDs, *cert.PrivateKeyID)
			}
		}
	}

	privKeyIDs = removeDuplicates(privKeyIDs)
	privKeyDtos, err := x.privKeyService.FindByIDs(ctx, privKeyIDs)

	return certDtos, privKeyDtos, nil
}

func (x *X509CertificateService) getLatestSubscriptionCertificates(
	ctx context.Context, sub *X509CertificateSubscriptionDto, after time.Time, includeCertChainIfExists bool,
) ([]*X509CertificateDto, error) {
	fetchedCerts, err := x.certRepo.FindLatestActiveBySANsAndCreatedAtAfter(ctx, sub.SANs, after)
	if err != nil {
		return nil, err
	}

	certs := make([]*X509CertificateDto, len(fetchedCerts))
	for i, cert := range fetchedCerts {
		certs[i] = certificateDaoToDto(cert)
	}

	if includeCertChainIfExists {
		for _, cert := range fetchedCerts {
			chainCerts, err := x.certRepo.FindCertificateChain(ctx, cert.ID)
			if err != nil {
				return nil, err
			}

			for _, chainCert := range chainCerts {
				certs = append(certs, certificateDaoToDto(chainCert))
			}
		}
	}

	return certs, nil
}

func certificateDaoToDto(cert *repository.X509CertificateDao) *X509CertificateDto {
	certPem := string(pemEncodeX509Certificate(cert.Bytes, "CERTIFICATE"))

	return NewX509CertificateDto(
		cert.ID,
		cert.CommonName,
		cert.SubjectAltNames,
		certPem,
		cert.ParentCertificateID,
		cert.PrivateKeyID,
		cert.NotBefore,
		cert.NotAfter,
		cert.CreatedAt,
	)
}

func pemEncodeX509Certificate(certBytes []byte, blockType string) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: certBytes,
	})
}
