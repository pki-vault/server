package repository

import (
	templaterepository "github.com/pki-vault/server/internal/db/repository"
)

type Bundle struct {
	x509CertificateRepository             *X509CertificateRepository
	x509CertificateSubscriptionRepository *X509CertificateSubscriptionRepository
	privateKeyRepository                  *X509PrivateKeyRepository
	transactionManager                    *TransactionManager
}

func NewRepositoryBundle(x509CertificateRepository *X509CertificateRepository, x509CertificateSubscriptionRepository *X509CertificateSubscriptionRepository, privateKeyRepository *X509PrivateKeyRepository, transactionManager *TransactionManager) *Bundle {
	return &Bundle{x509CertificateRepository: x509CertificateRepository, x509CertificateSubscriptionRepository: x509CertificateSubscriptionRepository, privateKeyRepository: privateKeyRepository, transactionManager: transactionManager}
}

func (p *Bundle) X509CertificateRepository() templaterepository.X509CertificateRepository {
	return p.x509CertificateRepository
}

func (p *Bundle) X509CertificateSubscriptionRepository() templaterepository.X509CertificateSubscriptionRepository {
	return p.x509CertificateSubscriptionRepository
}

func (p *Bundle) X509PrivateKeyRepository() templaterepository.PrivateKeyRepository {
	return p.privateKeyRepository
}

func (p *Bundle) TransactionManager() templaterepository.TransactionManager {
	return p.transactionManager
}
