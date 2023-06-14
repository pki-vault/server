package repository

//go:generate mockgen -destination=../../mocks/db/bundle.go -source bundle.go

type Bundle interface {
	X509CertificateRepository() X509CertificateRepository
	X509CertificateSubscriptionRepository() X509CertificateSubscriptionRepository
	X509PrivateKeyRepository() X509PrivateKeyRepository
	TransactionManager() TransactionManager
}

type SimpleBundle struct {
	certRepo    X509CertificateRepository
	subRepo     X509CertificateSubscriptionRepository
	privKeyRepo X509PrivateKeyRepository
	txMgr       TransactionManager
}

func NewSimpleBundle(certRepo X509CertificateRepository, subRepo X509CertificateSubscriptionRepository, keyRepo X509PrivateKeyRepository, txMgr TransactionManager) *SimpleBundle {
	return &SimpleBundle{certRepo: certRepo, subRepo: subRepo, privKeyRepo: keyRepo, txMgr: txMgr}
}

func (s SimpleBundle) X509CertificateRepository() X509CertificateRepository {
	return s.certRepo
}

func (s SimpleBundle) X509CertificateSubscriptionRepository() X509CertificateSubscriptionRepository {
	return s.subRepo
}

func (s SimpleBundle) X509PrivateKeyRepository() X509PrivateKeyRepository {
	return s.privKeyRepo
}

func (s SimpleBundle) TransactionManager() TransactionManager {
	return s.txMgr
}
