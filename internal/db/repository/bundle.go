package repository

type Bundle interface {
	X509CertificateRepository() X509CertificateRepository
	X509CertificateSubscriptionRepository() X509CertificateSubscriptionRepository
	X509PrivateKeyRepository() PrivateKeyRepository
	TransactionManager() TransactionManager
}
