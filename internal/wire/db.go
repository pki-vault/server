package wire

import (
	"github.com/google/wire"
	"github.com/pki-vault/server/internal/db/repository"
)

var repositorySet = wire.NewSet(
	ProvidePostgresqlX509CertificateRepository,
	ProvidePostgresqlX509CertificateSubscriptionRepository,
	ProvidePostgresqlX509PrivateKeyRepository,
	ProvidePostgresqlX509TransactionManager,
)

func ProvidePostgresqlX509CertificateRepository(repositoryBundle repository.Bundle) repository.X509CertificateRepository {
	return repositoryBundle.X509CertificateRepository()
}

func ProvidePostgresqlX509CertificateSubscriptionRepository(repositoryBundle repository.Bundle) repository.X509CertificateSubscriptionRepository {
	return repositoryBundle.X509CertificateSubscriptionRepository()
}

func ProvidePostgresqlX509PrivateKeyRepository(repositoryBundle repository.Bundle) repository.PrivateKeyRepository {
	return repositoryBundle.X509PrivateKeyRepository()
}

func ProvidePostgresqlX509TransactionManager(repositoryBundle repository.Bundle) repository.TransactionManager {
	return repositoryBundle.TransactionManager()
}
