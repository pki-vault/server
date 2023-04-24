package wire

import (
	"github.com/google/wire"
	"github.com/pki-vault/server/internal/services"
)

var servicesSet = wire.NewSet(
	services.NewX509CertificateService,
	services.NewX509CertificateSubscriptionService,
	services.NewDefaultX509PrivateKeyService,
	services.NewX509ImportService,
)
