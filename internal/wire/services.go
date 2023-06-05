package wire

import (
	"github.com/google/wire"
	"github.com/pki-vault/server/internal/service"
)

var servicesSet = wire.NewSet(
	service.NewX509CertificateService,
	service.NewX509CertificateSubscriptionService,
	service.NewDefaultX509PrivateKeyService,
	service.NewX509ImportService,
)
