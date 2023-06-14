package wire

import (
	"github.com/google/wire"
	"github.com/pki-vault/server/internal/service"
)

var servicesSet = wire.NewSet(
	service.NewX509CertificateService,
	wire.Bind(new(service.X509CertificateService), new(*service.DefaultX509CertificateService)),
	service.NewX509CertificateSubscriptionService,
	wire.Bind(new(service.X509CertificateSubscriptionService), new(*service.DefaultX509CertificateSubscriptionService)),
	service.NewDefaultX509PrivateKeyService,
	wire.Bind(new(service.X509PrivateKeyService), new(*service.DefaultX509PrivateKeyService)),
	service.NewX509ImportService,
	wire.Bind(new(service.X509ImportService), new(*service.DefaultX509ImportService)),
)
