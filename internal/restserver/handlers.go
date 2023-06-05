package restserver

import (
	"context"
	"encoding/pem"
	"github.com/pki-vault/server/internal/service"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

type RestHandlerImpl struct {
	logger                             *zap.Logger
	x509CertificateSubscriptionService *service.X509CertificateSubscriptionService
	x509CertificateService             *service.X509CertificateService
	x509ImportService                  *service.X509ImportService
}

func NewRestHandlerImpl(logger *zap.Logger, x509CertificateSubscriptionService *service.X509CertificateSubscriptionService, x509CertificateService *service.X509CertificateService, x509ImportServiceV2 *service.X509ImportService) *RestHandlerImpl {
	return &RestHandlerImpl{logger: logger, x509CertificateSubscriptionService: x509CertificateSubscriptionService, x509CertificateService: x509CertificateService, x509ImportService: x509ImportServiceV2}
}

func (r *RestHandlerImpl) GetX509CertificateUpdatesV1(ctx context.Context, request GetX509CertificateUpdatesV1RequestObject) (GetX509CertificateUpdatesV1ResponseObject, error) {
	notExistingIDs, err := r.x509CertificateSubscriptionService.Exists(ctx, request.Params.Subscriptions)
	if err != nil {
		message := "could not load certificate updates"
		r.l(ctx).Debug(message)
		return GetX509CertificateUpdatesV1400JSONResponse{
			Code:          ptr(http.StatusBadRequest),
			Message:       &message,
			DetailMessage: ptr("unable to check if all certificate subscriptions exist"),
		}, nil
	}
	if len(notExistingIDs) != 0 {
		message := "one or more certificate subscriptions don't exist"
		r.l(ctx).Debug(message)

		var notExistingIDStrings []string
		for _, id := range notExistingIDs {
			notExistingIDStrings = append(notExistingIDStrings, id.String())
		}
		return GetX509CertificateUpdatesV1400JSONResponse{
			Code:          ptr(http.StatusBadRequest),
			Message:       &message,
			DetailMessage: ptr("missing certificate subscriptions: " + strings.Join(notExistingIDStrings, ", ")),
		}, nil
	}

	certDtos, privKeyDtos, err := r.x509CertificateService.GetUpdates(ctx, request.Params.Subscriptions, request.Params.After, true)
	if err != nil {
		message := "could not load certificate updates"
		r.l(ctx).Error(message, zap.Error(err))
		return GetX509CertificateUpdatesV1defaultJSONResponse{
			Body: Error{
				Code:    ptr(http.StatusInternalServerError),
				Message: &message,
			},
			StatusCode: http.StatusInternalServerError,
		}, nil
	}

	certs := make([]X509Certificate, len(certDtos))
	for i, cert := range certDtos {
		certs[i] = dtoToX509Certificate(cert)
	}
	privKeys := make([]X509PrivateKey, len(privKeyDtos))
	for i, privKey := range privKeyDtos {
		privKeys[i] = dtoToX509PrivateKey(privKey)
	}

	return GetX509CertificateUpdatesV1200JSONResponse{
		Certificates: &certs,
		PrivateKeys:  &privKeys,
	}, nil
}

func (r *RestHandlerImpl) BulkImportX509V1(
	ctx context.Context, request BulkImportX509V1RequestObject,
) (BulkImportX509V1ResponseObject, error) {
	var certPems []*pem.Block
	if request.Body.Certificates != nil {
		for _, cert := range *request.Body.Certificates {
			certificate, rest := pem.Decode([]byte(cert))
			if len(rest) != 0 {
				message := "certificate pem has invalid extra data"
				r.l(ctx).Debug(message)
				return BulkImportX509V1400JSONResponse{
					Code:    ptr(http.StatusBadRequest),
					Message: &message,
				}, nil
			}
			certPems = append(certPems, certificate)
		}
	}

	var privKeyPems []*pem.Block
	if request.Body.PrivateKeys != nil {
		for _, privKey := range *request.Body.PrivateKeys {
			privateKey, rest := pem.Decode([]byte(privKey))
			if len(rest) != 0 {
				message := "private key pem has invalid extra data"
				r.l(ctx).Debug(message)
				return BulkImportX509V1400JSONResponse{
					Code:    ptr(http.StatusBadRequest),
					Message: &message,
				}, nil
			}
			privKeyPems = append(privKeyPems, privateKey)
		}
	}

	createdCerts, createdPrivKeys, err := r.x509ImportService.Import(ctx, certPems, privKeyPems)
	if err != nil {
		message := "could not create certificates and private keys"
		r.l(ctx).Error(message, zap.Error(err))
		return BulkImportX509V1defaultJSONResponse{
			Body: Error{
				Code:    ptr(http.StatusInternalServerError),
				Message: &message,
			},
			StatusCode: http.StatusInternalServerError,
		}, nil
	}

	certs := make([]X509Certificate, len(createdCerts))
	for i, cert := range createdCerts {
		certs[i] = dtoToX509Certificate(cert)
	}
	privKeys := make([]X509PrivateKey, len(createdPrivKeys))
	for i, privKey := range createdPrivKeys {
		privKeys[i] = dtoToX509PrivateKey(privKey)
	}

	return BulkImportX509V1201JSONResponse{
		Certificates: &certs,
		PrivateKeys:  &privKeys,
	}, nil
}

func (r *RestHandlerImpl) ImportX509BundleV1(
	ctx context.Context, request ImportX509BundleV1RequestObject,
) (ImportX509BundleV1ResponseObject, error) {
	certPemBlock, rest := pem.Decode([]byte(request.Body.Certificate))
	if len(rest) != 0 {
		message := "pem has invalid extra data"
		r.l(ctx).Debug(message)
		return ImportX509BundleV1400JSONResponse{
			Code:    ptr(http.StatusBadRequest),
			Message: &message,
		}, nil
	}

	var privateKeyPemBlock *pem.Block
	if request.Body.PrivateKey != nil {
		privateKeyPemBlock, rest = pem.Decode([]byte(*request.Body.PrivateKey))
		if len(rest) != 0 {
			message := "private key pem has invalid extra data"
			r.l(ctx).Debug(message)
			return ImportX509BundleV1400JSONResponse{
				Code:    ptr(http.StatusBadRequest),
				Message: &message,
			}, nil
		}
	}

	// Add chain certificates
	chainPemBlocks, rest := separatePemBlocks([]byte(request.Body.Chain))
	if len(rest) != 0 {
		message := "cert chain pem blocks have invalid extra data"
		r.l(ctx).Debug(message)
		return ImportX509BundleV1400JSONResponse{
			Code:          ptr(http.StatusBadRequest),
			Message:       &message,
			DetailMessage: nil,
		}, nil
	}

	createdCerts, createdPrivKeys, err := r.x509ImportService.Import(ctx, append([]*pem.Block{certPemBlock}, chainPemBlocks...), []*pem.Block{privateKeyPemBlock})
	if err != nil {
		message := "could not create certificates and private keys"
		r.l(ctx).Error(message, zap.Error(err))
		return ImportX509BundleV1defaultJSONResponse{
			Body: Error{
				Code:    ptr(http.StatusInternalServerError),
				Message: &message,
			},
			StatusCode: http.StatusInternalServerError,
		}, nil
	}

	certs := make([]X509Certificate, len(createdCerts))
	for i, cert := range createdCerts {
		certs[i] = dtoToX509Certificate(cert)
	}
	privKeys := make([]X509PrivateKey, len(createdPrivKeys))
	for i, privKey := range createdPrivKeys {
		privKeys[i] = dtoToX509PrivateKey(privKey)
	}

	return ImportX509BundleV1201JSONResponse{
		Certificates: &certs,
		PrivateKeys:  &privKeys,
	}, nil
}

func (r *RestHandlerImpl) CreateX509CertificateSubscriptionV1(
	ctx context.Context, request CreateX509CertificateSubscriptionV1RequestObject,
) (CreateX509CertificateSubscriptionV1ResponseObject, error) {
	createRequest := service.NewCreateX509CertificateSubscriptionDto(
		request.Body.SubjectAltNames,
		request.Body.IncludePrivateKey)
	createdSubscription, err := r.x509CertificateSubscriptionService.Create(ctx, createRequest)
	if err != nil {
		message := "could not create subscription"
		r.l(ctx).Error(message, zap.Error(err))
		return CreateX509CertificateSubscriptionV1defaultJSONResponse{
			Body: Error{
				Code:    ptr(http.StatusInternalServerError),
				Message: &message,
			},
			StatusCode: http.StatusInternalServerError,
		}, nil
	}
	return CreateX509CertificateSubscriptionV1200JSONResponse(dtoToX509CertificateSubscription(createdSubscription)), nil
}

func (r *RestHandlerImpl) DeleteX509CertificateSubscriptionV1(
	ctx context.Context, request DeleteX509CertificateSubscriptionV1RequestObject,
) (DeleteX509CertificateSubscriptionV1ResponseObject, error) {
	rowsDeleted, err := r.x509CertificateSubscriptionService.Delete(ctx, request.Id)
	if err != nil {
		message := "could not delete subscription"
		r.l(ctx).Error(message, zap.Error(err))
		return DeleteX509CertificateSubscriptionV1defaultJSONResponse{
			Body: Error{
				Code:    ptr(http.StatusInternalServerError),
				Message: &message,
			},
			StatusCode: http.StatusInternalServerError,
		}, nil
	}
	if rowsDeleted < 1 {
		return DeleteX509CertificateSubscriptionV1404JSONResponse{
			Code:    ptr(http.StatusNotFound),
			Message: ptr("subscription does not exist"),
		}, nil
	}
	return DeleteX509CertificateSubscriptionV1204Response{}, nil
}

func dtoToX509PrivateKey(privKeyDto *service.X509PrivateKeyDto) X509PrivateKey {
	return X509PrivateKey{
		Id:  privKeyDto.ID,
		Key: privKeyDto.PemPrivateKey,
	}
}

func dtoToX509Certificate(certDto *service.X509CertificateDto) X509Certificate {
	return X509Certificate{
		Certificate:         certDto.CertificatePem,
		CommonName:          ptr(certDto.CommonName),
		CreatedAt:           certDto.CreatedAt,
		Id:                  certDto.ID,
		NotAfter:            certDto.NotAfter,
		NotBefore:           certDto.NotBefore,
		ParentCertificateId: certDto.ParentCertificateID,
		PrivateKeyId:        certDto.PrivateKeyID,
		Sans:                certDto.SubjectAltNames,
	}
}

func dtoToX509CertificateSubscription(dto *service.X509CertificateSubscriptionDto) X509CertificateSubscription {
	return X509CertificateSubscription{
		CreatedAt:         dto.CreatedAt,
		Id:                dto.ID,
		IncludePrivateKey: dto.IncludePrivateKey,
		SubjectAltNames:   dto.SANs,
	}
}

func separatePemBlocks(pemBlocks []byte) (blocks []*pem.Block, rest []byte) {
	return separatePemBlocksRecursively(pemBlocks, nil)
}

func separatePemBlocksRecursively(pemBlocks []byte, foundPemBlocks []*pem.Block) (blocks []*pem.Block, rest []byte) {
	pemBlock, rest := pem.Decode(pemBlocks)
	if pemBlock == nil {
		return foundPemBlocks, rest
	}

	return separatePemBlocksRecursively(rest, append(foundPemBlocks, pemBlock))
}

func (r *RestHandlerImpl) l(ctx context.Context) *zap.Logger {
	logger := ctx.Value(GinCtxLoggerKey)
	if logger == nil {
		panic("")
	}
	return logger.(*zap.Logger)
}

func ptr[T any](input T) *T {
	return &input
}
