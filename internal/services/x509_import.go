package services

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/db/repository"
)

type X509ImportService struct {
	repository.Bundle
	clock clockwork.Clock
}

func NewX509ImportService(bundle repository.Bundle, clock clockwork.Clock) *X509ImportService {
	return &X509ImportService{Bundle: bundle, clock: clock}
}

func (x *X509ImportService) Import(
	ctx context.Context, certPems []*pem.Block, privKeyPems []*pem.Block,
) ([]*X509CertificateDto, []*X509PrivateKeyDto, error) {
	txCtx, err := x.TransactionManager().BeginTx(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if p := recover(); p != nil && txCtx != nil {
			rollbackErr := x.TransactionManager().RollbackTx(txCtx)
			if rollbackErr != nil {
				panic(fmt.Errorf("unable to rollback transaction for panic: %s: %w", p, rollbackErr))
			}
			panic(p)
		}
		if err != nil {
			rollbackErr := x.TransactionManager().RollbackTx(txCtx)
			if rollbackErr != nil {
				panic(fmt.Errorf("unable to rollback transaction: %w", err))
			}
		}
	}()

	var createdPrivKeys []*repository.X509PrivateKeyDao
	{
		privKeyPems = removeDuplicates(privKeyPems)
		// parse deduplicated private keys
		privKeys := make([]*repository.X509PrivateKeyDao, len(privKeyPems))
		for idx, privKey := range privKeyPems {
			privateKey, err := x.parseX509PrivateKey(privKey)
			if err != nil {
				return nil, nil, err
			}
			privKeys[idx] = privateKey
		}

		createdPrivKeys, err = x.persistPrivateKeys(txCtx, privKeys)
		if err != nil {
			return nil, nil, err
		}
	}

	toBeCreatedCerts, alreadyExistingCerts, err := x.filterToBeCreatedCertificates(txCtx, certPems)
	if err != nil {
		return nil, nil, err
	}

	privKeyLinkDeferredCertUpdates, err := x.linkPrivateKeysToCertificates(txCtx, createdPrivKeys, toBeCreatedCerts)
	if err != nil {
		return nil, nil, err
	}

	err = x.linkParentCertificatesAmongThemselves(toBeCreatedCerts)
	if err != nil {
		return nil, nil, err
	}
	err = x.linkCertificatesFromDBAsParents(txCtx, toBeCreatedCerts)
	if err != nil {
		return nil, nil, err
	}
	deferredCertUpdates, err := x.linkCertificatesAsParentsInDBCertificates(txCtx, toBeCreatedCerts)
	if err != nil {
		return nil, nil, err
	}

	createdCerts, err := x.sortAndPersistCertificates(txCtx, toBeCreatedCerts)
	if err != nil {
		return nil, nil, err
	}

	// Update all certificates in the DB which got a parent or a private key from the current import.
	// This has to be deferred because we first need to persist the import certificates and private keys.
	err = x.executeDeferredCertUpdates(txCtx, append(privKeyLinkDeferredCertUpdates, deferredCertUpdates...))
	if err != nil {
		return nil, nil, err
	}

	err = x.TransactionManager().CommitTx(txCtx)
	if err != nil {
		return nil, nil, err
	}

	certDtos := make([]*X509CertificateDto, len(createdCerts)+len(alreadyExistingCerts))
	for i, dao := range append(createdCerts, alreadyExistingCerts...) {
		certDtos[i] = certificateDaoToDto(dao)
	}
	privKeyDtos := make([]*X509PrivateKeyDto, len(createdPrivKeys))
	for i, dao := range createdPrivKeys {
		privKeyDtos[i] = privateKeyDaoToDto(dao)
	}

	return certDtos, privKeyDtos, nil
}

// filterToBeCreatedCertificates find existing certificates in the database and overwrite.
// This is necessary because the underlying DB should not allow duplicates.
// So we use the existing cert, primarily because of its ID we can use.
func (x *X509ImportService) filterToBeCreatedCertificates(
	txCtx context.Context, certPems []*pem.Block,
) (toBeCreatedCerts []*repository.X509CertificateDao, alreadyExistingCerts []*repository.X509CertificateDao, err error) {
	certPems = removeDuplicates(certPems)
	// parse deduplicated certificates
	parsedCerts := make([]*repository.X509CertificateDao, len(certPems))
	for idx, cert := range certPems {
		certificate, err := x.parseX509Certificate(cert)
		if err != nil {
			return nil, nil, err
		}
		parsedCerts[idx] = certificate
	}

	alreadyExistingCerts, err = x.findExistingCertificates(txCtx, parsedCerts)
	if err != nil {
		return nil, nil, err
	}

	toBeCreatedCerts = make([]*repository.X509CertificateDao, 0, len(parsedCerts))
	// Filter certificates which are not existingCerts and add them to the toBeCreatedCerts
outerLoop:
	for _, cert := range parsedCerts {
		for _, existingCert := range alreadyExistingCerts {
			if bytes.Equal(cert.BytesHash, existingCert.BytesHash) {
				continue outerLoop
			}
		}
		toBeCreatedCerts = append(toBeCreatedCerts, cert)
	}

	return toBeCreatedCerts, alreadyExistingCerts, nil
}

func (x *X509ImportService) persistPrivateKeys(
	ctx context.Context, privKeys []*repository.X509PrivateKeyDao,
) (createdPrivKeys []*repository.X509PrivateKeyDao, err error) {
	createdPrivKeys = make([]*repository.X509PrivateKeyDao, len(privKeys))
	for idx, privKey := range privKeys {
		foundOrCreated, err := x.X509PrivateKeyRepository().GetOrCreate(ctx, privKey)
		if err != nil {
			return nil, err
		}
		createdPrivKeys[idx] = foundOrCreated
	}

	return createdPrivKeys, nil
}

func (x *X509ImportService) linkPrivateKeysToCertificates(
	ctx context.Context, privKeys []*repository.X509PrivateKeyDao, certs []*repository.X509CertificateDao,
) (deferredUpdates []*repository.X509CertificateDao, err error) {
	for _, cert := range certs {
	privKeyLoop:
		// Find key with matching public key hash in import list
		for _, privKey := range privKeys {
			if bytes.Equal(cert.PublicKeyHash, privKey.PublicKeyHash) {
				cert.PrivateKeyID = &privKey.ID
				break privKeyLoop
			}
		}

		// If no matching key was found, try to find one in the database
		if cert.PrivateKeyID == nil {
			privKey, exists, err := x.X509PrivateKeyRepository().FindByPublicKeyHash(ctx, cert.PublicKeyHash)
			if err != nil {
				return nil, err
			}
			if exists {
				cert.PrivateKeyID = &privKey.ID
			} else {
				// TODO: add logging
			}
		}
	}

	// Find certificates in DB with no private key set which match public key hash from the import list
	// and set the private key ID
	for _, privKey := range privKeys {
		foundCerts, err := x.X509CertificateRepository().FindByPublicKeyHashAndNoPrivateKeySet(ctx, privKey.PublicKeyHash)
		if err != nil {
			return nil, err
		}
		for _, foundCert := range foundCerts {
			foundCert.PrivateKeyID = &privKey.ID
		}
		deferredUpdates = append(deferredUpdates, foundCerts...)
	}

	return deferredUpdates, err
}

func (x *X509ImportService) linkParentCertificatesAmongThemselves(
	certs []*repository.X509CertificateDao,
) error {
	parsedCerts, err := parseCerts(certs)
	if err != nil {
		return err
	}

	// Tries to link up certificates in the import list
	for _, cert := range certs {
		for _, potentialParentCert := range certs {
			if cert.ID == potentialParentCert.ID {
				continue
			}

			parsedCert, certExists := parsedCerts[cert.ID]
			if !certExists {
				panic(fmt.Errorf("certificate with ID %s not found in parsedCerts", cert.ID))
			}

			parsedParentCert, parsedParentCertExists := parsedCerts[potentialParentCert.ID]
			if !parsedParentCertExists {
				panic(fmt.Errorf("certificate with ID %s not found in parsedCerts", potentialParentCert.ID))
			}

			if parsedCert.CheckSignatureFrom(parsedParentCert) == nil {
				cert.ParentCertificateID = &potentialParentCert.ID
			}
		}
	}
	return nil
}

func (x *X509ImportService) linkCertificatesFromDBAsParents(
	ctx context.Context, certs []*repository.X509CertificateDao,
) error {
	parsedCerts, err := parseCerts(certs)
	if err != nil {
		return err
	}

	for _, cert := range certs {
		parsedCert, certExists := parsedCerts[cert.ID]
		if !certExists {
			panic(fmt.Errorf("certificate with ID %s not found in parsedCerts", cert.ID))
		}

		potentialParentCerts, err := x.X509CertificateRepository().FindBySubjectHash(ctx, cert.IssuerHash)
		if err != nil {
			return err
		}
		for _, potentialParentCert := range potentialParentCerts {
			parsedPotentialParentCert, err := x509.ParseCertificate(potentialParentCert.Bytes)
			if err != nil {
				return err
			}

			if parsedCert.CheckSignatureFrom(parsedPotentialParentCert) == nil {
				cert.ParentCertificateID = &potentialParentCert.ID
			}
		}
	}

	return nil
}

// linkCertificatesAsParentsInDBCertificates finds certificates in the DB where the parent certificate is not set
// and try to find a parent certificate for them in the supplied certs slice (probably from import list).
func (x *X509ImportService) linkCertificatesAsParentsInDBCertificates(
	ctx context.Context, certs []*repository.X509CertificateDao,
) (deferredUpdates []*repository.X509CertificateDao, err error) {
	parsedCerts, err := parseCerts(certs)
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		parsedCert, certExists := parsedCerts[cert.ID]
		if !certExists {
			panic(fmt.Errorf("certificate with ID %s not found in parsedCerts", cert.ID))
		}

		// The issuer of the certificate to find must be the subject of the current cert in the import list
		potentialChildCerts, err := x.X509CertificateRepository().FindByIssuerHashAndNoParentSet(ctx, cert.SubjectHash)
		if err != nil {
			return nil, err
		}
		for _, potentialChildCert := range potentialChildCerts {
			parsedPotentialChildCert, err := x509.ParseCertificate(potentialChildCert.Bytes)
			if err != nil {
				return nil, err
			}

			if parsedPotentialChildCert.CheckSignatureFrom(parsedCert) == nil {
				potentialChildCert.ParentCertificateID = &cert.ID
				deferredUpdates = append(deferredUpdates, potentialChildCert)
			}
		}
	}

	return deferredUpdates, nil
}

func parseCerts(certs []*repository.X509CertificateDao) (map[uuid.UUID]*x509.Certificate, error) {
	var parsedCerts map[uuid.UUID]*x509.Certificate
	for _, cert := range certs {
		if parsedCerts == nil {
			parsedCerts = make(map[uuid.UUID]*x509.Certificate)
		}

		parsedCert, err := x509.ParseCertificate(cert.Bytes)
		if err != nil {
			return nil, err
		}

		parsedCerts[cert.ID] = parsedCert
	}
	return parsedCerts, nil
}

// executeDeferredCertUpdates executes the deferred updates for certificates already in the database,
// where the new parent must have first been inserted before the update to satisfy foreign key constraints.
func (x *X509ImportService) executeDeferredCertUpdates(ctx context.Context, deferredCertUpdates []*repository.X509CertificateDao) error {
	for _, cert := range deferredCertUpdates {
		_, updated, err := x.X509CertificateRepository().Update(ctx, cert)
		if err != nil {
			return err
		}
		if !updated {
			panic(fmt.Errorf("certificate %s was supposed to be updated but it wasnt", cert.ID))
		}
	}
	return nil
}

func (x *X509ImportService) sortAndPersistCertificates(
	ctx context.Context, certs []*repository.X509CertificateDao,
) ([]*repository.X509CertificateDao, error) {
	edges, noEdges, err := buildCertParentToChildGraph(certs)
	if err != nil {
		return nil, err
	}
	sortedCerts, err := topologicalSortCerts(edges)
	if err != nil {
		return nil, err
	}

	// Add certificates with no edges to the end of the list
	sortedCerts = append(sortedCerts, noEdges...)

	var createdCerts []*repository.X509CertificateDao
	// Persist certificates in sorted order
	for _, cert := range sortedCerts {
		foundOrCreatedCert, err := x.X509CertificateRepository().GetOrCreate(ctx, cert)
		if err != nil {
			return nil, err
		}
		createdCerts = append(createdCerts, foundOrCreatedCert)
	}

	return createdCerts, nil
}

func buildCertParentToChildGraph(
	certs []*repository.X509CertificateDao,
) (
	edges map[*repository.X509CertificateDao][]*repository.X509CertificateDao,
	noEdges []*repository.X509CertificateDao,
	err error,
) {
	parsedCerts, err := parseCerts(certs)
	if err != nil {
		return nil, nil, err
	}

	// parent -> all child cert list
	edges = make(map[*repository.X509CertificateDao][]*repository.X509CertificateDao)
	inEdges := make(map[*repository.X509CertificateDao]bool)

	for _, parent := range certs {
		for _, child := range certs {
			if parent == child {
				continue
			}

			parsedChildCert, childCertExists := parsedCerts[child.ID]
			if !childCertExists {
				panic(fmt.Errorf("certificate with ID %s not found in parsedCerts", child.ID))
			}
			parsedParentCert, parsedParentCertExists := parsedCerts[parent.ID]
			if !parsedParentCertExists {
				panic(fmt.Errorf("certificate with ID %s not found in parsedCerts", parent.ID))
			}

			if parsedChildCert.CheckSignatureFrom(parsedParentCert) == nil {
				edges[parent] = append(edges[parent], child)
				inEdges[parent] = true
				inEdges[child] = true
			}
		}
	}

	noEdges = make([]*repository.X509CertificateDao, 0)
	for _, certificate := range certs {
		if !inEdges[certificate] {
			noEdges = append(noEdges, certificate)
		}
	}

	return edges, noEdges, nil
}

func topologicalSortCerts(
	edges map[*repository.X509CertificateDao][]*repository.X509CertificateDao,
) ([]*repository.X509CertificateDao, error) {
	var result []*repository.X509CertificateDao
	visited := make(map[*repository.X509CertificateDao]bool)
	var visit func(certificate *repository.X509CertificateDao) error

	visit = func(edge *repository.X509CertificateDao) error {
		if visited[edge] {
			return nil
		}
		visited[edge] = true
		for _, dependent := range edges[edge] {
			if err := visit(dependent); err != nil {
				return err
			}
		}
		result = append([]*repository.X509CertificateDao{edge}, result...)
		return nil
	}

	for element := range edges {
		if !visited[element] {
			if err := visit(element); err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

func (x *X509ImportService) parseX509Certificate(certPem *pem.Block) (*repository.X509CertificateDao, error) {
	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, err
	}

	certPubKeyHash, err := computePublicKeyTypeSpecificHash(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	return repository.NewX509CertificateDao(
		uuid.New(),
		cert.Subject.CommonName,
		cert.DNSNames,
		ComputeSubjectOrIssuerHash(cert.Issuer),
		ComputeSubjectOrIssuerHash(cert.Subject),
		ComputeBytesHash(cert.Raw),
		cert.Raw,
		certPubKeyHash,
		nil,
		nil,
		cert.NotBefore,
		cert.NotAfter,
		x.clock.Now(),
	), nil
}

func (x *X509ImportService) parseX509PrivateKey(privKeyPem *pem.Block) (*repository.X509PrivateKeyDao, error) {
	privKey, privKeyType, err := ParsePrivateKey(privKeyPem.Bytes)
	if err != nil {
		return nil, err
	}

	pubKeyHash, err := ComputePublicKeyTypeSpecificHashFromPrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	return repository.NewX509PrivateKeyDao(
		uuid.New(),
		repository.PrivateKeyType(privKeyType),
		privKeyPem.Type,
		ComputeBytesHash(privKeyPem.Bytes),
		privKeyPem.Bytes,
		pubKeyHash,
		x.clock.Now(),
	), nil
}

// findExistingCertificates attaches already existing certificates to the given list of certificates and replaces them.
// This is necessary because we are required to avoid duplicate certificates in the database.
func (x *X509ImportService) findExistingCertificates(ctx context.Context, certs []*repository.X509CertificateDao) ([]*repository.X509CertificateDao, error) {
	certByteHashes := make([]*[]byte, len(certs))
	for i, cert := range certs {
		certByteHashes[i] = &cert.BytesHash
	}

	fetchedCerts, err := x.X509CertificateRepository().FindAllByByteHashes(ctx, certByteHashes)
	if err != nil {
		return nil, err
	}

	return fetchedCerts, nil
}

func removeDuplicates[T comparable](slices []T) []T {
	allKeys := make(map[T]bool)
	var list []T
	for _, item := range slices {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
