package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	postgresqlmodels "github.com/pki-vault/server/internal/db/postgresql/models"
	"github.com/pki-vault/server/internal/db/repository"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"github.com/volatiletech/sqlboiler/v4/types"
	"time"
)

type X509CertificateRepository struct {
	db                   *sql.DB
	privateKeyRepository *X509PrivateKeyRepository
	clock                clockwork.Clock
}

func NewX509CertificateRepository(db *sql.DB, privateKeyRepository *X509PrivateKeyRepository, clock clockwork.Clock) *X509CertificateRepository {
	return &X509CertificateRepository{db: db, privateKeyRepository: privateKeyRepository, clock: clock}
}

func (r *X509CertificateRepository) GetOrCreate(
	ctx context.Context, cert *repository.X509CertificateDao,
) (*repository.X509CertificateDao, error) {
	tx, ctx, controlsTx, err := getOrCreateTx(ctx, r.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnErrIfControlling(tx, &err, controlsTx)

	fetchedCert, err := postgresqlmodels.X509Certificates(postgresqlmodels.X509CertificateWhere.BytesHash.EQ(cert.BytesHash)).One(ctx, tx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if fetchedCert != nil {
		return postgresqlCertificateToDao(fetchedCert), commitTxIfControlling(tx, controlsTx)
	}

	certModel := r.postgresqlCertificateToModel(cert)
	err = certModel.Insert(ctx, tx, boil.Infer())
	if err != nil {
		return nil, err
	}

	return postgresqlCertificateToDao(certModel), commitTxIfControlling(tx, controlsTx)
}

func (r *X509CertificateRepository) Update(ctx context.Context, cert *repository.X509CertificateDao) (updatedCert *repository.X509CertificateDao, updated bool, err error) {
	tx, ctx, controlsTx, err := getOrCreateTx(ctx, r.db)
	if err != nil {
		return nil, false, err
	}
	defer rollbackTxOnErrIfControlling(tx, &err, controlsTx)

	certModel := r.postgresqlCertificateToModel(cert)
	updatedRows, err := certModel.Update(ctx, tx, boil.Infer())
	if err != nil {
		return nil, false, err
	}

	return postgresqlCertificateToDao(certModel), updatedRows != 0, commitTxIfControlling(tx, controlsTx)
}

func (r *X509CertificateRepository) FindByIssuerHashAndNoParentSet(ctx context.Context, issuerHash []byte) ([]*repository.X509CertificateDao, error) {
	executor, err := getCtxTxOrExecutor(ctx, r.db)
	if err != nil {
		return nil, fmt.Errorf("failed to get executor: %w", err)
	}

	fetchedCerts, err := postgresqlmodels.X509Certificates(
		postgresqlmodels.X509CertificateWhere.IssuerHash.EQ(issuerHash),
		postgresqlmodels.X509CertificateWhere.ParentCertificateID.IsNull(),
	).All(ctx, executor)
	if err != nil {
		return nil, err
	}

	var convertedCerts []*repository.X509CertificateDao
	for _, cert := range fetchedCerts {
		convertedCerts = append(convertedCerts, postgresqlCertificateToDao(cert))
	}

	return convertedCerts, nil
}

func (r *X509CertificateRepository) FindByPublicKeyHashAndNoPrivateKeySet(ctx context.Context, pubKeyHash []byte) ([]*repository.X509CertificateDao, error) {
	executor, err := getCtxTxOrExecutor(ctx, r.db)
	if err != nil {
		return nil, fmt.Errorf("failed to get executor: %w", err)
	}

	fetchedCerts, err := postgresqlmodels.X509Certificates(
		postgresqlmodels.X509CertificateWhere.PublicKeyHash.EQ(pubKeyHash),
		postgresqlmodels.X509CertificateWhere.PrivateKeyID.IsNull(),
	).All(ctx, executor)
	if err != nil {
		return nil, err
	}

	var convertedCerts []*repository.X509CertificateDao
	for _, cert := range fetchedCerts {
		convertedCerts = append(convertedCerts, postgresqlCertificateToDao(cert))
	}

	return convertedCerts, nil
}

func (r *X509CertificateRepository) FindBySubjectHash(ctx context.Context, subjectHash []byte) ([]*repository.X509CertificateDao, error) {
	executor, err := getCtxTxOrExecutor(ctx, r.db)
	if err != nil {
		return nil, fmt.Errorf("failed to get executor: %w", err)
	}

	fetchedCerts, err := postgresqlmodels.X509Certificates(postgresqlmodels.X509CertificateWhere.SubjectHash.EQ(subjectHash)).
		All(ctx, executor)
	if err != nil {
		return nil, err
	}

	var convertedCerts []*repository.X509CertificateDao
	for _, cert := range fetchedCerts {
		convertedCerts = append(convertedCerts, postgresqlCertificateToDao(cert))
	}

	return convertedCerts, nil
}

func (r *X509CertificateRepository) FindAllByByteHashes(ctx context.Context, byteHashes []*[]byte) ([]*repository.X509CertificateDao, error) {
	executor, err := getCtxTxOrExecutor(ctx, r.db)
	if err != nil {
		return nil, fmt.Errorf("failed to get executor: %w", err)
	}

	mods := make([]qm.QueryMod, len(byteHashes))
	for i, byteHash := range byteHashes {
		mods[i] = qm.Or2(postgresqlmodels.X509CertificateWhere.BytesHash.EQ(*byteHash))
	}

	fetchedCerts, err := postgresqlmodels.X509Certificates(mods...).
		All(ctx, executor)
	if err != nil {
		return nil, err
	}

	var convertedCerts []*repository.X509CertificateDao
	for _, cert := range fetchedCerts {
		convertedCerts = append(convertedCerts, postgresqlCertificateToDao(cert))
	}
	return convertedCerts, nil
}

func (r *X509CertificateRepository) FindLatestActiveBySANsAndCreatedAtAfter(
	ctx context.Context, subjectAltNames []string, sinceAfter time.Time,
) ([]*repository.X509CertificateDao, error) {
	executor, err := getCtxTxOrExecutor(ctx, r.db)
	if err != nil {
		return nil, fmt.Errorf("failed to get executor: %w", err)
	}

	query := queries.Raw(`SELECT * FROM get_certificate_updates($1::text[], $2::timestamp);`, types.Array(subjectAltNames), sinceAfter)

	var fetchedCerts []*postgresqlmodels.X509Certificate
	err = query.Bind(ctx, executor, &fetchedCerts)
	if err != nil {
		return nil, err
	}

	convertedCertDaos := make([]*repository.X509CertificateDao, len(fetchedCerts))
	for i, foundCert := range fetchedCerts {
		convertedCertDaos[i] = postgresqlCertificateToDao(foundCert)
	}

	return convertedCertDaos, nil
}

func (r *X509CertificateRepository) FindCertificateChain(ctx context.Context, startCertId uuid.UUID) ([]*repository.X509CertificateDao, error) {
	executor, err := getCtxTxOrExecutor(ctx, r.db)
	if err != nil {
		return nil, fmt.Errorf("failed to get executor: %w", err)
	}

	query := queries.Raw(`SELECT * FROM get_certificate_chain($1);`, startCertId.String())

	var fetchedCerts []*postgresqlmodels.X509Certificate
	err = query.Bind(ctx, executor, &fetchedCerts)
	if err != nil {
		return nil, err
	}

	var convertedCerts []*repository.X509CertificateDao
	for _, foundCert := range fetchedCerts {
		convertedCerts = append(convertedCerts, postgresqlCertificateToDao(foundCert))
	}

	return convertedCerts, nil
}

func (r *X509CertificateRepository) postgresqlCertificateToModel(
	cert *repository.X509CertificateDao,
) *postgresqlmodels.X509Certificate {
	var parentCertID null.String
	if cert.ParentCertificateID != nil {
		parentCertID = null.StringFrom(cert.ParentCertificateID.String())
	}
	var privKeyID null.String
	if cert.PrivateKeyID != nil {
		privKeyID = null.StringFrom(cert.PrivateKeyID.String())
	}

	return &postgresqlmodels.X509Certificate{
		ID:                  cert.ID.String(),
		CommonName:          cert.CommonName,
		SubjectAltNames:     cert.SubjectAltNames,
		IssuerHash:          cert.IssuerHash,
		SubjectHash:         cert.SubjectHash,
		BytesHash:           cert.BytesHash,
		Bytes:               cert.Bytes,
		PublicKeyHash:       cert.PublicKeyHash,
		ParentCertificateID: parentCertID,
		PrivateKeyID:        privKeyID,
		NotBefore:           normalizeTime(cert.NotBefore),
		NotAfter:            normalizeTime(cert.NotAfter),
		CreatedAt:           normalizeTime(r.clock.Now()),
	}
}

func postgresqlCertificateToDao(
	cert *postgresqlmodels.X509Certificate,
) *repository.X509CertificateDao {
	var parentCertID *uuid.UUID
	if cert.ParentCertificateID.Valid {
		tempUuid := uuid.MustParse(cert.ParentCertificateID.String)
		parentCertID = &tempUuid
	}
	var privKeyID *uuid.UUID
	if cert.PrivateKeyID.Valid {
		temp := uuid.MustParse(cert.PrivateKeyID.String)
		privKeyID = &temp
	}

	return repository.NewX509CertificateDao(
		uuid.MustParse(cert.ID),
		cert.CommonName,
		cert.SubjectAltNames,
		cert.IssuerHash,
		cert.SubjectHash,
		cert.BytesHash,
		cert.Bytes,
		cert.PublicKeyHash,
		parentCertID,
		privKeyID,
		normalizeTime(cert.NotBefore),
		normalizeTime(cert.NotAfter),
		normalizeTime(cert.CreatedAt),
	)
}
