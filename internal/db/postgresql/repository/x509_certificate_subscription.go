package repository

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/db/postgresql/models"
	"github.com/pki-vault/server/internal/db/repository"
	"github.com/volatiletech/sqlboiler/v4/boil"
)

type X509CertificateSubscriptionRepository struct {
	db    *sql.DB
	clock clockwork.Clock
}

func NewX509CertificateSubscriptionRepository(db *sql.DB, clock clockwork.Clock) *X509CertificateSubscriptionRepository {
	return &X509CertificateSubscriptionRepository{db: db, clock: clock}
}

func (x *X509CertificateSubscriptionRepository) Create(
	ctx context.Context, certSub *repository.X509CertificateSubscriptionDao,
) (*repository.X509CertificateSubscriptionDao, error) {
	tx, ctx, controlsTx, err := getOrCreateTx(ctx, x.db)
	defer rollbackTxOnErrIfControlling(tx, &err, controlsTx)
	if err != nil {
		return nil, err
	}

	sub := &models.X509CertificateSubscription{
		ID:                certSub.ID.String(),
		SubjectAltNames:   certSub.SubjectAltNames,
		IncludePrivateKey: certSub.IncludePrivateKey,
		CreatedAt:         normalizeTime(x.clock.Now()),
	}
	err = sub.Insert(ctx, x.db, boil.Infer())
	if err != nil {
		return nil, err
	}

	return postgresqlCertificateSubscriptionToDto(sub), commitTxIfControlling(tx, controlsTx)
}

func (x *X509CertificateSubscriptionRepository) FindByIDs(
	ctx context.Context, IDs []uuid.UUID,
) ([]*repository.X509CertificateSubscriptionDao, error) {
	executor, err := getCtxTxOrExecutor(ctx, x.db)
	if err != nil {
		return nil, fmt.Errorf("failed to get executor: %w", err)
	}

	var ids []string
	for _, id := range IDs {
		ids = append(ids, id.String())
	}

	fetchedSubs, err := models.
		X509CertificateSubscriptions(models.X509CertificateSubscriptionWhere.ID.IN(ids)).
		All(ctx, executor)
	if err != nil {
		return nil, err
	}

	var convertedSubs []*repository.X509CertificateSubscriptionDao
	for _, result := range fetchedSubs {
		convertedSubs = append(convertedSubs, postgresqlCertificateSubscriptionToDto(result))
	}
	return convertedSubs, nil
}

func (x *X509CertificateSubscriptionRepository) Delete(
	ctx context.Context, id uuid.UUID,
) (rowsDeleted int64, err error) {
	tx, ctx, controlsTx, err := getOrCreateTx(ctx, x.db)
	defer rollbackTxOnErrIfControlling(tx, &err, controlsTx)
	if err != nil {
		return 0, err
	}

	rowsDeleted, err = models.
		X509CertificateSubscriptions(models.X509CertificateSubscriptionWhere.ID.EQ(id.String())).
		DeleteAll(ctx, tx)
	if err != nil {
		return 0, err
	}

	return rowsDeleted, commitTxIfControlling(tx, controlsTx)
}

func postgresqlCertificateSubscriptionToDto(sub *models.X509CertificateSubscription) *repository.X509CertificateSubscriptionDao {
	return repository.NewX509CertificateSubscriptionDao(
		uuid.MustParse(sub.ID),
		sub.SubjectAltNames,
		sub.IncludePrivateKey,
		normalizeTime(sub.CreatedAt),
	)
}
