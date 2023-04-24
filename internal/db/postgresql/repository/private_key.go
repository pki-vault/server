package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/db/postgresql/models"
	"github.com/pki-vault/server/internal/db/repository"
	"github.com/volatiletech/sqlboiler/v4/boil"
)

type X509PrivateKeyRepository struct {
	db    *sql.DB
	clock clockwork.Clock
}

func NewX509PrivateKeyRepository(db *sql.DB, clock clockwork.Clock) *X509PrivateKeyRepository {
	return &X509PrivateKeyRepository{db: db, clock: clock}
}

func (p *X509PrivateKeyRepository) GetOrCreate(
	ctx context.Context, privKey *repository.X509PrivateKeyDao,
) (*repository.X509PrivateKeyDao, error) {
	tx, ctx, controlsTx, err := getOrCreateTx(ctx, p.db)
	defer rollbackTxOnErrIfControlling(tx, &err, controlsTx)
	if err != nil {
		return nil, err
	}

	fetchedPrivKey, err := models.X509PrivateKeys(models.X509PrivateKeyWhere.PublicKeyHash.EQ(privKey.PublicKeyHash)).One(ctx, tx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if fetchedPrivKey != nil {
		return postgresqlPrivateKeyToDao(fetchedPrivKey), commitTxIfControlling(tx, controlsTx)
	}

	privKeyModel := p.postgresqlPrivateKeyToModel(privKey)
	err = privKeyModel.Insert(ctx, tx, boil.Infer())
	if err != nil {
		return nil, err
	}

	return postgresqlPrivateKeyToDao(privKeyModel), commitTxIfControlling(tx, controlsTx)
}

func (p *X509PrivateKeyRepository) FindByID(
	ctx context.Context, id uuid.UUID,
) (privKey *repository.X509PrivateKeyDao, exists bool, err error) {
	executor, err := getCtxTxOrExecutor(ctx, p.db)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get executor: %w", err)
	}

	privKeyModel, err := models.X509PrivateKeys(models.X509PrivateKeyWhere.ID.EQ(id.String())).One(ctx, executor)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}

	return postgresqlPrivateKeyToDao(privKeyModel), true, nil
}

func (p *X509PrivateKeyRepository) FindByIDs(
	ctx context.Context, ids []uuid.UUID,
) (privKeys []*repository.X509PrivateKeyDao, err error) {
	executor, err := getCtxTxOrExecutor(ctx, p.db)
	if err != nil {
		return nil, fmt.Errorf("failed to get executor: %w", err)
	}

	privKeyModels, err := models.X509PrivateKeys(models.X509PrivateKeyWhere.ID.IN(uuidsToStrings(ids))).All(ctx, executor)
	if err != nil {
		return nil, err
	}

	for _, privKeyModel := range privKeyModels {
		privKeys = append(privKeys, postgresqlPrivateKeyToDao(privKeyModel))
	}

	return privKeys, nil
}

func (p *X509PrivateKeyRepository) FindByPublicKeyHash(
	ctx context.Context, pubKeyHash []byte,
) (privKey *repository.X509PrivateKeyDao, exists bool, err error) {
	executor, err := getCtxTxOrExecutor(ctx, p.db)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get executor: %w", err)
	}

	privKeyModel, err := models.X509PrivateKeys(models.X509PrivateKeyWhere.PublicKeyHash.EQ(pubKeyHash)).One(ctx, executor)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}

	return postgresqlPrivateKeyToDao(privKeyModel), true, nil
}

func (p *X509PrivateKeyRepository) postgresqlPrivateKeyToModel(privKey *repository.X509PrivateKeyDao) *models.X509PrivateKey {
	return &models.X509PrivateKey{
		ID:            privKey.ID.String(),
		Type:          models.PrivateKeyType(privKey.Type),
		PemBlockType:  privKey.PemBlockType,
		Bytes:         privKey.Bytes,
		BytesHash:     privKey.BytesHash,
		PublicKeyHash: privKey.PublicKeyHash,
		CreatedAt:     normalizeTime(privKey.CreatedAt),
	}
}

func postgresqlPrivateKeyToDao(privateKey *models.X509PrivateKey) *repository.X509PrivateKeyDao {
	return repository.NewX509PrivateKeyDao(
		uuid.MustParse(privateKey.ID),
		repository.PrivateKeyType(privateKey.Type),
		privateKey.PemBlockType,
		privateKey.BytesHash,
		privateKey.Bytes,
		privateKey.PublicKeyHash,
		normalizeTime(privateKey.CreatedAt),
	)
}

func uuidsToStrings(ids []uuid.UUID) []string {
	var strings []string
	for _, id := range ids {
		strings = append(strings, id.String())
	}
	return strings
}
