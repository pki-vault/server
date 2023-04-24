package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/volatiletech/sqlboiler/v4/boil"
)

type TxCtxKey struct{}

type TransactionManager struct {
	db *sql.DB
}

func NewTransactionManager(db *sql.DB) *TransactionManager {
	return &TransactionManager{db: db}
}

func (t *TransactionManager) BeginTx(ctx context.Context) (context.Context, error) {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create transaction: %w", err)
	}
	return context.WithValue(ctx, TxCtxKey{}, tx), nil
}

func (t *TransactionManager) CommitTx(ctx context.Context) error {
	tx, ok := ctx.Value(TxCtxKey{}).(*sql.Tx)
	if !ok {
		return errors.New("no transaction found in context")
	}
	return tx.Commit()
}

func (t *TransactionManager) RollbackTx(ctx context.Context) error {
	tx, ok := ctx.Value(TxCtxKey{}).(*sql.Tx)
	if !ok {
		return errors.New("no transaction found in context")
	}
	return tx.Rollback()
}

func getCtxTxOrExecutor(ctx context.Context, db *sql.DB) (boil.ContextExecutor, error) {
	if ctx == nil {
		return db, nil
	}

	tx, ok := ctx.Value(TxCtxKey{}).(*sql.Tx)
	if ok {
		return tx, nil
	}

	return db, nil
}

func getOrCreateTx(ctx context.Context, db *sql.DB) (tx *sql.Tx, txCtx context.Context, controlsTx bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// Try to get tx form ctx
	var ok bool
	tx, ok = ctx.Value(TxCtxKey{}).(*sql.Tx)
	if ok {
		txCtx = ctx
	} else {
		tx, err = db.BeginTx(ctx, nil)
		if err != nil {
			return nil, nil, false, fmt.Errorf("cannot create database transaction: %w", err)
		}
		txCtx = context.WithValue(ctx, TxCtxKey{}, tx)
		controlsTx = true
	}

	// Got tx from context, we don't control it
	return tx, txCtx, controlsTx, err
}

func rollbackTxOnErrIfControlling(tx *sql.Tx, err *error, controlsTx bool) {
	if p := recover(); p != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return
		}
		if rollbackErr != nil {
			panic(fmt.Errorf("unable to rollback transaction for panic: %s: %w", p, rollbackErr))
		}
		panic(p)
	}
	if err != nil && *err != nil && controlsTx {
		if tx == nil {
			panic(fmt.Errorf("unable to rollback undefined transaction for error: %w", *err))
		}
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			panic(fmt.Errorf("unable to rollback transaction for error: %s: %w", (*err).Error(), rollbackErr))
		}
	}
}

func commitTxIfControlling(tx *sql.Tx, controlsTx bool) error {
	if tx != nil && controlsTx {
		return tx.Commit()
	}
	return nil
}
