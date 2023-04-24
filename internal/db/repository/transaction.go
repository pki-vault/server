package repository

//go:generate mockgen -destination=../../mocks/db/transaction.go -source transaction.go

import "context"

type TransactionManager interface {
	BeginTx(ctx context.Context) (txCtx context.Context, err error)
	CommitTx(txCtx context.Context) error
	RollbackTx(txCtx context.Context) error
}
