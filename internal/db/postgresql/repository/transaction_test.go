package repository

import (
	"context"
	"database/sql"
	"github.com/pki-vault/server/internal/testutil"
	"reflect"
	"testing"
)

func TestNewTransactionManager(t *testing.T) {
	type args struct {
		db *sql.DB
	}
	tests := []struct {
		name string
		args args
		want *TransactionManager
	}{
		{
			name: "ensure all fields are set",
			args: args{
				postgresqlTestBackend.Db(),
			},
			want: &TransactionManager{db: postgresqlTestBackend.Db()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTransactionManager(tt.args.db)
			if !testutil.AllFieldsNotNilOrEmptyStruct(got) {
				t.Errorf("NewTransactionManager() not all fields are set")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTransactionManager() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTransactionManager_BeginTx(t *testing.T) {
	type fields struct {
		db *sql.DB
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantTxCtx context.Context
		wantErr   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &TransactionManager{
				db: tt.fields.db,
			}
			gotTxCtx, err := p.BeginTx(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("BeginTx() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotTxCtx, tt.wantTxCtx) {
				t.Errorf("BeginTx() gotTxCtx = %v, want %v", gotTxCtx, tt.wantTxCtx)
			}
		})
	}
}

func TestTransactionManager_CommitTx(t *testing.T) {
	type fields struct {
		db *sql.DB
	}
	type args struct {
		txCtx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &TransactionManager{
				db: tt.fields.db,
			}
			if err := p.CommitTx(tt.args.txCtx); (err != nil) != tt.wantErr {
				t.Errorf("CommitTx() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTransactionManager_RollbackTx(t *testing.T) {
	type fields struct {
		db *sql.DB
	}
	type args struct {
		txCtx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &TransactionManager{
				db: tt.fields.db,
			}
			if err := p.RollbackTx(tt.args.txCtx); (err != nil) != tt.wantErr {
				t.Errorf("RollbackTx() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getOrCreateTx(t *testing.T) {
	type args struct {
		ctx context.Context
		db  *sql.DB
	}
	tests := []struct {
		name           string
		args           args
		wantTx         *sql.Tx
		wantTxCtx      context.Context
		wantControlsTx bool
		wantErr        bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTx, gotTxCtx, gotControlsTx, err := getOrCreateTx(tt.args.ctx, tt.args.db)
			if (err != nil) != tt.wantErr {
				t.Errorf("getOrCreateTx() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotTx, tt.wantTx) {
				t.Errorf("getOrCreateTx() gotTx = %v, want %v", gotTx, tt.wantTx)
			}
			if !reflect.DeepEqual(gotTxCtx, tt.wantTxCtx) {
				t.Errorf("getOrCreateTx() gotTxCtx = %v, want %v", gotTxCtx, tt.wantTxCtx)
			}
			if gotControlsTx != tt.wantControlsTx {
				t.Errorf("getOrCreateTx() gotControlsTx = %v, want %v", gotControlsTx, tt.wantControlsTx)
			}
		})
	}
}

func Test_rollbackTxOnErrIfControlling(t *testing.T) {
	type args struct {
		tx         *sql.Tx
		err        error
		controlsTx bool
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rollbackTxOnErrIfControlling(tt.args.tx, &tt.args.err, tt.args.controlsTx)
		})
	}
}
