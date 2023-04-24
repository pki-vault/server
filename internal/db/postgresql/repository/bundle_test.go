package repository

import (
	"github.com/pki-vault/server/internal/testutil"
	"reflect"
	"testing"
)

func TestNewRepositoryBundle(t *testing.T) {
	type args struct {
		x509CertificateRepository             *X509CertificateRepository
		x509CertificateSubscriptionRepository *X509CertificateSubscriptionRepository
		privateKeyRepository                  *X509PrivateKeyRepository
		transactionManager                    *TransactionManager
	}
	tests := []struct {
		name string
		args args
		want *Bundle
	}{
		{
			name: "ensure all fields are set",
			args: args{
				x509CertificateRepository:             &X509CertificateRepository{},
				x509CertificateSubscriptionRepository: &X509CertificateSubscriptionRepository{},
				privateKeyRepository:                  &X509PrivateKeyRepository{},
				transactionManager:                    &TransactionManager{},
			},
			want: &Bundle{
				x509CertificateRepository:             &X509CertificateRepository{},
				x509CertificateSubscriptionRepository: &X509CertificateSubscriptionRepository{},
				privateKeyRepository:                  &X509PrivateKeyRepository{},
				transactionManager:                    &TransactionManager{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewRepositoryBundle(tt.args.x509CertificateRepository, tt.args.x509CertificateSubscriptionRepository, tt.args.privateKeyRepository, tt.args.transactionManager)
			if !testutil.AllFieldsNotNilOrEmptyStruct(got) {
				t.Errorf("NewRepositoryBundle() not all fields are set")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRepositoryBundle() = %v, want %v", got, tt.want)
			}
		})
	}
}
