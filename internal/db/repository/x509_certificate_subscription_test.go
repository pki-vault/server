package repository

import (
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/testutil"
	"reflect"
	"testing"
	"time"
)

func TestNewX509CertificateSubscriptionDao(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()

	type args struct {
		ID                uuid.UUID
		subjectAltNames   []string
		includePrivateKey bool
		createdAt         time.Time
	}
	tests := []struct {
		name string
		args args
		want *X509CertificateSubscriptionDao
	}{
		{
			name: "ensure all fields are set",
			args: args{
				ID:                uuid.MustParse("996bdde6-6f96-4006-8a73-e8d66e0d5630"),
				subjectAltNames:   []string{"example.invalid", "test.example.invalid"},
				includePrivateKey: true,
				createdAt:         fakeClock.Now(),
			},
			want: &X509CertificateSubscriptionDao{
				ID:                uuid.MustParse("996bdde6-6f96-4006-8a73-e8d66e0d5630"),
				SubjectAltNames:   []string{"example.invalid", "test.example.invalid"},
				IncludePrivateKey: true,
				CreatedAt:         fakeClock.Now(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewX509CertificateSubscriptionDao(tt.args.ID, tt.args.subjectAltNames, tt.args.includePrivateKey, tt.args.createdAt)
			if !testutil.AllFieldsNotNilOrEmptyStruct(got) {
				t.Errorf("NewX509CertificateSubscriptionDao() not all fields are set")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewX509CertificateSubscriptionDao() = %v, want %v", got, tt.want)
			}
		})
	}
}
