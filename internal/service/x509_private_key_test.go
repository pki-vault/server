package service

import (
	"context"
	"encoding/pem"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/db/repository"
	mock_repository "github.com/pki-vault/server/internal/mocks/db"
	"github.com/pki-vault/server/internal/testutil"
	"reflect"
	"testing"
	"time"
)

func TestDefaultX509PrivateKeyService_GetOrCreate(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	ctx := context.Background()
	certRepo := mock_repository.NewMockX509PrivateKeyRepository(ctrl)

	toBeCreated := readPemFile(t, "testdata/private_keys/pkcs8_rsa_2048.pem")
	var expectedKeyUuid uuid.UUID

	certRepo.
		EXPECT().
		GetOrCreate(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, privKey *repository.X509PrivateKeyDao) (*repository.X509PrivateKeyDao, error) {
			expectedKeyUuid = privKey.ID
			return privKey, nil
		})

	service := NewDefaultX509PrivateKeyService(certRepo, fakeClock)
	createdKey, err := service.GetOrCreate(ctx, &CreatePrivateKeyRequest{
		PrivateKey: toBeCreated,
	})
	if err != nil {
		t.Errorf("GetOrCreate() got unexpected error: %v", err)
	}

	expectedKey := &X509PrivateKeyDto{
		ID:            expectedKeyUuid,
		PrivateKeyPem: string(pem.EncodeToMemory(toBeCreated)),
		CreatedAt:     fakeClock.Now(),
	}
	if !reflect.DeepEqual(createdKey, expectedKey) {
		t.Errorf("GetOrCreate() expected key to be %v, but got %v", expectedKey, createdKey)
	}
}

func TestNewDefaultX509PrivateKeyService(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	ctrl := gomock.NewController(t)
	certRepo := mock_repository.NewMockX509PrivateKeyRepository(ctrl)

	t.Cleanup(ctrl.Finish)

	type args struct {
		certRepo repository.X509PrivateKeyRepository
		clock    clockwork.Clock
	}
	tests := []struct {
		name string
		args args
		want *DefaultX509PrivateKeyService
	}{
		{
			name: "ensure all fields are set",
			args: args{
				certRepo: certRepo,
				clock:    fakeClock,
			},
			want: &DefaultX509PrivateKeyService{
				certRepo: certRepo,
				clock:    fakeClock,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewDefaultX509PrivateKeyService(tt.args.certRepo, tt.args.clock)
			if !testutil.AllFieldsNotNilOrEmptyStruct(got) {
				t.Errorf("NewDefaultX509PrivateKeyService() not all fields are set")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDefaultX509PrivateKeyService() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewX509PrivateKeyDto(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()

	type args struct {
		ID            uuid.UUID
		pemPrivateKey string
		createdAt     time.Time
	}
	tests := []struct {
		name string
		args args
		want *X509PrivateKeyDto
	}{
		{
			name: "ensure correct transform",
			args: args{
				ID:            uuid.MustParse("db79f4ba-18cb-4c6e-8712-2821b2696d50"),
				pemPrivateKey: "-----BEGIN PRIVATE KEY-----\ncmFuZG9tIGRhdGE=\n-----END PRIVATE KEY-----\n",
				createdAt:     fakeClock.Now(),
			},
			want: &X509PrivateKeyDto{
				ID:            uuid.MustParse("db79f4ba-18cb-4c6e-8712-2821b2696d50"),
				PrivateKeyPem: "-----BEGIN PRIVATE KEY-----\ncmFuZG9tIGRhdGE=\n-----END PRIVATE KEY-----\n",
				CreatedAt:     fakeClock.Now(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewX509PrivateKeyDto(tt.args.ID, tt.args.pemPrivateKey, tt.args.createdAt); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewX509PrivateKeyDto() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_privateKeyDaoToDto(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()

	type args struct {
		privKey *repository.X509PrivateKeyDao
	}
	tests := []struct {
		name string
		args args
		want *X509PrivateKeyDto
	}{
		{
			name: "ensure correct transform",
			args: args{
				privKey: &repository.X509PrivateKeyDao{
					ID:           uuid.MustParse("db79f4ba-18cb-4c6e-8712-2821b2696d50"),
					Type:         "RSA",
					PemBlockType: "PRIVATE KEY",
					Bytes:        []byte("random data"),
					CreatedAt:    fakeClock.Now(),
				},
			},
			want: &X509PrivateKeyDto{
				ID:            uuid.MustParse("db79f4ba-18cb-4c6e-8712-2821b2696d50"),
				PrivateKeyPem: "-----BEGIN PRIVATE KEY-----\ncmFuZG9tIGRhdGE=\n-----END PRIVATE KEY-----\n",
				CreatedAt:     fakeClock.Now(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := privateKeyDaoToDto(tt.args.privKey); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("privateKeyDaoToDto() = %v, want %v", got, tt.want)
			}
		})
	}
}
