package restserver

import (
	"context"
	"encoding/pem"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	mock_service "github.com/pki-vault/server/internal/mocks/services"
	"github.com/pki-vault/server/internal/service"
	"github.com/pki-vault/server/internal/testutil"
	"go.uber.org/zap"
	"reflect"
	"testing"
	"time"
)

func TestNewRestHandlerImpl(t *testing.T) {
	type args struct {
		logger                             *zap.Logger
		x509CertificateSubscriptionService *service.DefaultX509CertificateSubscriptionService
		x509CertificateService             *service.DefaultX509CertificateService
		x509ImportService                  *service.DefaultX509ImportService
	}
	tests := []struct {
		name string
		args args
		want *RestHandlerImpl
	}{
		{
			name: "ensure all fields are set",
			args: args{
				logger:                             zap.NewNop(),
				x509CertificateSubscriptionService: &service.DefaultX509CertificateSubscriptionService{},
				x509CertificateService:             &service.DefaultX509CertificateService{},
				x509ImportService:                  &service.DefaultX509ImportService{},
			},
			want: &RestHandlerImpl{
				logger:                             zap.NewNop(),
				x509CertificateSubscriptionService: &service.DefaultX509CertificateSubscriptionService{},
				x509CertificateService:             &service.DefaultX509CertificateService{},
				x509ImportService:                  &service.DefaultX509ImportService{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewRestHandlerImpl(tt.args.logger, tt.args.x509CertificateSubscriptionService, tt.args.x509CertificateService, tt.args.x509ImportService)
			if !testutil.AllFieldsNotNilOrEmptyStruct(got) {
				t.Errorf("TestNewRestHandlerImpl() not all fields are set")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TestNewRestHandlerImpl() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRestHandlerImpl_BulkImportX509V1(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	logger := zap.NewNop()

	t.Run("certificates and private keys are created", func(t *testing.T) {
		ctx := context.Background()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		svc := mock_service.NewMockX509ImportService(ctrl)
		svc.
			EXPECT().
			Import(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(
				[]*service.X509CertificateDto{
					{
						ID:                  uuid.MustParse("536c7378-2563-40ac-a513-b423693cdaae"),
						CommonName:          "example.invalid",
						SubjectAltNames:     []string{"test.example.invalid"},
						CertificatePem:      "-----BEGIN CERTIFICATE-----\ncmFuZG9tIGRhdGE=\n-----END CERTIFICATE-----",
						ParentCertificateID: ptr(uuid.MustParse("48939f46-4f0a-458c-8bf6-e52136624c91")),
						PrivateKeyID:        ptr(uuid.MustParse("605831e4-eda5-465e-a7e0-66f99d70569f")),
						NotBefore:           fakeClock.Now().Add(-time.Hour),
						NotAfter:            fakeClock.Now().Add(time.Hour),
						CreatedAt:           fakeClock.Now(),
					},
					{
						ID:                  uuid.MustParse("b3e8d5fd-5661-416e-aa40-e13eaf7d440a"),
						CommonName:          "test.invalid",
						SubjectAltNames:     []string{},
						CertificatePem:      "-----BEGIN CERTIFICATE-----\ncmFuZG9tIGRhdGEgIzI=\n-----END CERTIFICATE-----",
						ParentCertificateID: ptr(uuid.MustParse("bfc1c6e5-58cd-41bb-9541-d12e9a31af49")),
						PrivateKeyID:        ptr(uuid.MustParse("e03c63a2-2494-42d5-8d57-27a1f8cf0359")),
						NotBefore:           fakeClock.Now(),
						NotAfter:            fakeClock.Now().Add(time.Hour * 2),
						CreatedAt:           fakeClock.Now().Add(time.Hour),
					},
				},
				[]*service.X509PrivateKeyDto{
					{
						ID:            uuid.MustParse("4855bf58-3f3f-407c-8973-740d93868996"),
						PrivateKeyPem: "-----BEGIN PRIVATE KEY-----\ndGVzdCBwcml2YXRlIGtleSAjMQ==\n-----END PRIVATE KEY-----",
						CreatedAt:     fakeClock.Now(),
					},
					{
						ID:            uuid.MustParse("8bfb6b0f-1277-47a2-a9aa-f38912e09ed2"),
						PrivateKeyPem: "-----BEGIN PRIVATE KEY-----\ndGVzdCBwcml2YXRlIGtleSAjMg==\n-----END PRIVATE KEY-----",
						CreatedAt:     fakeClock.Now().Add(-time.Hour),
					},
				},
				nil,
			)

		r := &RestHandlerImpl{
			logger:            logger,
			x509ImportService: svc,
		}

		result, err := r.BulkImportX509V1(ctx, BulkImportX509V1RequestObject{
			Body: &BulkImportX509V1JSONRequestBody{
				Certificates: &[]string{
					"-----BEGIN CERTIFICATE-----\ncmFuZG9tIGRhdGE=\n-----END CERTIFICATE-----",
					"-----BEGIN CERTIFICATE-----\ncmFuZG9tIGRhdGEgIzI=\n-----END CERTIFICATE-----",
				},
				PrivateKeys: &[]string{
					"-----BEGIN PRIVATE KEY-----\ndGVzdCBwcml2YXRlIGtleSAjMQ==\n-----END PRIVATE KEY-----",
					"-----BEGIN PRIVATE KEY-----\ndGVzdCBwcml2YXRlIGtleSAjMg==\n-----END PRIVATE KEY-----",
				},
			},
		})

		if err != nil {
			t.Errorf("BulkImportX509V1() error = %v", err)
			return
		}

		expected := BulkImportX509V1201JSONResponse{
			Certificates: &[]X509Certificate{
				{
					Certificate:         "-----BEGIN CERTIFICATE-----\ncmFuZG9tIGRhdGE=\n-----END CERTIFICATE-----",
					CommonName:          ptr("example.invalid"),
					CreatedAt:           fakeClock.Now(),
					Id:                  uuid.MustParse("536c7378-2563-40ac-a513-b423693cdaae"),
					NotAfter:            fakeClock.Now().Add(time.Hour),
					NotBefore:           fakeClock.Now().Add(-time.Hour),
					ParentCertificateId: ptr(uuid.MustParse("48939f46-4f0a-458c-8bf6-e52136624c91")),
					PrivateKeyId:        ptr(uuid.MustParse("605831e4-eda5-465e-a7e0-66f99d70569f")),
					Sans:                []string{"test.example.invalid"},
				},
				{
					Certificate:         "-----BEGIN CERTIFICATE-----\ncmFuZG9tIGRhdGEgIzI=\n-----END CERTIFICATE-----",
					CommonName:          ptr("test.invalid"),
					CreatedAt:           fakeClock.Now().Add(time.Hour),
					Id:                  uuid.MustParse("b3e8d5fd-5661-416e-aa40-e13eaf7d440a"),
					NotAfter:            fakeClock.Now().Add(time.Hour * 2),
					NotBefore:           fakeClock.Now(),
					ParentCertificateId: ptr(uuid.MustParse("bfc1c6e5-58cd-41bb-9541-d12e9a31af49")),
					PrivateKeyId:        ptr(uuid.MustParse("e03c63a2-2494-42d5-8d57-27a1f8cf0359")),
					Sans:                []string{},
				},
			},
			PrivateKeys: &[]X509PrivateKey{
				{
					Id:  uuid.MustParse("4855bf58-3f3f-407c-8973-740d93868996"),
					Key: "-----BEGIN PRIVATE KEY-----\ndGVzdCBwcml2YXRlIGtleSAjMQ==\n-----END PRIVATE KEY-----",
				},
				{
					Id:  uuid.MustParse("8bfb6b0f-1277-47a2-a9aa-f38912e09ed2"),
					Key: "-----BEGIN PRIVATE KEY-----\ndGVzdCBwcml2YXRlIGtleSAjMg==\n-----END PRIVATE KEY-----",
				},
			},
		}

		if !reflect.DeepEqual(result, expected) {
			t.Errorf("BulkImportX509V1() got = %v, want %v", result, expected)
		}
	})
}

func TestRestHandlerImpl_CreateX509CertificateSubscriptionV1(t *testing.T) {
	type fields struct {
		logger                             *zap.Logger
		x509CertificateSubscriptionService *service.DefaultX509CertificateSubscriptionService
		x509CertificateService             *service.DefaultX509CertificateService
		x509ImportService                  *service.DefaultX509ImportService
	}
	type args struct {
		ctx     context.Context
		request CreateX509CertificateSubscriptionV1RequestObject
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    CreateX509CertificateSubscriptionV1ResponseObject
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RestHandlerImpl{
				logger:                             tt.fields.logger,
				x509CertificateSubscriptionService: tt.fields.x509CertificateSubscriptionService,
				x509CertificateService:             tt.fields.x509CertificateService,
				x509ImportService:                  tt.fields.x509ImportService,
			}
			got, err := r.CreateX509CertificateSubscriptionV1(tt.args.ctx, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateX509CertificateSubscriptionV1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateX509CertificateSubscriptionV1() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRestHandlerImpl_DeleteX509CertificateSubscriptionV1(t *testing.T) {
	type fields struct {
		logger                             *zap.Logger
		x509CertificateSubscriptionService *service.DefaultX509CertificateSubscriptionService
		x509CertificateService             *service.DefaultX509CertificateService
		x509ImportService                  *service.DefaultX509ImportService
	}
	type args struct {
		ctx     context.Context
		request DeleteX509CertificateSubscriptionV1RequestObject
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    DeleteX509CertificateSubscriptionV1ResponseObject
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RestHandlerImpl{
				logger:                             tt.fields.logger,
				x509CertificateSubscriptionService: tt.fields.x509CertificateSubscriptionService,
				x509CertificateService:             tt.fields.x509CertificateService,
				x509ImportService:                  tt.fields.x509ImportService,
			}
			got, err := r.DeleteX509CertificateSubscriptionV1(tt.args.ctx, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteX509CertificateSubscriptionV1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DeleteX509CertificateSubscriptionV1() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRestHandlerImpl_GetX509CertificateUpdatesV1(t *testing.T) {
	type fields struct {
		logger                             *zap.Logger
		x509CertificateSubscriptionService *service.DefaultX509CertificateSubscriptionService
		x509CertificateService             *service.DefaultX509CertificateService
		x509ImportService                  *service.DefaultX509ImportService
	}
	type args struct {
		ctx     context.Context
		request GetX509CertificateUpdatesV1RequestObject
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    GetX509CertificateUpdatesV1ResponseObject
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RestHandlerImpl{
				logger:                             tt.fields.logger,
				x509CertificateSubscriptionService: tt.fields.x509CertificateSubscriptionService,
				x509CertificateService:             tt.fields.x509CertificateService,
				x509ImportService:                  tt.fields.x509ImportService,
			}
			got, err := r.GetX509CertificateUpdatesV1(tt.args.ctx, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetX509CertificateUpdatesV1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetX509CertificateUpdatesV1() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRestHandlerImpl_ImportX509BundleV1(t *testing.T) {
	type fields struct {
		logger                             *zap.Logger
		x509CertificateSubscriptionService *service.DefaultX509CertificateSubscriptionService
		x509CertificateService             *service.DefaultX509CertificateService
		x509ImportService                  *service.DefaultX509ImportService
	}
	type args struct {
		ctx     context.Context
		request ImportX509BundleV1RequestObject
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    ImportX509BundleV1ResponseObject
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RestHandlerImpl{
				logger:                             tt.fields.logger,
				x509CertificateSubscriptionService: tt.fields.x509CertificateSubscriptionService,
				x509CertificateService:             tt.fields.x509CertificateService,
				x509ImportService:                  tt.fields.x509ImportService,
			}
			got, err := r.ImportX509BundleV1(tt.args.ctx, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ImportX509BundleV1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ImportX509BundleV1() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRestHandlerImpl_l(t *testing.T) {
	type fields struct {
		logger                             *zap.Logger
		x509CertificateSubscriptionService *service.DefaultX509CertificateSubscriptionService
		x509CertificateService             *service.DefaultX509CertificateService
		x509ImportService                  *service.DefaultX509ImportService
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *zap.Logger
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RestHandlerImpl{
				logger:                             tt.fields.logger,
				x509CertificateSubscriptionService: tt.fields.x509CertificateSubscriptionService,
				x509CertificateService:             tt.fields.x509CertificateService,
				x509ImportService:                  tt.fields.x509ImportService,
			}
			if got := r.l(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("l() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_dtoToX509Certificate(t *testing.T) {
	type args struct {
		certDto *service.X509CertificateDto
	}
	tests := []struct {
		name string
		args args
		want X509Certificate
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dtoToX509Certificate(tt.args.certDto); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dtoToX509Certificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_dtoToX509CertificateSubscription(t *testing.T) {
	type args struct {
		dto *service.X509CertificateSubscriptionDto
	}
	tests := []struct {
		name string
		args args
		want X509CertificateSubscription
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dtoToX509CertificateSubscription(tt.args.dto); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dtoToX509CertificateSubscription() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_dtoToX509PrivateKey(t *testing.T) {
	type args struct {
		privKeyDto *service.X509PrivateKeyDto
	}
	tests := []struct {
		name string
		args args
		want X509PrivateKey
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dtoToX509PrivateKey(tt.args.privKeyDto); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dtoToX509PrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ptr(t *testing.T) {
	type args[T any] struct {
		input T
	}
	type testCase struct {
		name string
		args args[any]
		want *any
	}
	tests := []testCase{
		{
			name: "int to ptr",
			args: args[any]{
				input: 32,
			},
			want: func() *any {
				i := any(32)
				return &i
			}(),
		},
		{
			name: "string to ptr",
			args: args[any]{
				input: "teststring",
			},
			want: func() *any {
				s := any("teststring")
				return &s
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ptr(tt.args.input); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ptr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_separatePemBlocks(t *testing.T) {
	type args struct {
		pemBlocks []byte
	}
	tests := []struct {
		name       string
		args       args
		wantBlocks []*pem.Block
		wantRest   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBlocks, gotRest := separatePemBlocks(tt.args.pemBlocks)
			if !reflect.DeepEqual(gotBlocks, tt.wantBlocks) {
				t.Errorf("separatePemBlocks() gotBlocks = %v, want %v", gotBlocks, tt.wantBlocks)
			}
			if !reflect.DeepEqual(gotRest, tt.wantRest) {
				t.Errorf("separatePemBlocks() gotRest = %v, want %v", gotRest, tt.wantRest)
			}
		})
	}
}

func Test_separatePemBlocksRecursively(t *testing.T) {
	type args struct {
		pemBlocks      []byte
		foundPemBlocks []*pem.Block
	}
	tests := []struct {
		name       string
		args       args
		wantBlocks []*pem.Block
		wantRest   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBlocks, gotRest := separatePemBlocksRecursively(tt.args.pemBlocks, tt.args.foundPemBlocks)
			if !reflect.DeepEqual(gotBlocks, tt.wantBlocks) {
				t.Errorf("separatePemBlocksRecursively() gotBlocks = %v, want %v", gotBlocks, tt.wantBlocks)
			}
			if !reflect.DeepEqual(gotRest, tt.wantRest) {
				t.Errorf("separatePemBlocksRecursively() gotRest = %v, want %v", gotRest, tt.wantRest)
			}
		})
	}
}
