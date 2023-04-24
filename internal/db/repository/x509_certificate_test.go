package repository

import (
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/testutil"
	"reflect"
	"testing"
	"time"
)

func TestNewX509CertificateDao(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()

	type args struct {
		ID              uuid.UUID
		commonName      string
		subjectAltNames []string
		issuerHash      []byte
		subjectHash     []byte
		bytesHash       []byte
		bytes           []byte
		pubKeyHash      []byte
		parentCertID    *uuid.UUID
		privKeyID       *uuid.UUID
		notBefore       time.Time
		notAfter        time.Time
		createdAt       time.Time
	}
	tests := []struct {
		name string
		args args
		want *X509CertificateDao
	}{
		{
			name: "ensure all fields are set",
			args: args{
				ID:              uuid.MustParse("996bdde6-6f96-4006-8a73-e8d66e0d5630"),
				commonName:      "example.invalid",
				subjectAltNames: []string{"example.invalid", "test.example.invalid"},
				issuerHash:      []byte{0x5B, 0xE4, 0x1D, 0x66},
				subjectHash:     []byte{0x3A, 0xC2, 0x6E, 0x7B},
				bytesHash:       []byte{0xF8, 0x51, 0x20, 0x9A},
				bytes:           []byte{0x98, 0x6B, 0x3D, 0x24},
				pubKeyHash:      []byte{0x4A, 0xFD, 0x7E, 0x51},
				parentCertID:    testutil.Ptr(uuid.MustParse("99891708-bd95-4efa-b353-2fd091cf24e4")),
				privKeyID:       testutil.Ptr(uuid.MustParse("f526fe2f-352d-403e-b5e2-1f59c6e15780")),
				notBefore:       fakeClock.Now(),
				notAfter:        fakeClock.Now().Add(1 * time.Hour),
				createdAt:       fakeClock.Now().Add(2 * time.Hour),
			},
			want: &X509CertificateDao{
				ID:                  uuid.MustParse("996bdde6-6f96-4006-8a73-e8d66e0d5630"),
				CommonName:          "example.invalid",
				SubjectAltNames:     []string{"example.invalid", "test.example.invalid"},
				IssuerHash:          []byte{0x5B, 0xE4, 0x1D, 0x66},
				SubjectHash:         []byte{0x3A, 0xC2, 0x6E, 0x7B},
				BytesHash:           []byte{0xF8, 0x51, 0x20, 0x9A},
				Bytes:               []byte{0x98, 0x6B, 0x3D, 0x24},
				PublicKeyHash:       []byte{0x4A, 0xFD, 0x7E, 0x51},
				ParentCertificateID: testutil.Ptr(uuid.MustParse("99891708-bd95-4efa-b353-2fd091cf24e4")),
				PrivateKeyID:        testutil.Ptr(uuid.MustParse("f526fe2f-352d-403e-b5e2-1f59c6e15780")),
				NotBefore:           fakeClock.Now(),
				NotAfter:            fakeClock.Now().Add(1 * time.Hour),
				CreatedAt:           fakeClock.Now().Add(2 * time.Hour),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewX509CertificateDao(tt.args.ID, tt.args.commonName, tt.args.subjectAltNames, tt.args.issuerHash, tt.args.subjectHash, tt.args.bytesHash, tt.args.bytes, tt.args.pubKeyHash, tt.args.parentCertID, tt.args.privKeyID, tt.args.notBefore, tt.args.notAfter, tt.args.createdAt)
			if !testutil.AllFieldsNotNilOrEmptyStruct(got) {
				t.Errorf("NewX509CertificateDao() not all fields are set")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewX509CertificateDao() = %v, want %v", got, tt.want)
			}
		})
	}
}
