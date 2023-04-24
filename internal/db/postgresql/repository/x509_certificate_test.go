package repository

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/db/postgresql/models"
	"github.com/pki-vault/server/internal/db/repository"
	"github.com/pki-vault/server/internal/services"
	"github.com/pki-vault/server/internal/testutil"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	caBasePath       = "./../../../../testdata/certificates"
	exampleBasePath  = "./../../../../testdata/certificates/example.invalid"
	wildcardBasePath = "./../../../../testdata/certificates/wildcard.invalid"
)

func TestNewX509CertificateRepository(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	db := postgresqlTestBackend.Db()

	type args struct {
		db                *sql.DB
		privKeyRepository *X509PrivateKeyRepository
		clock             clockwork.Clock
	}
	tests := []struct {
		name string
		args args
		want *X509CertificateRepository
	}{
		{
			name: "ensure all fields are set",
			args: args{
				db:                db,
				privKeyRepository: &X509PrivateKeyRepository{},
				clock:             fakeClock,
			},
			want: &X509CertificateRepository{
				db:                   db,
				privateKeyRepository: &X509PrivateKeyRepository{},
				clock:                fakeClock,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewX509CertificateRepository(tt.args.db, tt.args.privKeyRepository, tt.args.clock)
			if !testutil.AllFieldsNotNilOrEmptyStruct(got) {
				t.Errorf("NewX509CertificateRepository() not all fields are set")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewX509CertificateRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestX509CertificateRepository_FindByIssuerHashAndNoParentSet(t *testing.T) {
	ctx := context.Background()
	fakeClock := clockwork.NewFakeClock()
	db := postgresqlTestBackend.Db()

	if err := seedX509CertificateTestData(t, ctx, fakeClock); err != nil {
		t.Fatal(err)
	}

	fetchedCert, err := models.X509Certificates(
		models.X509CertificateWhere.CommonName.EQ("Test Root CA Alpha"),
		models.X509CertificateWhere.NotBefore.LTE(time.Now()),
		models.X509CertificateWhere.NotAfter.GTE(time.Now()),
		qm.OrderBy(models.X509CertificateColumns.NotAfter+" desc"),
		qm.Limit(1),
	).One(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	expectedCert := postgresqlCertificateToDao(fetchedCert)

	type fields struct {
		db    *sql.DB
		clock clockwork.Clock
	}
	type args struct {
		ctx        context.Context
		issuerHash []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*repository.X509CertificateDao
		wantErr bool
	}{
		{
			name: "find existing",
			fields: fields{
				db:    db,
				clock: clockwork.NewFakeClock(),
			},
			args: args{
				ctx: ctx,
				issuerHash: services.ComputeSubjectOrIssuerHash(pkix.Name{
					CommonName: "Test Root CA Alpha",
				}),
			},
			want:    []*repository.X509CertificateDao{expectedCert},
			wantErr: false,
		},
		{
			name: "dont find non existing",
			fields: fields{
				db:    db,
				clock: clockwork.NewFakeClock(),
			},
			args: args{
				ctx: ctx,
				issuerHash: services.ComputeSubjectOrIssuerHash(pkix.Name{
					CommonName: "does-not-exist.invalid",
				}),
			},
			want:    nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &X509CertificateRepository{
				db:    tt.fields.db,
				clock: tt.fields.clock,
			}
			got, err := r.FindByIssuerHashAndNoParentSet(tt.args.ctx, tt.args.issuerHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindByIssuerHashAndNoParentSet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for wantIndex := range tt.want {
				if !reflect.DeepEqual(tt.want[wantIndex], got[wantIndex]) {
					t.Errorf("FindByIssuerHashAndNoParentSet() got = %+v, want %+v", *got[wantIndex], *tt.want[wantIndex])
				}
			}
		})
	}
}

func TestCertificateRepository_FindBySubjectHash(t *testing.T) {
	ctx := context.Background()
	fakeClock := clockwork.NewFakeClock()
	db := postgresqlTestBackend.Db()

	if err := seedX509CertificateTestData(t, ctx, fakeClock); err != nil {
		t.Fatal(err)
	}

	fetchedCert, err := models.X509Certificates(
		models.X509CertificateWhere.CommonName.EQ("example.invalid"),
		models.X509CertificateWhere.NotBefore.LTE(time.Now()),
		models.X509CertificateWhere.NotAfter.GTE(time.Now()),
		qm.OrderBy(models.X509CertificateColumns.NotAfter+" desc"),
		qm.Limit(1),
	).One(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	expectedCert := postgresqlCertificateToDao(fetchedCert)

	type fields struct {
		db    *sql.DB
		clock clockwork.Clock
	}
	type args struct {
		ctx         context.Context
		subjectHash []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*repository.X509CertificateDao
		wantErr bool
	}{
		{
			name: "find existing",
			fields: fields{
				db:    db,
				clock: clockwork.NewFakeClock(),
			},
			args: args{
				ctx: ctx,
				subjectHash: services.ComputeSubjectOrIssuerHash(pkix.Name{
					CommonName: "example.invalid",
				}),
			},
			want:    []*repository.X509CertificateDao{expectedCert},
			wantErr: false,
		},
		{
			name: "dont find non existing",
			fields: fields{
				db:    db,
				clock: clockwork.NewFakeClock(),
			},
			args: args{
				ctx: ctx,
				subjectHash: services.ComputeSubjectOrIssuerHash(pkix.Name{
					CommonName: "does-not-exist.invalid",
				}),
			},
			want:    nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &X509CertificateRepository{
				db:    tt.fields.db,
				clock: tt.fields.clock,
			}
			got, err := r.FindBySubjectHash(tt.args.ctx, tt.args.subjectHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindBySubjectHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for wantIndex := range tt.want {
				if !reflect.DeepEqual(tt.want[wantIndex], got[wantIndex]) {
					t.Errorf("FindBySubjectHash() got = %+v, want %+v", *got[wantIndex], *tt.want[wantIndex])
				}
			}
		})
	}
}

func TestCertificateRepository_FindCertificateChain(t *testing.T) {
	ctx := context.Background()
	fakeClock := clockwork.NewFakeClock()
	db := postgresqlTestBackend.Db()

	if err := seedX509CertificateTestData(t, ctx, fakeClock); err != nil {
		t.Fatal(err)
	}

	fetchedCert, err := models.X509Certificates(
		models.X509CertificateWhere.CommonName.EQ("example.invalid"),
		models.X509CertificateWhere.NotBefore.LTE(time.Now()),
		models.X509CertificateWhere.NotAfter.GTE(time.Now()),
		qm.OrderBy(models.X509CertificateColumns.NotAfter+" desc"),
		qm.Limit(1),
	).One(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	checkTimeValidity(fetchedCert)
	fetchedIntermediateCert, err := models.X509Certificates(
		models.X509CertificateWhere.ID.EQ(fetchedCert.ParentCertificateID.String),
		models.X509CertificateWhere.NotBefore.LTE(time.Now()),
		models.X509CertificateWhere.NotAfter.GTE(time.Now()),
		qm.OrderBy(models.X509CertificateColumns.NotAfter+" desc"),
		qm.Limit(1),
	).One(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	checkTimeValidity(fetchedIntermediateCert)
	fetchedCaCert, err := models.X509Certificates(
		models.X509CertificateWhere.ID.EQ(fetchedIntermediateCert.ParentCertificateID.String),
		models.X509CertificateWhere.NotBefore.LTE(time.Now()),
		models.X509CertificateWhere.NotAfter.GTE(time.Now()),
		qm.OrderBy(models.X509CertificateColumns.NotAfter+" desc"),
		qm.Limit(1),
	).One(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	checkTimeValidity(fetchedCaCert)

	type fields struct {
		db    *sql.DB
		clock clockwork.Clock
	}
	type args struct {
		ctx                context.Context
		startCertificateId uuid.UUID
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*repository.X509CertificateDao
		wantErr bool
	}{
		{
			name: "find correct chain with active certificates",
			fields: fields{
				db:    db,
				clock: clockwork.NewFakeClock(),
			},
			args: args{
				ctx:                ctx,
				startCertificateId: uuid.MustParse(fetchedCert.ID),
			},
			want: []*repository.X509CertificateDao{
				postgresqlCertificateToDao(fetchedCert),
				postgresqlCertificateToDao(fetchedIntermediateCert),
				postgresqlCertificateToDao(fetchedCaCert),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &X509CertificateRepository{
				db:    tt.fields.db,
				clock: tt.fields.clock,
			}
			got, err := r.FindCertificateChain(tt.args.ctx, tt.args.startCertificateId)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindCertificateChain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for wantIndex := range tt.want {
				if !reflect.DeepEqual(tt.want[wantIndex], got[wantIndex]) {
					t.Errorf("FindCertificateChain() got = %+v, want %+v", *got[wantIndex], *tt.want[wantIndex])
				}
			}
		})
	}
}

func TestCertificateRepository_FindLatestActiveBySANsAndCreatedAtAfter(t *testing.T) {
	ctx := context.Background()
	fakeClock := clockwork.NewFakeClock()
	db := postgresqlTestBackend.Db()

	if err := seedX509CertificateTestData(t, ctx, fakeClock); err != nil {
		t.Fatal(err)
	}

	exampleCert, err := models.X509Certificates(
		models.X509CertificateWhere.CommonName.EQ("example.invalid"),
		models.X509CertificateWhere.NotBefore.LTE(time.Now()),
		models.X509CertificateWhere.NotAfter.GTE(time.Now()),
		qm.OrderBy(models.X509CertificateColumns.NotAfter+" desc"),
		qm.Limit(1),
	).One(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	wildcardCert, err := models.X509Certificates(
		models.X509CertificateWhere.CommonName.EQ("*.wildcard.invalid"),
		models.X509CertificateWhere.NotBefore.LTE(time.Now()),
		models.X509CertificateWhere.NotAfter.GTE(time.Now()),
		qm.OrderBy(models.X509CertificateColumns.NotAfter+" desc"),
		qm.Limit(1),
	).One(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		db    *sql.DB
		clock clockwork.Clock
	}
	type args struct {
		ctx                       context.Context
		subjectIdentifiers        []string
		sinceAfter                time.Time
		includePrivateKeyIfExists bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*repository.X509CertificateDao
		wantErr bool
	}{
		{
			name: "find latest created since sinceAfter",
			fields: fields{
				db:    db,
				clock: clockwork.NewFakeClock(),
			},
			args: args{
				ctx:                ctx,
				subjectIdentifiers: []string{"example.invalid"},
				// Include everything in first filter by createdAt
				sinceAfter:                time.UnixMilli(0),
				includePrivateKeyIfExists: true,
			},
			want: []*repository.X509CertificateDao{
				postgresqlCertificateToDao(exampleCert),
			},
			wantErr: false,
		},
		{
			name: "find none when none relevant were created after sinceAfter",
			fields: fields{
				db:    db,
				clock: clockwork.NewFakeClock(),
			},
			args: args{
				ctx:                ctx,
				subjectIdentifiers: []string{"example.invalid"},
				// ensure there is really no possibility we find something
				sinceAfter:                time.Now().Add(24 * time.Hour),
				includePrivateKeyIfExists: true,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "find wildcard certificate matching subject identifiers",
			fields: fields{
				db:    db,
				clock: clockwork.NewFakeClock(),
			},
			args: args{
				ctx: ctx,
				// *.wildcard.invalid exists
				subjectIdentifiers: []string{"subdomain.wildcard.invalid"},
				// Include everything in first filter by createdAt
				sinceAfter:                time.UnixMilli(0),
				includePrivateKeyIfExists: true,
			},
			want: []*repository.X509CertificateDao{
				postgresqlCertificateToDao(wildcardCert),
			},
			wantErr: false,
		},
		{
			name: "find wildcard certificate matching subject identifiers with third level domain",
			fields: fields{
				db:    db,
				clock: clockwork.NewFakeClock(),
			},
			args: args{
				ctx: ctx,
				// *.wildcard.invalid exists
				subjectIdentifiers: []string{"subsubdomain.subdomain.wildcard.invalid"},
				// Include everything in first filter by createdAt
				sinceAfter:                time.UnixMilli(0),
				includePrivateKeyIfExists: true,
			},
			want: []*repository.X509CertificateDao{
				postgresqlCertificateToDao(wildcardCert),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &X509CertificateRepository{
				db:    tt.fields.db,
				clock: tt.fields.clock,
			}
			got, err := r.FindLatestActiveBySANsAndCreatedAtAfter(tt.args.ctx, tt.args.subjectIdentifiers, tt.args.sinceAfter)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindLatestActiveBySANsAndCreatedAtAfter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for wantIndex := range tt.want {
				if !reflect.DeepEqual(tt.want[wantIndex], got[wantIndex]) {
					t.Errorf("FindLatestActiveBySANsAndCreatedAtAfter() got = %+v, want %+v", *got[wantIndex], *tt.want[wantIndex])
				}
			}
		})
	}
}

func TestCertificateRepository_GetOrCreate(t *testing.T) {
	ctx := context.Background()
	fakeClock := clockwork.NewFakeClock()
	db := postgresqlTestBackend.Db()
	repo := &X509CertificateRepository{
		db:                   db,
		privateKeyRepository: NewX509PrivateKeyRepository(db, fakeClock),
		clock:                fakeClock,
	}

	if err := seedX509CertificateTestData(t, ctx, fakeClock); err != nil {
		t.Fatal(err)
	}

	anyPrivKey, err := models.X509PrivateKeys(qm.Limit(1)).One(ctx, db)

	fetchedRootCert, err := models.X509Certificates(
		models.X509CertificateWhere.ParentCertificateID.IsNull(),
		qm.Limit(1),
	).One(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("create certificate (parent and private key)", func(t *testing.T) {
		id := uuid.MustParse("91fe0afa-91c3-443b-bea6-6cb69d2eb7b6")
		toBeCreatedCert := &repository.X509CertificateDao{
			ID:                  id,
			CommonName:          "x509-certificate-get-or-create-unit-test.invalid",
			SubjectAltNames:     []string{"subdomain.x509-certificate-unit-test.invalid"},
			IssuerHash:          []byte{0x3D, 0x90, 0x2F, 0x7E},
			SubjectHash:         []byte{0x3F, 0x6A, 0x1C, 0x9D},
			BytesHash:           []byte{0x9E, 0x10, 0x4A, 0x8B},
			Bytes:               []byte{0x71, 0xC9, 0x5A, 0xE0},
			PublicKeyHash:       []byte{0x52, 0xC3, 0x7F, 0xA1},
			ParentCertificateID: testutil.Ptr(uuid.MustParse(fetchedRootCert.ID)),
			PrivateKeyID:        testutil.Ptr(uuid.MustParse(anyPrivKey.ID)),
			NotBefore:           testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.0000Z"),
			NotAfter:            testutil.TimeMustParse(time.RFC3339, "2024-04-15T14:30:00.0000Z"),
			CreatedAt:           time.Time{},
		}

		got, err := repo.GetOrCreate(ctx, toBeCreatedCert)
		if err != nil {
			t.Fatal(err)
		}
		expectedCert := &repository.X509CertificateDao{
			ID:                  id,
			CommonName:          "x509-certificate-get-or-create-unit-test.invalid",
			SubjectAltNames:     []string{"subdomain.x509-certificate-unit-test.invalid"},
			IssuerHash:          []byte{0x3D, 0x90, 0x2F, 0x7E},
			SubjectHash:         []byte{0x3F, 0x6A, 0x1C, 0x9D},
			BytesHash:           []byte{0x9E, 0x10, 0x4A, 0x8B},
			Bytes:               []byte{0x71, 0xC9, 0x5A, 0xE0},
			PublicKeyHash:       []byte{0x52, 0xC3, 0x7F, 0xA1},
			ParentCertificateID: testutil.Ptr(uuid.MustParse(fetchedRootCert.ID)),
			PrivateKeyID:        testutil.Ptr(uuid.MustParse(anyPrivKey.ID)),
			NotBefore:           testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.0000Z"),
			NotAfter:            testutil.TimeMustParse(time.RFC3339, "2024-04-15T14:30:00.0000Z"),
			CreatedAt:           normalizeTime(fakeClock.Now()),
		}
		if !testutil.AllFieldsNotNilOrEmptyStruct(expectedCert) {
			t.Errorf("GetOrCreate() not all fields are set")
		}
		if !reflect.DeepEqual(got, expectedCert) {
			t.Errorf("GetOrCreate() got = %v, want %v", got, expectedCert)
		}

		// Ensure inserted record in the database is correct
		var fetchedCreatedCert *repository.X509CertificateDao
		{
			fetchedCreatedCertModel, err := models.
				X509Certificates(models.X509CertificateWhere.ID.EQ(id.String())).
				One(ctx, db)
			if err != nil {
				return
			}

			fetchedCreatedCert = postgresqlCertificateToDao(fetchedCreatedCertModel)
		}

		if !reflect.DeepEqual(fetchedCreatedCert, expectedCert) {
			t.Errorf("GetOrCreate() = %v, want %v", fetchedCreatedCert, expectedCert)
		}
	})

	t.Run("create intermediate ca certificate (parent and no private key)", func(t *testing.T) {
		id := uuid.MustParse("10a15adf-449a-45e1-a775-d08803a51d0f")
		toBeCreatedCert := &repository.X509CertificateDao{
			ID:                  id,
			CommonName:          "x509-certificate-get-or-create-unit-test intermediate ca",
			SubjectAltNames:     []string{},
			IssuerHash:          []byte{0xA3, 0x17, 0x88, 0xE2},
			SubjectHash:         []byte{0x46, 0xA8, 0x91, 0x5F},
			BytesHash:           []byte{0x2A, 0xF1, 0x81, 0x69},
			Bytes:               []byte{0x1D, 0x6A, 0x35, 0xC0},
			PublicKeyHash:       []byte{0x7C, 0x6D, 0xE9, 0x56},
			ParentCertificateID: testutil.Ptr(uuid.MustParse(fetchedRootCert.ID)),
			PrivateKeyID:        nil,
			NotBefore:           testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.0000Z"),
			NotAfter:            testutil.TimeMustParse(time.RFC3339, "2024-04-15T14:30:00.0000Z"),
			CreatedAt:           time.Time{},
		}

		got, err := repo.GetOrCreate(ctx, toBeCreatedCert)
		if err != nil {
			t.Fatal(err)
		}
		expectedCert := &repository.X509CertificateDao{
			ID:                  id,
			CommonName:          "x509-certificate-get-or-create-unit-test intermediate ca",
			SubjectAltNames:     []string{},
			IssuerHash:          []byte{0xA3, 0x17, 0x88, 0xE2},
			SubjectHash:         []byte{0x46, 0xA8, 0x91, 0x5F},
			BytesHash:           []byte{0x2A, 0xF1, 0x81, 0x69},
			Bytes:               []byte{0x1D, 0x6A, 0x35, 0xC0},
			PublicKeyHash:       []byte{0x7C, 0x6D, 0xE9, 0x56},
			ParentCertificateID: testutil.Ptr(uuid.MustParse(fetchedRootCert.ID)),
			PrivateKeyID:        nil,
			NotBefore:           testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.0000Z"),
			NotAfter:            testutil.TimeMustParse(time.RFC3339, "2024-04-15T14:30:00.0000Z"),
			CreatedAt:           normalizeTime(fakeClock.Now()),
		}
		if !reflect.DeepEqual(got, expectedCert) {
			t.Errorf("GetOrCreate() got = %v, want %v", got, expectedCert)
		}

		// Ensure inserted record in the database is correct
		var fetchedCreatedCert *repository.X509CertificateDao
		{
			fetchedCreatedCertModel, err := models.
				X509Certificates(models.X509CertificateWhere.ID.EQ(id.String())).
				One(ctx, db)
			if err != nil {
				return
			}

			fetchedCreatedCert = postgresqlCertificateToDao(fetchedCreatedCertModel)
		}

		if !reflect.DeepEqual(fetchedCreatedCert, expectedCert) {
			t.Errorf("GetOrCreate() = %v, want %v", fetchedCreatedCert, expectedCert)
		}
	})

	t.Run("create root certificate (no parent or private key)", func(t *testing.T) {
		id := uuid.MustParse("1d2b3dfd-c2fd-407c-abee-5e24a79f708f")
		toBeCreatedCert := &repository.X509CertificateDao{
			ID:                  id,
			CommonName:          "x509-certificate-get-or-create-unit-test root ca",
			SubjectAltNames:     []string{},
			IssuerHash:          []byte{0xF9, 0x06, 0xB4, 0x50},
			SubjectHash:         []byte{0x7A, 0x53, 0xE6, 0x98},
			BytesHash:           []byte{0x5F, 0xC7, 0x23, 0x89},
			Bytes:               []byte{0x3E, 0xC7, 0x29, 0x85},
			PublicKeyHash:       []byte{0x12, 0xB8, 0x5C, 0xD6},
			ParentCertificateID: nil,
			PrivateKeyID:        nil,
			NotBefore:           testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.0000Z"),
			NotAfter:            testutil.TimeMustParse(time.RFC3339, "2024-04-15T14:30:00.0000Z"),
			CreatedAt:           time.Time{},
		}

		got, err := repo.GetOrCreate(ctx, toBeCreatedCert)
		if err != nil {
			t.Fatal(err)
		}
		expectedCert := &repository.X509CertificateDao{
			ID:                  id,
			CommonName:          "x509-certificate-get-or-create-unit-test root ca",
			SubjectAltNames:     []string{},
			IssuerHash:          []byte{0xF9, 0x06, 0xB4, 0x50},
			SubjectHash:         []byte{0x7A, 0x53, 0xE6, 0x98},
			BytesHash:           []byte{0x5F, 0xC7, 0x23, 0x89},
			Bytes:               []byte{0x3E, 0xC7, 0x29, 0x85},
			PublicKeyHash:       []byte{0x12, 0xB8, 0x5C, 0xD6},
			ParentCertificateID: nil,
			PrivateKeyID:        nil,
			NotBefore:           testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.0000Z"),
			NotAfter:            testutil.TimeMustParse(time.RFC3339, "2024-04-15T14:30:00.0000Z"),
			CreatedAt:           normalizeTime(fakeClock.Now()),
		}
		if !reflect.DeepEqual(got, expectedCert) {
			t.Errorf("GetOrCreate() got = %v, want %v", got, expectedCert)
		}

		// Ensure inserted record in the database is correct
		var fetchedCreatedCert *repository.X509CertificateDao
		{
			fetchedCreatedCertModel, err := models.
				X509Certificates(models.X509CertificateWhere.ID.EQ(id.String())).
				One(ctx, db)
			if err != nil {
				return
			}

			fetchedCreatedCert = postgresqlCertificateToDao(fetchedCreatedCertModel)
		}

		if !reflect.DeepEqual(fetchedCreatedCert, expectedCert) {
			t.Errorf("GetOrCreate() = %v, want %v", fetchedCreatedCert, expectedCert)
		}
	})
}

func Test_postgresqlCertificateToDto(t *testing.T) {
	type args struct {
		certificate *models.X509Certificate
	}
	tests := []struct {
		name string
		args args
		want *repository.X509CertificateDao
	}{
		{
			name: "ensure correct transform",
			args: args{
				certificate: &models.X509Certificate{
					ID:              "5871d359-ca00-4718-bbee-aaa2cab2e4df",
					CommonName:      "test.invalid",
					SubjectAltNames: []string{"sub.test.invalid", "sub2.test.invalid"},
					// Random data
					IssuerHash:  []byte{0x71, 0x8E, 0xC5, 0x2A},
					SubjectHash: []byte{0xAB, 0x2F, 0x8C, 0x41},
					BytesHash:   []byte{0x30, 0xEB, 0x59, 0xA7},
					// Random data
					Bytes:               []byte{0xAB, 0x2F, 0x8C, 0xE9},
					PublicKeyHash:       []byte{0x7B, 0x22, 0xFE, 0x84},
					ParentCertificateID: null.StringFrom("1a5a4a95-bcd8-43b8-9f7b-5d91305db69b"),
					PrivateKeyID:        null.StringFrom("8e8594fa-0d39-4bd9-8743-997333be5a65"),
					NotBefore:           testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.0000Z"),
					NotAfter:            testutil.TimeMustParse(time.RFC3339, "2024-04-15T14:30:00.0000Z"),
					CreatedAt:           testutil.TimeMustParse(time.RFC3339, "2023-04-15T14:30:00.0000Z"),
				},
			},
			want: &repository.X509CertificateDao{
				ID:                  uuid.MustParse("5871d359-ca00-4718-bbee-aaa2cab2e4df"),
				CommonName:          "test.invalid",
				SubjectAltNames:     []string{"sub.test.invalid", "sub2.test.invalid"},
				IssuerHash:          []byte{0x71, 0x8E, 0xC5, 0x2A},
				SubjectHash:         []byte{0xAB, 0x2F, 0x8C, 0x41},
				BytesHash:           []byte{0x30, 0xEB, 0x59, 0xA7},
				Bytes:               []byte{0xAB, 0x2F, 0x8C, 0xE9},
				PublicKeyHash:       []byte{0x7B, 0x22, 0xFE, 0x84},
				ParentCertificateID: testutil.Ptr(uuid.MustParse("1a5a4a95-bcd8-43b8-9f7b-5d91305db69b")),
				PrivateKeyID:        testutil.Ptr(uuid.MustParse("8e8594fa-0d39-4bd9-8743-997333be5a65")),
				NotBefore:           testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.000Z"),
				NotAfter:            testutil.TimeMustParse(time.RFC3339, "2024-04-15T14:30:00.000Z"),
				CreatedAt:           testutil.TimeMustParse(time.RFC3339, "2023-04-15T14:30:00.000Z"),
			},
		},
		{
			name: "ensure correct time normalization",
			args: args{
				certificate: &models.X509Certificate{
					ID:              "5871d359-ca00-4718-bbee-aaa2cab2e4df",
					CommonName:      "test.invalid",
					SubjectAltNames: []string{"sub.test.invalid", "sub2.test.invalid"},
					// Random data
					IssuerHash:  []byte{0x4E, 0x23, 0x9B, 0xD7},
					SubjectHash: []byte{0xAB, 0x2F, 0x8C, 0x41},
					BytesHash:   []byte{0x2C, 0xF5, 0x98, 0x64},
					// Random data
					Bytes:               []byte{0xAB, 0x2F, 0x8C, 0xE9},
					PublicKeyHash:       []byte{0x9E, 0x10, 0x4A, 0x8B},
					ParentCertificateID: null.StringFrom("1a5a4a95-bcd8-43b8-9f7b-5d91305db69b"),
					PrivateKeyID:        null.StringFrom("8e8594fa-0d39-4bd9-8743-997333be5a65"),
					NotBefore:           testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.0016Z"),
					NotAfter:            testutil.TimeMustParse(time.RFC3339, "2024-04-15T14:30:00.0016Z"),
					CreatedAt:           testutil.TimeMustParse(time.RFC3339, "2023-04-15T14:30:00.0016Z"),
				},
			},
			want: &repository.X509CertificateDao{
				ID:                  uuid.MustParse("5871d359-ca00-4718-bbee-aaa2cab2e4df"),
				CommonName:          "test.invalid",
				SubjectAltNames:     []string{"sub.test.invalid", "sub2.test.invalid"},
				IssuerHash:          []byte{0x4E, 0x23, 0x9B, 0xD7},
				SubjectHash:         []byte{0xAB, 0x2F, 0x8C, 0x41},
				BytesHash:           []byte{0x2C, 0xF5, 0x98, 0x64},
				Bytes:               []byte{0xAB, 0x2F, 0x8C, 0xE9},
				PublicKeyHash:       []byte{0x9E, 0x10, 0x4A, 0x8B},
				ParentCertificateID: testutil.Ptr(uuid.MustParse("1a5a4a95-bcd8-43b8-9f7b-5d91305db69b")),
				PrivateKeyID:        testutil.Ptr(uuid.MustParse("8e8594fa-0d39-4bd9-8743-997333be5a65")),
				NotBefore:           testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.002Z"),
				NotAfter:            testutil.TimeMustParse(time.RFC3339, "2024-04-15T14:30:00.002Z"),
				CreatedAt:           testutil.TimeMustParse(time.RFC3339, "2023-04-15T14:30:00.002Z"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !testutil.AllFieldsNotNilOrEmptyStruct(tt.want) {
				t.Errorf("postgresqlCertificateToDao() not all fields are set")
			}
			if got := postgresqlCertificateToDao(tt.args.certificate); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("postgresqlCertificateToDao() = %v, want %v", got, tt.want)
			}
		})
	}
}

func seedX509CertificateTestData(t *testing.T, ctx context.Context, clock clockwork.Clock) error {
	db := postgresqlTestBackend.Db()
	t.Cleanup(cleanX509CertificateTestTables)

	pkr := NewX509PrivateKeyRepository(db, clock)
	xcr := NewX509CertificateRepository(db, pkr, clock)

	// active certificates
	_, caDao, _, err := createCertificateWithOptionalKey(ctx, clock, pkr, xcr, caBasePath, "alpha_ca.pem", "alpha_ca-key.pem", false, nil)
	if err != nil {
		return err
	}
	_, exampleIntermediateCaDao, _, err := createCertificateWithOptionalKey(ctx, clock, pkr, xcr, exampleBasePath, "ca.pem", "ca-key.pem", true, &caDao.ID)
	_, _, _, err = createCertificateWithOptionalKey(ctx, clock, pkr, xcr, exampleBasePath, "server.pem", "server-key.pem", true, &exampleIntermediateCaDao.ID)
	if err != nil {
		return err
	}
	_, wildcardIntermediateCaDao, _, err := createCertificateWithOptionalKey(ctx, clock, pkr, xcr, wildcardBasePath, "ca.pem", "ca-key.pem", true, &caDao.ID)
	if err != nil {
		return err
	}
	_, _, _, err = createCertificateWithOptionalKey(ctx, clock, pkr, xcr, wildcardBasePath, "server.pem", "server-key.pem", true, &wildcardIntermediateCaDao.ID)
	if err != nil {
		return err
	}

	// expired certificates
	_, exampleExpiredIntermediateCaDao, _, err := createCertificateWithOptionalKey(ctx, clock, pkr, xcr, exampleBasePath, "expired_ca.pem", "ca-key.pem", true, &caDao.ID)
	if err != nil {
		return err
	}
	_, _, _, err = createCertificateWithOptionalKey(ctx, clock, pkr, xcr, exampleBasePath, "expired_server.pem", "server-key.pem", true, &exampleExpiredIntermediateCaDao.ID)
	if err != nil {
		return err
	}
	return nil
}

func createCertificateWithOptionalKey(ctx context.Context, clock clockwork.Clock,
	privateKeyRepository *X509PrivateKeyRepository,
	certificateRepository *X509CertificateRepository,
	basePath string, certFile string, keyFile string, includePrivKey bool, parentCertID *uuid.UUID,
) (*x509.Certificate, *repository.X509CertificateDao, *repository.X509PrivateKeyDao, error) {
	var err error
	var createdPrivateKey *repository.X509PrivateKeyDao
	var privKeyID *uuid.UUID
	var pubKeyHash []byte

	cert, _, privKeyPemBlock := readCertificateWithOptionalKey(basePath, certFile, keyFile, includePrivKey)

	if includePrivKey {
		privKey, privKeyType, err := services.ParsePrivateKey(privKeyPemBlock.Bytes)
		if err != nil {
			panic(err)
		}
		pubKeyHash, err = services.ComputePublicKeyTypeSpecificHashFromPrivateKey(privKey)
		if err != nil {
			panic(err)
		}

		//createdPrivateKey, err = privKeyRepository.GetOrCreate(ctx, nil, &repository.CreatePrivateKeyRequest{
		//	Type:         repository.PrivateKeyTypeRSA, // FIXME test more types
		//	Bytes:        privKeyPemBlock.Bytes,
		//	PemBlockType: null.StringFrom(privKeyPemBlock.Type),
		//})
		// TODO refactor to not use repository methods
		createdPrivateKey, err = privateKeyRepository.GetOrCreate(ctx, repository.NewX509PrivateKeyDao(
			uuid.New(),
			repository.PrivateKeyType(privKeyType),
			privKeyPemBlock.Type,
			services.ComputeBytesHash(privKeyPemBlock.Bytes),
			privKeyPemBlock.Bytes,
			pubKeyHash,
			clock.Now(), // FIXME?
		))
		if err != nil {
			return nil, nil, nil, err
		}
		privKeyID = &createdPrivateKey.ID
	}
	createdCert, err := certificateRepository.GetOrCreate(
		ctx,
		repository.NewX509CertificateDao(
			uuid.New(),
			cert.Subject.CommonName,
			cert.DNSNames,
			services.ComputeSubjectOrIssuerHash(cert.Issuer),
			services.ComputeSubjectOrIssuerHash(cert.Subject),
			services.ComputeBytesHash(cert.Raw),
			cert.Raw,
			pubKeyHash, // FIXME wrong
			parentCertID,
			privKeyID,
			cert.NotBefore,
			cert.NotAfter,
			clock.Now(),
		),
	)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, createdCert, createdPrivateKey, nil
}

func readCertificateWithOptionalKey(
	basePath string, certFile string, keyFile string, includePrivKey bool,
) (cert *x509.Certificate, certPemBlock *pem.Block, privKeyPemBlock *pem.Block) {
	if includePrivKey {
		privKeyPemBlock = readPemFile(fmt.Sprintf("%s/%s", strings.TrimSuffix(basePath, "/"), keyFile))
	}
	cert, certPemBlock = readCertificate(fmt.Sprintf("%s/%s", strings.TrimSuffix(basePath, "/"), certFile))

	return cert, certPemBlock, privKeyPemBlock
}

func readCertificate(filePath string) (*x509.Certificate, *pem.Block) {
	pemBlock := readPemFile(filePath)
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		panic(err)
	}
	return certificate, pemBlock
}

func readPemFile(filePath string) *pem.Block {
	file, err := os.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
	pemBlock, _ := pem.Decode(file)
	return pemBlock
}

func checkTimeValidity(cert *models.X509Certificate) {
	if cert.NotBefore.After(time.Now()) || cert.NotAfter.Before(time.Now()) {
		panic(errors.New("cert is expired when it should not be"))
	}
}

func cleanX509CertificateTestTables() {
	db := postgresqlTestBackend.Db()

	_, err := db.Exec("delete from x509_certificates")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("delete from x509_private_keys")
	if err != nil {
		panic(err)
	}
}
