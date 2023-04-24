package repository

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/db/postgresql/models"
	"github.com/pki-vault/server/internal/db/repository"
	"github.com/pki-vault/server/internal/testutil"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"reflect"
	"testing"
	"time"
)

func TestNewPrivateKeyRepository(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	db := postgresqlTestBackend.Db()

	type args struct {
		db    *sql.DB
		clock clockwork.Clock
	}
	tests := []struct {
		name string
		args args
		want *X509PrivateKeyRepository
	}{
		{
			name: "ensure all fields are set",
			args: args{
				db:    db,
				clock: fakeClock,
			},
			want: &X509PrivateKeyRepository{
				db:    db,
				clock: fakeClock,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewX509PrivateKeyRepository(tt.args.db, tt.args.clock)
			if !testutil.AllFieldsNotNilOrEmptyStruct(got) {
				t.Errorf("NewX509PrivateKeyRepository() not all fields are set")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewX509PrivateKeyRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivateKeyRepository_FindById(t *testing.T) {
	ctx := context.Background()
	fakeClock := clockwork.NewFakeClock()
	db := postgresqlTestBackend.Db()

	if err := seedX509PrivateKeyTestData(t, ctx, fakeClock); err != nil {
		t.Fatal(err)
	}

	type fields struct {
		db    *sql.DB
		clock clockwork.Clock
	}
	type args struct {
		ctx context.Context
		id  uuid.UUID
	}
	tests := []struct {
		name              string
		fields            fields
		args              args
		wantPrivateKeyDao *repository.X509PrivateKeyDao
		wantExists        bool
		wantErr           bool
	}{
		{
			name: "find existing",
			fields: fields{
				db:    db,
				clock: fakeClock,
			},
			args: args{
				ctx: ctx,
				id:  uuid.MustParse("69de12f8-9542-4a9c-88f5-d7db600ce3ed"),
			},
			wantPrivateKeyDao: &repository.X509PrivateKeyDao{
				ID:            uuid.MustParse("69de12f8-9542-4a9c-88f5-d7db600ce3ed"),
				Type:          "RSA",
				PemBlockType:  "RSA PRIVATE KEY",
				BytesHash:     []byte{0x8E, 0x4F, 0xF3, 0x6A, 0x3D},
				Bytes:         []byte{0x6F, 0x1B, 0x59, 0xC8, 0x82},
				PublicKeyHash: []byte{0x04, 0xE2, 0x11, 0xF9, 0x0C},
				CreatedAt:     normalizeTime(fakeClock.Now()),
			},
			wantExists: true,
			wantErr:    false,
		},
		{
			name: "dont find not existing",
			fields: fields{
				db:    db,
				clock: fakeClock,
			},
			args: args{
				ctx: ctx,
				id:  uuid.MustParse("8446864e-0231-437a-b40b-2dd1619a8a35"),
			},
			wantPrivateKeyDao: nil,
			wantExists:        false,
			wantErr:           false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &X509PrivateKeyRepository{
				db:    tt.fields.db,
				clock: tt.fields.clock,
			}
			gotPrivateKeyDao, gotExists, err := p.FindByID(tt.args.ctx, tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindByID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPrivateKeyDao, tt.wantPrivateKeyDao) {
				t.Errorf("FindByID() gotPrivateKeyDao = %v, want %v", gotPrivateKeyDao, tt.wantPrivateKeyDao)
			}
			if gotExists != tt.wantExists {
				t.Errorf("FindByID() gotExists = %v, want %v", gotExists, tt.wantExists)
			}
		})
	}
}

func TestPrivateKeyRepository_GetOrCreate(t *testing.T) {
	ctx := context.Background()
	fakeClock := clockwork.NewFakeClock()
	db := postgresqlTestBackend.Db()
	repo := &X509PrivateKeyRepository{
		db:    db,
		clock: fakeClock,
	}

	if err := seedX509CertificateTestData(t, ctx, fakeClock); err != nil {
		t.Fatal(err)
	}

	t.Run("create private key", func(t *testing.T) {
		id := uuid.MustParse("91fe0afa-91c3-443b-bea6-6cb69d2eb7b6")

		toBeCreatedPrivKey := repository.X509PrivateKeyDao{
			ID:            id,
			Type:          "RSA",
			PemBlockType:  "RSA PRIVATE KEY",
			BytesHash:     []byte{0xA9, 0x3D, 0x1E, 0x7B, 0xC8},
			Bytes:         []byte{0x31, 0xE1, 0x20, 0x7C, 0xB2},
			PublicKeyHash: []byte{0xC5, 0x47, 0x73, 0x8D, 0x0E},
			CreatedAt:     fakeClock.Now(),
		}
		expectedPrivKey := toBeCreatedPrivKey
		expectedPrivKey.CreatedAt = normalizeTime(expectedPrivKey.CreatedAt)

		exists, err := models.X509PrivateKeys(models.X509PrivateKeyWhere.ID.EQ(id.String())).Exists(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatal("To be created private key ID already exists")
		}

		createdPrivKey, err := repo.GetOrCreate(ctx, &toBeCreatedPrivKey)
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(createdPrivKey, &expectedPrivKey) {
			t.Errorf("GetOrCreate() = %v, want %v", createdPrivKey, &expectedPrivKey)
		}

		// Ensure inserted record in the database is correct
		var fetchedCreatedPrivKey *repository.X509PrivateKeyDao
		{
			fetchedCreatedPrivKeyModel, err := models.
				X509PrivateKeys(models.X509PrivateKeyWhere.ID.EQ(id.String())).
				One(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			fetchedCreatedPrivKey = postgresqlPrivateKeyToDao(fetchedCreatedPrivKeyModel)
		}

		if !reflect.DeepEqual(fetchedCreatedPrivKey, &expectedPrivKey) {
			t.Errorf("GetOrCreate() = %v, want %v", fetchedCreatedPrivKey, &expectedPrivKey)
		}
	})
}

func TestPrivateKeyRepository_postgresqlPrivateKeyToModel(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()

	type fields struct {
		db    *sql.DB
		clock clockwork.Clock
	}
	type args struct {
		privKey *repository.X509PrivateKeyDao
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *models.X509PrivateKey
	}{
		{
			name: "ensure correct transform",
			fields: fields{
				db:    nil,
				clock: fakeClock,
			},
			args: args{
				privKey: repository.NewX509PrivateKeyDao(
					uuid.MustParse("f682279b-db13-4c10-86a3-145774ee56dc"),
					repository.PrivateKeyTypeRSA,
					"RSA PRIVATE KEY",
					[]byte{0xE4, 0x89, 0x2C, 0x53},
					[]byte{0x72, 0xB6, 0x8D, 0x31},
					[]byte{0xD7, 0x9C, 0xF1, 0x23},
					fakeClock.Now(),
				),
			},
			want: &models.X509PrivateKey{
				ID:            "f682279b-db13-4c10-86a3-145774ee56dc",
				Type:          "RSA",
				PemBlockType:  "RSA PRIVATE KEY",
				BytesHash:     []byte{0xE4, 0x89, 0x2C, 0x53},
				Bytes:         []byte{0x72, 0xB6, 0x8D, 0x31},
				PublicKeyHash: []byte{0xD7, 0x9C, 0xF1, 0x23},
				CreatedAt:     normalizeTime(fakeClock.Now()),
			},
		},
		{
			name: "ensure correct time normalization",
			fields: fields{
				db:    nil,
				clock: fakeClock,
			},
			args: args{
				privKey: repository.NewX509PrivateKeyDao(
					uuid.MustParse("f682279b-db13-4c10-86a3-145774ee56dc"),
					repository.PrivateKeyTypeRSA,
					"RSA PRIVATE KEY",
					[]byte{0xE4, 0x89, 0x2C, 0x53},
					[]byte{0x72, 0xB6, 0x8D, 0x31},
					[]byte{0xD7, 0x9C, 0xF1, 0x23},
					testutil.TimeMustParse(time.RFC3339, "2023-04-15T14:30:00.0016Z"),
				),
			},
			want: &models.X509PrivateKey{
				ID:            "f682279b-db13-4c10-86a3-145774ee56dc",
				Type:          "RSA",
				PemBlockType:  "RSA PRIVATE KEY",
				BytesHash:     []byte{0xE4, 0x89, 0x2C, 0x53},
				Bytes:         []byte{0x72, 0xB6, 0x8D, 0x31},
				PublicKeyHash: []byte{0xD7, 0x9C, 0xF1, 0x23},
				CreatedAt:     testutil.TimeMustParse(time.RFC3339, "2023-04-15T14:30:00.002Z"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &X509PrivateKeyRepository{
				db:    tt.fields.db,
				clock: tt.fields.clock,
			}
			if got := p.postgresqlPrivateKeyToModel(tt.args.privKey); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("postgresqlPrivateKeyToModel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_postgresqlPrivateKeyToDao(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()

	type args struct {
		privateKey *models.X509PrivateKey
	}
	tests := []struct {
		name string
		args args
		want *repository.X509PrivateKeyDao
	}{
		{
			name: "ensure correct transform",
			args: args{
				privateKey: &models.X509PrivateKey{
					ID:            "d9952fee-8e50-452e-8829-09580368804f",
					Type:          "RSA",
					PemBlockType:  "RSA PRIVATE KEY",
					BytesHash:     []byte{0x5D, 0x3A, 0x9E, 0x21, 0x6B},
					Bytes:         []byte{0xD7, 0x0C, 0x8A, 0x77, 0x34},
					PublicKeyHash: []byte{0x2E, 0x91, 0xBC, 0x70, 0x15},
					CreatedAt:     fakeClock.Now(),
				},
			},
			want: &repository.X509PrivateKeyDao{
				ID:            uuid.MustParse("d9952fee-8e50-452e-8829-09580368804f"),
				Type:          "RSA",
				PemBlockType:  "RSA PRIVATE KEY",
				BytesHash:     []byte{0x5D, 0x3A, 0x9E, 0x21, 0x6B},
				Bytes:         []byte{0xD7, 0x0C, 0x8A, 0x77, 0x34},
				PublicKeyHash: []byte{0x2E, 0x91, 0xBC, 0x70, 0x15},
				CreatedAt:     normalizeTime(fakeClock.Now()),
			},
		},
		{
			name: "ensure correct time normalization",
			args: args{
				privateKey: &models.X509PrivateKey{
					ID:            "d9952fee-8e50-452e-8829-09580368804f",
					Type:          "RSA",
					PemBlockType:  "RSA PRIVATE KEY",
					BytesHash:     []byte{0x5D, 0x3A, 0x9E, 0x21, 0x6B},
					Bytes:         []byte{0xD7, 0x0C, 0x8A, 0x77, 0x34},
					PublicKeyHash: []byte{0x2E, 0x91, 0xBC, 0x70, 0x15},
					CreatedAt:     testutil.TimeMustParse(time.RFC3339, "2023-04-15T14:30:00.0016Z"),
				},
			},
			want: &repository.X509PrivateKeyDao{
				ID:            uuid.MustParse("d9952fee-8e50-452e-8829-09580368804f"),
				Type:          "RSA",
				PemBlockType:  "RSA PRIVATE KEY",
				BytesHash:     []byte{0x5D, 0x3A, 0x9E, 0x21, 0x6B},
				Bytes:         []byte{0xD7, 0x0C, 0x8A, 0x77, 0x34},
				PublicKeyHash: []byte{0x2E, 0x91, 0xBC, 0x70, 0x15},
				CreatedAt:     testutil.TimeMustParse(time.RFC3339, "2023-04-15T14:30:00.002Z"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !testutil.AllFieldsNotNilOrEmptyStruct(tt.want) {
				t.Errorf("postgresqlPrivateKeyToDao() not all fields are set")
			}
			if got := postgresqlPrivateKeyToDao(tt.args.privateKey); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("postgresqlPrivateKeyToDao() = %v, want %v", got, tt.want)
			}
		})
	}
}

func seedX509PrivateKeyTestData(t *testing.T, ctx context.Context, clock clockwork.Clock) error {
	db := postgresqlTestBackend.Db()
	t.Cleanup(cleanupX509PrivateKeyTestTables)
	{
		privKey := models.X509PrivateKey{
			ID:            "69de12f8-9542-4a9c-88f5-d7db600ce3ed",
			Type:          "RSA",
			PemBlockType:  "RSA PRIVATE KEY",
			BytesHash:     []byte{0x8E, 0x4F, 0xF3, 0x6A, 0x3D},
			Bytes:         []byte{0x6F, 0x1B, 0x59, 0xC8, 0x82},
			PublicKeyHash: []byte{0x04, 0xE2, 0x11, 0xF9, 0x0C},
			CreatedAt:     normalizeTime(clock.Now()),
		}
		err := privKey.Insert(ctx, db, boil.Infer())
		if err != nil {
			return err
		}
	}
	{
		privKey := models.X509PrivateKey{
			ID:            "c56025a2-ea2c-4dec-8bd7-90190e64d913",
			Type:          "ECDSA",
			PemBlockType:  "EC PRIVATE KEY",
			BytesHash:     []byte{0xE6, 0x7D, 0x18, 0xC5, 0x2B},
			Bytes:         []byte{0x17, 0x8D, 0x3F, 0x92, 0x67},
			PublicKeyHash: []byte{0x58, 0xFA, 0x87, 0x12, 0x9E},
			CreatedAt:     normalizeTime(clock.Now().Add(1 * 24 * time.Hour)),
		}
		err := privKey.Insert(ctx, db, boil.Infer())
		if err != nil {
			return err
		}
	}
	{
		privKey := models.X509PrivateKey{
			ID:            "8b8ab80f-0f82-4a16-aa1a-5d8998173ed5",
			Type:          "ED25519",
			PemBlockType:  "PRIVATE KEY",
			BytesHash:     []byte{0x99, 0x1A, 0x5D, 0x3B, 0x8C},
			Bytes:         []byte{0x36, 0xE8, 0x6F, 0xB1, 0xD9},
			PublicKeyHash: []byte{0x6D, 0x4E, 0x2A, 0xF0, 0x87},
			CreatedAt:     normalizeTime(clock.Now().Add(2 * 24 * time.Hour)),
		}
		err := privKey.Insert(ctx, db, boil.Infer())
		if err != nil {
			return err
		}
	}
	return nil
}

func cleanupX509PrivateKeyTestTables() {
	_, err := postgresqlTestBackend.Db().Exec("delete from x509_private_keys")
	if err != nil {
		panic(err)
	}
}
