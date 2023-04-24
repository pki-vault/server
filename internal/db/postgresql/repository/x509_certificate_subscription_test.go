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

func TestNewX509CertificateSubscriptionRepository(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()

	type args struct {
		db    *sql.DB
		clock clockwork.Clock
	}
	tests := []struct {
		name string
		args args
		want *X509CertificateSubscriptionRepository
	}{
		{
			name: "ensure all fields are set",
			args: args{
				db:    postgresqlTestBackend.Db(),
				clock: fakeClock,
			},
			want: &X509CertificateSubscriptionRepository{
				db:    postgresqlTestBackend.Db(),
				clock: fakeClock,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewX509CertificateSubscriptionRepository(tt.args.db, tt.args.clock)
			if !testutil.AllFieldsNotNilOrEmptyStruct(got) {
				t.Errorf("NewX509CertificateSubscriptionRepository() not all fields are set")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTransactionManager() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestX509CertificateSubscriptionRepository_Create(t *testing.T) {
	ctx := context.Background()
	fakeClock := clockwork.NewFakeClock()
	db := postgresqlTestBackend.Db()
	repo := &X509CertificateSubscriptionRepository{
		db:    db,
		clock: fakeClock,
	}

	if err := seedX509CertificateSubscriptionTestData(t, ctx, fakeClock); err != nil {
		t.Fatal(err)
	}

	t.Run("create subscripton", func(t *testing.T) {
		id := uuid.MustParse("a65a579e-76b3-441a-b20d-6dd2fdaca268")

		toBeCreatedSub := repository.X509CertificateSubscriptionDao{
			ID:                id,
			SubjectAltNames:   []string{"test.example.invalid", "sub.example.invalid"},
			IncludePrivateKey: true,
			CreatedAt:         fakeClock.Now(),
		}
		expectedSub := toBeCreatedSub
		expectedSub.CreatedAt = normalizeTime(expectedSub.CreatedAt)

		exists, err := models.X509CertificateSubscriptions(models.X509CertificateSubscriptionWhere.ID.EQ(id.String())).Exists(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatal("To be created sub ID already exists")
		}

		createdSub, err := repo.Create(ctx, &toBeCreatedSub)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(createdSub, &expectedSub) {
			t.Errorf("GetOrCreate() = %v, want %v", createdSub, &expectedSub)
		}

		// Ensure inserted record in the database is correct
		var fetchedSub *repository.X509CertificateSubscriptionDao
		{
			fetchedSubModel, err := models.
				X509CertificateSubscriptions(models.X509CertificateSubscriptionWhere.ID.EQ(id.String())).
				One(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			fetchedSub = postgresqlCertificateSubscriptionToDto(fetchedSubModel)
		}

		if !reflect.DeepEqual(fetchedSub, &expectedSub) {
			t.Errorf("GetOrCreate() = %v, want %v", fetchedSub, &expectedSub)
		}
	})
}

func TestX509CertificateSubscriptionRepository_Delete(t *testing.T) {
	ctx := context.Background()
	fakeClock := clockwork.NewFakeClock()
	db := postgresqlTestBackend.Db()
	repo := &X509CertificateSubscriptionRepository{
		db:    db,
		clock: fakeClock,
	}

	if err := seedX509CertificateSubscriptionTestData(t, ctx, fakeClock); err != nil {
		t.Fatal(err)
	}

	t.Run("delete subscripton", func(t *testing.T) {
		id := uuid.MustParse("ee6fdd50-0ce9-4186-892b-fd0c0c1482d9")
		toBeCreatedSub := &models.X509CertificateSubscription{
			ID:                id.String(),
			SubjectAltNames:   []string{"test.example.invalid", "sub.example.invalid"},
			IncludePrivateKey: true,
			CreatedAt:         fakeClock.Now(),
		}
		err := toBeCreatedSub.Insert(ctx, db, boil.Infer())
		if err != nil {
			t.Fatal(err)
		}

		rowsDeleted, err := repo.Delete(ctx, id)
		if err != nil {
			t.Fatal(err)
		}

		if rowsDeleted != 1 {
			t.Errorf("expected 1 row to be deleted but got %d deleted rows", rowsDeleted)
		}

		exists, err := models.X509CertificateSubscriptions(models.X509CertificateSubscriptionWhere.ID.EQ(id.String())).Exists(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Errorf("expected sub with id %s to be deleted, but it still exists", id.String())
		}
	})
}

func TestX509CertificateSubscriptionRepository_FindByIDs(t *testing.T) {
	ctx := context.Background()
	fakeClock := clockwork.NewFakeClock()

	if err := seedX509CertificateSubscriptionTestData(t, ctx, fakeClock); err != nil {
		t.Fatal(err)
	}

	type fields struct {
		db    *sql.DB
		clock clockwork.Clock
	}
	type args struct {
		ctx context.Context
		IDs []uuid.UUID
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*repository.X509CertificateSubscriptionDao
		wantErr bool
	}{
		{
			name: "find existing",
			fields: fields{
				db:    postgresqlTestBackend.Db(),
				clock: fakeClock,
			},
			args: args{
				ctx: ctx,
				IDs: []uuid.UUID{uuid.MustParse("7c9098f4-7dbd-471e-83fb-19be7095ae04")},
			},
			want: []*repository.X509CertificateSubscriptionDao{
				{
					ID:                uuid.MustParse("7c9098f4-7dbd-471e-83fb-19be7095ae04"),
					SubjectAltNames:   []string{"test.example.invalid"},
					IncludePrivateKey: false,
					CreatedAt:         normalizeTime(fakeClock.Now()),
				},
			},
			wantErr: false,
		},
		{
			name: "dont find not existing",
			fields: fields{
				db:    postgresqlTestBackend.Db(),
				clock: fakeClock,
			},
			args: args{
				ctx: ctx,
				IDs: []uuid.UUID{uuid.MustParse("26a1e6ec-570f-44e2-b2bf-8c43ea90ce68")},
			},
			want:    []*repository.X509CertificateSubscriptionDao{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &X509CertificateSubscriptionRepository{
				db:    tt.fields.db,
				clock: tt.fields.clock,
			}
			got, err := x.FindByIDs(tt.args.ctx, tt.args.IDs)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindByIDs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for wantIndex := range tt.want {
				if !reflect.DeepEqual(tt.want[wantIndex], got[wantIndex]) {
					t.Errorf("FindByIDs() got = %+v, want %+v", *got[wantIndex], *tt.want[wantIndex])
				}
			}
		})
	}
}

func Test_postgresqlSubscriptionToDto(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()

	type args struct {
		sub *models.X509CertificateSubscription
	}
	tests := []struct {
		name string
		args args
		want *repository.X509CertificateSubscriptionDao
	}{
		{
			name: "ensure correct transform",
			args: args{
				sub: &models.X509CertificateSubscription{
					ID:                "a48018b2-a6f7-4a44-9141-cb5108530181",
					SubjectAltNames:   []string{"test.example.invalid", "test2.example.invalid"},
					IncludePrivateKey: true,
					CreatedAt:         fakeClock.Now(),
				},
			},
			want: &repository.X509CertificateSubscriptionDao{
				ID:                uuid.MustParse("a48018b2-a6f7-4a44-9141-cb5108530181"),
				SubjectAltNames:   []string{"test.example.invalid", "test2.example.invalid"},
				IncludePrivateKey: true,
				CreatedAt:         normalizeTime(fakeClock.Now()),
			},
		},
		{
			name: "ensure correct time normalization",
			args: args{
				sub: &models.X509CertificateSubscription{
					ID:                "a48018b2-a6f7-4a44-9141-cb5108530181",
					SubjectAltNames:   []string{"example.invalid"},
					IncludePrivateKey: false,
					CreatedAt:         testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.0016Z"),
				},
			},
			want: &repository.X509CertificateSubscriptionDao{
				ID:                uuid.MustParse("a48018b2-a6f7-4a44-9141-cb5108530181"),
				SubjectAltNames:   []string{"example.invalid"},
				IncludePrivateKey: false,
				CreatedAt:         testutil.TimeMustParse(time.RFC3339, "2022-04-15T14:30:00.002Z"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !testutil.AllFieldsNotNilOrEmptyStruct(tt.want) {
				t.Errorf("postgresqlCertificateSubscriptionToDto() not all fields are set")
			}
			if got := postgresqlCertificateSubscriptionToDto(tt.args.sub); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("postgresqlCertificateSubscriptionToDto() = %v, want %v", got, tt.want)
			}
		})
	}
}

func seedX509CertificateSubscriptionTestData(t *testing.T, ctx context.Context, clock clockwork.Clock) error {
	t.Cleanup(cleanupX509CertificateSubscriptionTestTables)
	{
		sub := models.X509CertificateSubscription{
			ID:                "7c9098f4-7dbd-471e-83fb-19be7095ae04",
			SubjectAltNames:   []string{"test.example.invalid"},
			IncludePrivateKey: false,
			CreatedAt:         normalizeTime(clock.Now()),
		}
		err := sub.Insert(ctx, postgresqlTestBackend.Db(), boil.Infer())
		if err != nil {
			return err
		}
	}
	{
		sub := models.X509CertificateSubscription{
			ID:                "fea3641b-d12c-41e2-880e-e9c27c7adc35",
			SubjectAltNames:   []string{"pki-vault.invalid"},
			IncludePrivateKey: false,
			CreatedAt:         normalizeTime(clock.Now().Add(1 * 24 * time.Hour)),
		}
		err := sub.Insert(ctx, postgresqlTestBackend.Db(), boil.Infer())
		if err != nil {
			return err
		}
	}
	{
		sub := models.X509CertificateSubscription{
			ID:                "bd319c37-f6ff-4ca8-9bd2-2d17d962387c",
			SubjectAltNames:   []string{"sub.pki-vault.invalid"},
			IncludePrivateKey: true,
			CreatedAt:         normalizeTime(clock.Now().Add(2 * 24 * time.Hour)),
		}
		err := sub.Insert(ctx, postgresqlTestBackend.Db(), boil.Infer())
		if err != nil {
			return err
		}
	}
	return nil
}

func cleanupX509CertificateSubscriptionTestTables() {
	_, err := postgresqlTestBackend.Db().Exec("truncate table x509_certificate_subscriptions")
	if err != nil {
		panic(err)
	}
}
