package service

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"github.com/pki-vault/server/internal/db/repository"
	"os"
	"reflect"
	"testing"
)

func TestParsePrivateKey(t *testing.T) {
	type args struct {
		der []byte
	}
	tests := []struct {
		name        string
		args        args
		wantKey     crypto.PrivateKey
		wantKeyType string
		wantErr     bool
	}{
		{
			name: "PKCS1 RSA 2048",
			args: args{
				der: readPemFile(t, "testdata/private_keys/pkcs1_rsa_2048.pem").Bytes,
			},
			wantKey: func() crypto.PrivateKey {
				key, err := x509.ParsePKCS1PrivateKey(readPemFile(t, "testdata/private_keys/pkcs1_rsa_2048.pem").Bytes)
				if err != nil {
					t.Fatal(err)
				}
				return key
			}(),
			wantKeyType: string(repository.PrivateKeyTypeRSA),
			wantErr:     false,
		},
		{
			name: "PKCS8 RSA 2048",
			args: args{
				der: readPemFile(t, "testdata/private_keys/pkcs8_rsa_2048.pem").Bytes,
			},
			wantKey: func() crypto.PrivateKey {
				key, err := x509.ParsePKCS8PrivateKey(readPemFile(t, "testdata/private_keys/pkcs8_rsa_2048.pem").Bytes)
				if err != nil {
					t.Fatal(err)
				}
				return key
			}(),
			wantKeyType: string(repository.PrivateKeyTypeRSA),
			wantErr:     false,
		},
		{
			name: "PKCS8 ECDSA prime256v1",
			args: args{
				der: readPemFile(t, "testdata/private_keys/pkcs8_ecdsa_prime256v1.pem").Bytes,
			},
			wantKey: func() crypto.PrivateKey {
				key, err := x509.ParsePKCS8PrivateKey(readPemFile(t, "testdata/private_keys/pkcs8_ecdsa_prime256v1.pem").Bytes)
				if err != nil {
					t.Fatal(err)
				}
				return key
			}(),
			wantKeyType: string(repository.PrivateKeyTypeECDSA),
			wantErr:     false,
		},
		{
			name: "PKCS8 Ed25519 256bit",
			args: args{
				der: readPemFile(t, "testdata/private_keys/pkcs8_ed25519_256.pem").Bytes,
			},
			wantKey: func() crypto.PrivateKey {
				key, err := x509.ParsePKCS8PrivateKey(readPemFile(t, "testdata/private_keys/pkcs8_ed25519_256.pem").Bytes)
				if err != nil {
					t.Fatal(err)
				}
				return key
			}(),
			wantKeyType: string(repository.PrivateKeyTypeED25519),
			wantErr:     false,
		},
		{
			name: "EC ECDSA prime256v1",
			args: args{
				der: readPemFile(t, "testdata/private_keys/ec_ecdsa_prime256v1.pem").Bytes,
			},
			wantKey: func() crypto.PrivateKey {
				key, err := x509.ParseECPrivateKey(readPemFile(t, "testdata/private_keys/ec_ecdsa_prime256v1.pem").Bytes)
				if err != nil {
					t.Fatal(err)
				}
				return key
			}(),
			wantKeyType: string(repository.PrivateKeyTypeECDSA),
			wantErr:     false,
		},
		{
			name: "Invalid key",
			args: args{
				der: []byte("invalid"),
			},
			wantKey:     nil,
			wantKeyType: "",
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotKeyType, err := ParsePrivateKey(tt.args.der)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotKey, tt.wantKey) {
				t.Errorf("ParsePrivateKey() gotKey = %v, want %v", gotKey, tt.wantKey)
			}
			if gotKeyType != tt.wantKeyType {
				t.Errorf("ParsePrivateKey() gotKeyType = %v, want %v", gotKeyType, tt.wantKeyType)
			}
		})
	}
}

func readPemFile(t *testing.T, filePath string) *pem.Block {
	file, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, _ := pem.Decode(file)
	return pemBlock
}
