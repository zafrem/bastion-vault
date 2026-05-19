package kms

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	kmsv2 "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// mockKMSClient implements the kmsClient interface with user-injectable behaviour.
type mockKMSClient struct {
	generateDataKeyFn func(ctx context.Context, params *kmsv2.GenerateDataKeyInput, optFns ...func(*kmsv2.Options)) (*kmsv2.GenerateDataKeyOutput, error)
	encryptFn         func(ctx context.Context, params *kmsv2.EncryptInput, optFns ...func(*kmsv2.Options)) (*kmsv2.EncryptOutput, error)
	decryptFn         func(ctx context.Context, params *kmsv2.DecryptInput, optFns ...func(*kmsv2.Options)) (*kmsv2.DecryptOutput, error)
	generateMacFn     func(ctx context.Context, params *kmsv2.GenerateMacInput, optFns ...func(*kmsv2.Options)) (*kmsv2.GenerateMacOutput, error)
	describeKeyFn     func(ctx context.Context, params *kmsv2.DescribeKeyInput, optFns ...func(*kmsv2.Options)) (*kmsv2.DescribeKeyOutput, error)
}

func (m *mockKMSClient) GenerateDataKey(ctx context.Context, params *kmsv2.GenerateDataKeyInput, optFns ...func(*kmsv2.Options)) (*kmsv2.GenerateDataKeyOutput, error) {
	return m.generateDataKeyFn(ctx, params, optFns...)
}

func (m *mockKMSClient) Encrypt(ctx context.Context, params *kmsv2.EncryptInput, optFns ...func(*kmsv2.Options)) (*kmsv2.EncryptOutput, error) {
	return m.encryptFn(ctx, params, optFns...)
}

func (m *mockKMSClient) Decrypt(ctx context.Context, params *kmsv2.DecryptInput, optFns ...func(*kmsv2.Options)) (*kmsv2.DecryptOutput, error) {
	return m.decryptFn(ctx, params, optFns...)
}

func (m *mockKMSClient) GenerateMac(ctx context.Context, params *kmsv2.GenerateMacInput, optFns ...func(*kmsv2.Options)) (*kmsv2.GenerateMacOutput, error) {
	return m.generateMacFn(ctx, params, optFns...)
}

func (m *mockKMSClient) DescribeKey(ctx context.Context, params *kmsv2.DescribeKeyInput, optFns ...func(*kmsv2.Options)) (*kmsv2.DescribeKeyOutput, error) {
	return m.describeKeyFn(ctx, params, optFns...)
}

func TestAWSProvider_GenerateDataKey(t *testing.T) {
	plaintext := []byte("0123456789abcdef0123456789abcdef")
	ciphertext := []byte("ciphertext-blob")
	mock := &mockKMSClient{
		generateDataKeyFn: func(ctx context.Context, params *kmsv2.GenerateDataKeyInput, optFns ...func(*kmsv2.Options)) (*kmsv2.GenerateDataKeyOutput, error) {
			return &kmsv2.GenerateDataKeyOutput{
				Plaintext:      plaintext,
				CiphertextBlob: ciphertext,
				KeyId:          aws.String("master-key-1"),
			}, nil
		},
	}
	p := newAWSProviderWithClient(mock, "master-key-1")

	dk, err := p.GenerateDataKey(context.Background(), "tenant-key")
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if string(dk.Plaintext) != string(plaintext) {
		t.Errorf("plaintext = %q, want %q", dk.Plaintext, plaintext)
	}
	if string(dk.Ciphertext) != string(ciphertext) {
		t.Errorf("ciphertext = %q, want %q", dk.Ciphertext, ciphertext)
	}
	if dk.KeyID != "master-key-1" {
		t.Errorf("keyID = %q, want master-key-1", dk.KeyID)
	}
}

func TestAWSProvider_DecryptDataKey(t *testing.T) {
	known := []byte("the-known-plaintext")
	mock := &mockKMSClient{
		decryptFn: func(ctx context.Context, params *kmsv2.DecryptInput, optFns ...func(*kmsv2.Options)) (*kmsv2.DecryptOutput, error) {
			return &kmsv2.DecryptOutput{Plaintext: known}, nil
		},
	}
	p := newAWSProviderWithClient(mock, "master-key-1")

	pt, err := p.DecryptDataKey(context.Background(), []byte("some-ciphertext"), "tenant-key")
	if err != nil {
		t.Fatalf("DecryptDataKey: %v", err)
	}
	if string(pt) != string(known) {
		t.Errorf("plaintext = %q, want %q", pt, known)
	}
}

func TestAWSProvider_EncryptDecrypt(t *testing.T) {
	original := []byte("sensitive-data")
	ciphertext := []byte("encrypted-form")
	mock := &mockKMSClient{
		encryptFn: func(ctx context.Context, params *kmsv2.EncryptInput, optFns ...func(*kmsv2.Options)) (*kmsv2.EncryptOutput, error) {
			if string(params.Plaintext) != string(original) {
				t.Errorf("Encrypt got plaintext %q", params.Plaintext)
			}
			return &kmsv2.EncryptOutput{CiphertextBlob: ciphertext}, nil
		},
		decryptFn: func(ctx context.Context, params *kmsv2.DecryptInput, optFns ...func(*kmsv2.Options)) (*kmsv2.DecryptOutput, error) {
			if string(params.CiphertextBlob) != string(ciphertext) {
				t.Errorf("Decrypt got ciphertext %q", params.CiphertextBlob)
			}
			return &kmsv2.DecryptOutput{Plaintext: original}, nil
		},
	}
	p := newAWSProviderWithClient(mock, "master-key-1")

	ct, err := p.Encrypt(context.Background(), "k", original)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(ct) != string(ciphertext) {
		t.Errorf("ciphertext = %q, want %q", ct, ciphertext)
	}

	pt, err := p.Decrypt(context.Background(), "k", ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != string(original) {
		t.Errorf("round-trip plaintext = %q, want %q", pt, original)
	}
}

func TestAWSProvider_GenerateHMACKey_MacSuccess(t *testing.T) {
	mac := make([]byte, 48) // > 32 bytes
	for i := range mac {
		mac[i] = byte(i)
	}
	mock := &mockKMSClient{
		generateMacFn: func(ctx context.Context, params *kmsv2.GenerateMacInput, optFns ...func(*kmsv2.Options)) (*kmsv2.GenerateMacOutput, error) {
			return &kmsv2.GenerateMacOutput{Mac: mac}, nil
		},
	}
	p := newAWSProviderWithClient(mock, "master-key-1")

	key, err := p.GenerateHMACKey(context.Background(), "audit-key")
	if err != nil {
		t.Fatalf("GenerateHMACKey: %v", err)
	}
	if len(key) < 32 {
		t.Errorf("HMAC key length = %d, want >= 32", len(key))
	}
}

func TestAWSProvider_GenerateHMACKey_Fallback(t *testing.T) {
	// GenerateMac fails -> falls through to Encrypt/Decrypt path.
	plaintext := []byte("recovered-key-material-padded-out-to-length")
	mock := &mockKMSClient{
		generateMacFn: func(ctx context.Context, params *kmsv2.GenerateMacInput, optFns ...func(*kmsv2.Options)) (*kmsv2.GenerateMacOutput, error) {
			return nil, errors.New("master key is not an HMAC key")
		},
		encryptFn: func(ctx context.Context, params *kmsv2.EncryptInput, optFns ...func(*kmsv2.Options)) (*kmsv2.EncryptOutput, error) {
			return &kmsv2.EncryptOutput{CiphertextBlob: []byte("ct")}, nil
		},
		decryptFn: func(ctx context.Context, params *kmsv2.DecryptInput, optFns ...func(*kmsv2.Options)) (*kmsv2.DecryptOutput, error) {
			return &kmsv2.DecryptOutput{Plaintext: plaintext}, nil
		},
	}
	p := newAWSProviderWithClient(mock, "master-key-1")

	key, err := p.GenerateHMACKey(context.Background(), "audit-key")
	if err != nil {
		t.Fatalf("GenerateHMACKey fallback: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("fallback HMAC key length = %d, want 32", len(key))
	}
}

func TestAWSProvider_DescribeKey(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	mock := &mockKMSClient{
		describeKeyFn: func(ctx context.Context, params *kmsv2.DescribeKeyInput, optFns ...func(*kmsv2.Options)) (*kmsv2.DescribeKeyOutput, error) {
			return &kmsv2.DescribeKeyOutput{
				KeyMetadata: &types.KeyMetadata{
					KeyId:        aws.String("master-key-1"),
					KeyState:     types.KeyStateEnabled,
					CreationDate: &created,
					Description:  aws.String("primary master key"),
				},
			}, nil
		},
	}
	p := newAWSProviderWithClient(mock, "master-key-1")

	info, err := p.DescribeKey(context.Background(), "tenant-key")
	if err != nil {
		t.Fatalf("DescribeKey: %v", err)
	}
	if info.KeyID != "tenant-key" {
		t.Errorf("KeyID = %q, want tenant-key", info.KeyID)
	}
	if info.State != string(types.KeyStateEnabled) {
		t.Errorf("State = %q, want %q", info.State, types.KeyStateEnabled)
	}
	if info.Description != "primary master key" {
		t.Errorf("Description = %q, want 'primary master key'", info.Description)
	}
	if !info.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", info.CreatedAt, created)
	}
}
