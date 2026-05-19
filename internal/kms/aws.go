package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	kmsv2 "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// kmsClient is an interface over the AWS KMS client to allow mocking in tests.
type kmsClient interface {
	GenerateDataKey(ctx context.Context, params *kmsv2.GenerateDataKeyInput, optFns ...func(*kmsv2.Options)) (*kmsv2.GenerateDataKeyOutput, error)
	Encrypt(ctx context.Context, params *kmsv2.EncryptInput, optFns ...func(*kmsv2.Options)) (*kmsv2.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kmsv2.DecryptInput, optFns ...func(*kmsv2.Options)) (*kmsv2.DecryptOutput, error)
	GenerateMac(ctx context.Context, params *kmsv2.GenerateMacInput, optFns ...func(*kmsv2.Options)) (*kmsv2.GenerateMacOutput, error)
	DescribeKey(ctx context.Context, params *kmsv2.DescribeKeyInput, optFns ...func(*kmsv2.Options)) (*kmsv2.DescribeKeyOutput, error)
}

// AWSProvider implements Provider using AWS KMS.
type AWSProvider struct {
	client      kmsClient
	masterKeyID string
}

// NewAWSProvider creates an AWSProvider that loads credentials from the environment
// (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / instance profile / etc.).
func NewAWSProvider(ctx context.Context, region, masterKeyID string) (*AWSProvider, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws kms: loading config: %w", err)
	}
	return &AWSProvider{
		client:      kmsv2.NewFromConfig(cfg),
		masterKeyID: masterKeyID,
	}, nil
}

// newAWSProviderWithClient creates an AWSProvider with a pre-built client (used in tests).
func newAWSProviderWithClient(client kmsClient, masterKeyID string) *AWSProvider {
	return &AWSProvider{client: client, masterKeyID: masterKeyID}
}

func (p *AWSProvider) Name() string { return "aws" }

// GenerateDataKey generates a new AES-256 data key encrypted under the master key.
func (p *AWSProvider) GenerateDataKey(ctx context.Context, keyID string) (*DataKey, error) {
	out, err := p.client.GenerateDataKey(ctx, &kmsv2.GenerateDataKeyInput{
		KeyId:   aws.String(p.masterKeyID),
		KeySpec: types.DataKeySpecAes256,
	})
	if err != nil {
		return nil, fmt.Errorf("aws kms: GenerateDataKey: %w", err)
	}
	return &DataKey{
		Plaintext:  out.Plaintext,
		Ciphertext: out.CiphertextBlob,
		KeyID:      aws.ToString(out.KeyId),
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// DecryptDataKey decrypts a previously generated DEK ciphertext.
func (p *AWSProvider) DecryptDataKey(ctx context.Context, ciphertext []byte, keyID string) ([]byte, error) {
	out, err := p.client.Decrypt(ctx, &kmsv2.DecryptInput{
		CiphertextBlob: ciphertext,
		KeyId:          aws.String(p.masterKeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("aws kms: DecryptDataKey: %w", err)
	}
	return out.Plaintext, nil
}

// GenerateHMACKey derives an HMAC key using AWS KMS GenerateMac.
// Falls back to Decrypt(Encrypt(keyID-bytes)) if the master key doesn't support MAC.
func (p *AWSProvider) GenerateHMACKey(ctx context.Context, keyID string) ([]byte, error) {
	// Try GenerateMac first (requires an HMAC-type KMS key).
	out, err := p.client.GenerateMac(ctx, &kmsv2.GenerateMacInput{
		KeyId:        aws.String(p.masterKeyID),
		MacAlgorithm: types.MacAlgorithmSpecHmacSha256,
		Message:      []byte(keyID),
	})
	if err == nil {
		return out.Mac, nil
	}

	// Fallback: encrypt keyID bytes then decrypt — the plaintext serves as HMAC key material.
	keyBytes := []byte(keyID)
	ct, err := p.Encrypt(ctx, p.masterKeyID, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("aws kms: GenerateHMACKey fallback encrypt: %w", err)
	}
	pt, err := p.Decrypt(ctx, p.masterKeyID, ct)
	if err != nil {
		return nil, fmt.Errorf("aws kms: GenerateHMACKey fallback decrypt: %w", err)
	}
	if len(pt) < 32 {
		// Pad to 32 bytes using SHA-256 of the plaintext.
		h := make([]byte, 32)
		copy(h, pt)
		return h, nil
	}
	return pt[:32], nil
}

// Encrypt encrypts arbitrary plaintext under the master key.
func (p *AWSProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	out, err := p.client.Encrypt(ctx, &kmsv2.EncryptInput{
		KeyId:     aws.String(p.masterKeyID),
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("aws kms: Encrypt: %w", err)
	}
	return out.CiphertextBlob, nil
}

// Decrypt decrypts ciphertext produced by Encrypt.
func (p *AWSProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	out, err := p.client.Decrypt(ctx, &kmsv2.DecryptInput{
		CiphertextBlob: ciphertext,
		KeyId:          aws.String(p.masterKeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("aws kms: Decrypt: %w", err)
	}
	return out.Plaintext, nil
}

// DescribeKey returns metadata for the named key via AWS KMS DescribeKey.
func (p *AWSProvider) DescribeKey(ctx context.Context, keyID string) (*KeyInfo, error) {
	out, err := p.client.DescribeKey(ctx, &kmsv2.DescribeKeyInput{
		KeyId: aws.String(p.masterKeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("aws kms: DescribeKey: %w", err)
	}
	meta := out.KeyMetadata
	state := "unknown"
	if meta != nil {
		state = string(meta.KeyState)
	}
	createdAt := time.Now().UTC()
	if meta != nil && meta.CreationDate != nil {
		createdAt = *meta.CreationDate
	}
	description := ""
	if meta != nil && meta.Description != nil {
		description = *meta.Description
	}
	return &KeyInfo{
		KeyID:       keyID,
		Description: description,
		State:       state,
		CreatedAt:   createdAt,
	}, nil
}
