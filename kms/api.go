package kms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// ClientAPI presents an interface for a sub-part of the AWS KMS client service:
// "github.com/aws/aws-sdk-go-v2/service/kms"
type ClientAPI interface {
	GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	ReEncrypt(ctx context.Context, params *kms.ReEncryptInput, optFns ...func(*kms.Options)) (*kms.ReEncryptOutput, error)
}
