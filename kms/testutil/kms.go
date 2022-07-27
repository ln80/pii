package testutil

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var (
	kmsvc   *kms.Client
	kmsonce sync.Once

	kmsKey string
)

func WithKMSKey(t *testing.T, tfn func(kmsvc interface{}, key string)) {
	ctx := context.Background()

	endpoint := os.Getenv("KMS_ENDPOINT")
	if endpoint == "" {
		t.Fatal("kms test endpoint not found")
	}

	kmsonce.Do(func() {
		cfg, err := config.LoadDefaultConfig(
			ctx,
			config.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider("TEST", "TEST", "TEST"),
			),
		)
		if err != nil {
			t.Fatal(err)
		}

		kmsvc = kms.NewFromConfig(cfg, func(o *kms.Options) {
			o.EndpointResolver = kms.EndpointResolverFromURL(endpoint)
		})

		out1, err := kmsvc.CreateKey(ctx, &kms.CreateKeyInput{})
		if err != nil {
			t.Fatal(err)
		}

		kmsKey = aws.ToString(out1.KeyMetadata.KeyId)
		t.Log("kms test keys created:", kmsKey)
	})

	tfn(kmsvc, kmsKey)

}
