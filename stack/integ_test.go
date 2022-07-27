//go:build integ

package main

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	piidb "github.com/ln80/pii/dynamodb"
	"github.com/ln80/pii/testutil"
)

func TestIntegration(t *testing.T) {
	table := os.Getenv("DYNAMODB_TABLE")
	if table == "" {
		t.Fatalf(`
			missed env params:
				DYNAMODB_TABLE: %v,
		`, table)
	}
	cronFn := os.Getenv("CRON_FUNC")
	if cronFn == "" {
		t.Fatalf(`
			missed env params:
				CRON_FUNC: %v,
		`, table)
	}
	var gracePeriod time.Duration
	if gp := os.Getenv("GRACE_PERIOD"); gp != "" {
		d, err := strconv.Atoi(gp)
		if err != nil {
			t.Fatalf("failed to parse GracePeriod: %s: %v", gp, err)
		}
		gracePeriod = time.Second * time.Duration(d)
	}

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(
		ctx,
	)
	if err != nil {
		t.Fatalf("init dependencies failed: %v", err)
	}
	svc := dynamodb.NewFromConfig(cfg)

	engine := piidb.NewKeyEngine(svc, table, func(ec *piidb.KeyEngineConfig) {
		ec.GracePeriod = gracePeriod
	})

	nspace := "tnt-" + strconv.FormatInt(time.Now().Unix(), 10)
	t.Logf("integ test namespace: %s", nspace)

	testutil.KeyEngineTestSuite(t, ctx, engine, func(keto *testutil.KeyEngineTestOption) {
		keto.Namespace = nspace

		keto.GracePeriod = gracePeriod

		// Use test option hook to force cron lambda invoke
		keto.AutoDeleteUnusedHook = func() {
			var cfg aws.Config
			cfg, err = config.LoadDefaultConfig(
				context.Background(),
			)
			if err != nil {
				t.Fatal("expect err be nil got", err)
			}
			out, err := lambda.NewFromConfig(cfg).Invoke(ctx, &lambda.InvokeInput{
				FunctionName: aws.String(cronFn),
			})
			if err != nil {
				t.Fatal("expect err be nil got", err)
			}
			t.Logf("invoke cron lambda output: %d %v\n", out.StatusCode, string(out.Payload))
		}
	})
}
