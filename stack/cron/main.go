package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	piidb "github.com/ln80/pii/dynamodb"
)

var (
	_unitTesting bool

	engine piidb.KeyEngine
)

func init() {
	if _unitTesting {
		return
	}

	table := os.Getenv("DYNAMODB_TABLE")
	if table == "" {
		log.Fatalf(`
			missed env params:
				DYNAMODB_TABLE: %v,
			`, table)
	}
	log.Println("env Table Name:", table)

	cfg, err := config.LoadDefaultConfig(
		context.Background(),
	)
	if err != nil {
		log.Fatalf("init dependencies failed: %v", err)
	}

	svc := dynamodb.NewFromConfig(cfg)
	engine = piidb.NewKeyEngine(svc, table, func(ec *piidb.KeyEngineConfig) {
		if gp := os.Getenv("GRACE_PERIOD"); gp != "" {
			d, err := strconv.Atoi(gp)
			if err != nil {
				log.Fatalf("failed to parse GracePeriod: %s: %v", gp, err)
			}
			ec.GracePeriod = time.Second * time.Duration(d)
		}
	})
}

func main() {
	lambda.Start(makeHandler(engine))
}
