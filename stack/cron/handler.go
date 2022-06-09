package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	piidb "github.com/ln80/pii/dynamodb"
)

var errInvalidKeyEngine = errors.New("invalid key engine value, nil found")

type handler func(context.Context, events.CloudWatchEvent) error

func makeHandler(eng piidb.KeyEngine) handler {
	return func(ctx context.Context, _ events.CloudWatchEvent) (err error) {
		if eng == nil {
			return errInvalidKeyEngine
		}

		ns, err := eng.ListNamespace(ctx)
		if err != nil {
			return
		}

		for _, nspace := range ns {
			err = eng.DeleteUnusedKeys(ctx, nspace)
			if err != nil {
				err = fmt.Errorf("ns: %s, err: %w", nspace, err)
				return
			}
		}

		return
	}
}
