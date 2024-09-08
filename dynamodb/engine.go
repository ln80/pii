package dynamodb

import (
	"github.com/ln80/pii/core"
)

// Const
const (
	nsHashKeyVal = "#ns_"

	hashKey  = "_pk"
	rangeKey = "_sk"

	lsi    = "_lsi"
	lsiKey = "_lsik"

	attrKeyID      = "_kid"
	attrKey        = "_key"
	attrNamespace  = "_nspace"
	attrDisabledAt = "_disabledAt"
	attrDeletedAt  = "_deletedAt"
	attrEnabledAt  = "_enabledAt"
	attrState      = "_state"

	attrToken      = "_tkn"
	attrTokenValue = "_tknv"
)

// KeyEngineConfig is an alias to core.KeyEngineConfig type defined in the core package.
// It may change later to extend the core one.
type EngineConfig struct {
	core.KeyEngineConfig
}

type Engine struct {
	svc   ClientAPI
	table string

	*EngineConfig
}

// NewEngine returns a core.KeyEngine implementation built on top of a Dynamodb table.
//
// It requires a non-empty value for Dynamodb client service and table name parameters. Otherwise, it will panic.
func NewEngine(svc ClientAPI, table string, opts ...func(ec *EngineConfig)) *Engine {
	if svc == nil {
		panic("invalid Dynamodb client service, nil value found")
	}
	if table == "" {
		panic("invalid dynamodb table name, empty value found")
	}

	defaultCfg := EngineConfig{KeyEngineConfig: core.NewKeyEngineConfig()}
	eng := &Engine{
		svc:          svc,
		table:        table,
		EngineConfig: &defaultCfg,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(eng.EngineConfig)
	}

	return eng
}
