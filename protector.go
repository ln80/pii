package pii

import (
	"context"
	"errors"

	"github.com/ln80/pii/aes"
	"github.com/ln80/pii/core"
	"github.com/ln80/pii/memory"
)

type Protector interface {
	Encrypt(ctx context.Context, structPts ...interface{}) error
	Decrypt(ctx context.Context, structPts ...interface{}) error
	Forget(ctx context.Context, subID string) error
	Recover(ctx context.Context, subID string) error
	Clear(ctx context.Context, force bool) error
}

type ProtectorConfig struct {
	Engine       core.KeyEngine
	Encrypter    core.Encrypter
	CacheEnabled bool
	CacheTTL     int64
}

type protector struct {
	namespace string

	*ProtectorConfig
}

var _ Protector = &protector{}

func NewProtector(namespace string, opts ...func(*ProtectorConfig)) Protector {
	p := &protector{
		namespace: namespace,
		ProtectorConfig: &ProtectorConfig{
			Engine:       memory.NewKeyEngine(),
			Encrypter:    aes.New256CBCEncrypter(),
			CacheEnabled: true,
		},
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(p.ProtectorConfig)
	}

	if p.CacheEnabled {
		// TODO make sure that engine is not already a cache wrapper
		p.Engine = memory.NewCacheWrapper(p.Engine, p.CacheTTL)
	}

	return p
}

func (p *protector) Encrypt(ctx context.Context, values ...interface{}) error {
	structs, err := scan(values...)
	if err != nil {
		return err
	}
	if len(structs) == 0 {
		return nil
	}

	keys, err := p.Engine.GetOrCreateKeys(ctx, p.namespace, structs.subjectIDs(), nil)
	if err != nil {
		return err
	}

	for _, s := range structs {
		key := keys[s.subjectID()]
		if err := s.replace(func(i int, input string) (string, error) {
			return p.Encrypter.Encrypt(key, input)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (p *protector) Decrypt(ctx context.Context, values ...interface{}) error {
	structs, err := scan(values...)
	if err != nil {
		return err
	}

	if len(structs) == 0 {
		return nil
	}

	keys, err := p.Engine.GetKeys(ctx, p.namespace, structs.subjectIDs()...)
	if err != nil {
		return err
	}

	for _, ps := range structs {
		if err := ps.replace(func(i int, input string) (string, error) {
			key, ok := keys[ps.subjectID()]
			if ok {
				return p.Encrypter.Decrypt(key, input)
			}
			return ps.replacements[i], nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (p *protector) Forget(ctx context.Context, subID string) (err error) {
	defer func() {
		if errors.Is(err, core.ErrUnsupportedKeyOperation) {
			err = p.Engine.DeleteKey(ctx, p.namespace, subID)
		}
	}()

	return p.Engine.DisableKey(ctx, p.namespace, subID)
}

func (p *protector) Recover(ctx context.Context, subID string) error {
	return nil
}

func (p *protector) Clear(ctx context.Context, force bool) error {
	if cp, ok := p.Engine.(core.KeyCacheEngine); ok {
		// log.Println("protector has cache", ok, p.CacheEnabled)
		return cp.Clear(ctx, p.namespace, force)
	}

	return nil
}
