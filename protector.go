package pii

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ln80/pii/aes"
	"github.com/ln80/pii/core"
	"github.com/ln80/pii/memory"
)

var (
	ErrFailedToEncryptDecryptStructField = errors.New("failed to encrypt/decrypt struct field")
	ErrFailedToForgetSubject             = errors.New("failed to forget subject")
	ErrFailedToRecoverSubject            = errors.New("failed to recover subject")
	ErrSubjectForgotten                  = errors.New("subject is likely forgotten")
)

type Protector interface {
	Encrypt(ctx context.Context, structPts ...interface{}) error
	Decrypt(ctx context.Context, structPts ...interface{}) error
	Forget(ctx context.Context, subID string) error
	Recover(ctx context.Context, subID string) error
	Clear(ctx context.Context, force bool) error
}

type ProtectorConfig struct {
	Engine        core.KeyEngine
	Encrypter     core.Encrypter
	CacheEnabled  bool
	CacheTTL      time.Duration
	GracefullMode bool
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
			Engine:        memory.NewKeyEngine(),
			Encrypter:     aes.New256GCMEncrypter(),
			CacheEnabled:  true,
			GracefullMode: true,
		},
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(p.ProtectorConfig)
	}

	if p.CacheEnabled {
		if _, ok := p.Engine.(core.KeyCacheEngine); !ok {
			p.Engine = memory.NewCacheWrapper(p.Engine, p.CacheTTL)
		}
	}

	return p
}

func (p *protector) Encrypt(ctx context.Context, structPtrs ...interface{}) error {
	structs, err := scan(structPtrs...)
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

	for idx, s := range structs {
		fn := func(i int, input string) (string, error) {
			key, ok := keys[s.subjectID()]
			if !ok {
				return "", ErrSubjectForgotten
			}
			return p.Encrypter.Encrypt(key, input)
		}
		if err := s.replace(fn); err != nil {
			return fmt.Errorf("%w: at #%d", err, idx)
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

	for idx, ps := range structs {
		fn := func(i int, input string) (string, error) {
			key, ok := keys[ps.subjectID()]
			if !ok {
				return ps.replacements[i], nil
			}
			return p.Encrypter.Decrypt(key, input)
		}
		if err := ps.replace(fn); err != nil {
			return fmt.Errorf("%w: at #%d", err, idx)
		}
	}
	return nil
}

func (p *protector) Forget(ctx context.Context, subID string) (err error) {
	// defers are LIFO
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: subject: %s, details: %v", ErrFailedToForgetSubject, subID, err)
		}
	}()

	// defer func() {
	// 	if errors.Is(err, core.ErrUnsupportedKeyOperation) {
	// 		err = p.Engine.DeleteKey(ctx, p.namespace, subID)
	// 	}
	// }()

	if p.GracefullMode {
		return p.Engine.DisableKey(ctx, p.namespace, subID)
	}

	return p.Engine.DeleteKey(ctx, p.namespace, subID)
}

func (p *protector) Recover(ctx context.Context, subID string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %s, details: %v", ErrFailedToRecoverSubject, subID, err)
		}
	}()
	return p.Engine.RenableKey(ctx, p.namespace, subID)
}

func (p *protector) Clear(ctx context.Context, force bool) error {
	if cp, ok := p.Engine.(core.KeyCacheEngine); ok {
		// log.Println("protector has cache", ok, p.CacheEnabled)
		return cp.ClearCache(ctx, p.namespace, force)
	}

	return nil
}
