package pii

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ln80/pii/aes"
	"github.com/ln80/pii/core"
	"github.com/ln80/pii/memory"
)

var (
	// maybe add mask value as attr of pii identifier tag
	// piiCypherReg = regexp.MustCompile(
	// 	`<pii (\w+) ::> (.+)`,
	// )

	piiCypherIdentifier = "<pii::>"
)

func isEncryptedPII(cypher string) bool {
	return strings.HasPrefix(cypher, piiCypherIdentifier) && len(cypher) > len(piiCypherIdentifier)
}

func packEncryptedPII(cypher string) string {
	if isEncryptedPII(cypher) {
		return cypher
	}

	return piiCypherIdentifier + cypher
}

func unpackEncryptedPII(cypher string) string {
	if !isEncryptedPII(cypher) {
		return ""
	}

	return cypher[len(piiCypherIdentifier):]
}

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
		if _, ok := p.Engine.(core.KeyEngineCache); !ok {
			p.Engine = memory.NewCacheWrapper(p.Engine, p.CacheTTL)
		}
	}

	return p
}

func bufferToFieldFunc(buffer map[int]string) func(fieldIdx int, val string) (string, error) {
	return func(fieldIdx int, val string) (string, error) {
		if _, ok := buffer[fieldIdx]; !ok {
			return val, nil
		}
		return buffer[fieldIdx], nil
	}
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

	// two steps process to ensure atomicity
	buffer := make(map[int]map[int]string)

	// first iteration over PII data performs a fake replacement:
	// only to catch, encrypt and push field values to buffer
	for structIdx, s := range structs {
		buffer[structIdx] = make(map[int]string)
		fn := func(fieldIdx int, val string) (newVal string, err error) {
			// always return the current field value
			defer func() {
				newVal = val
			}()

			key, ok := keys[s.subjectID()]
			if !ok {
				err = ErrSubjectForgotten
				return
			}
			// idempotency: no need to re-encrypt field value if is already encrypted
			if isEncryptedPII(val) {
				buffer[structIdx][fieldIdx] = val
				return
			}

			encVal, err := p.Encrypter.Encrypt(key, val)
			if err != nil {
				return
			}
			buffer[structIdx][fieldIdx] = packEncryptedPII(encVal)
			return
		}

		if err := s.replace(fn); err != nil {
			return fmt.Errorf("%w: at #%d", err, structIdx)
		}
	}

	// once all PII data are encrypted & pushed to buffer
	// iterate a second time to replace field values for real
	for structIdx, s := range structs {
		if err := s.replace(bufferToFieldFunc(buffer[structIdx])); err != nil {
			return fmt.Errorf("%w: at #%d", err, structIdx)
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

	buffer := make(map[int]map[int]string)

	for structIdx, s := range structs {
		buffer[structIdx] = make(map[int]string)

		fn := func(fieldIdx int, val string) (newVal string, err error) {
			// always return the current field value
			defer func() {
				newVal = val
			}()

			key, ok := keys[s.subjectID()]
			if !ok {
				buffer[structIdx][fieldIdx] = s.replacements[fieldIdx]
			} else {
				// make sure not to try decrypt a plain text value
				if !isEncryptedPII(val) {
					buffer[structIdx][fieldIdx] = val
					return
				}

				val = unpackEncryptedPII(val)
				plainVal, err := p.Encrypter.Decrypt(key, val)
				if err != nil {
					return "", err
				}
				buffer[structIdx][fieldIdx] = plainVal
			}

			return
		}
		if err := s.replace(fn); err != nil {
			return fmt.Errorf("%w: at #%d", err, structIdx)
		}
	}

	for structIdx, s := range structs {
		if err := s.replace(bufferToFieldFunc(buffer[structIdx])); err != nil {
			return fmt.Errorf("%w: at #%d", err, structIdx)
		}
	}
	return nil
}

func (p *protector) Forget(ctx context.Context, subID string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: subject: %s, details: %v", ErrFailedToForgetSubject, subID, err)
		}
	}()

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
	if cp, ok := p.Engine.(core.KeyEngineCache); ok {
		return cp.ClearCache(ctx, p.namespace, force)
	}

	return nil
}
