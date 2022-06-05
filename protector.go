// Package pii offers a set of tools to deal with
// Personal Identified Information in struct-field level
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
	// add support for attrs?
	// packReg = regexp.MustCompile(
	// 	`<pii:(.*):(.+)`,
	// )

	packPrefix = "<pii::"
)

// isPackedPII checks if the given text is prefixed by a tag.
// Internally we only pack already encrypted personal data.
// The func serves as workaround to distinguish between encrypted and plain text PII
func isPackedPII(cipher string) bool {
	return strings.HasPrefix(cipher, packPrefix) && len(cipher) > len(packPrefix)
}

func packPII(cipher string) string {
	if isPackedPII(cipher) {
		return cipher
	}
	return packPrefix + cipher
}

func unpackPII(cipher string) string {
	if !isPackedPII(cipher) {
		return ""
	}
	return cipher[len(packPrefix):]
}

var (
	// ErrEncryptDecryptFailure = errors.New("failed to encrypt or decrypt")
	// ErrForgetSubjectFailure  = errors.New("failed to forget subject")
	// ErrRecoverSubjectFailure = errors.New("failed to recover subject")
	// ErrUnableRecoverSubject  = errors.New("unable to recover subject")
	// ErrSubjectForgotten      = errors.New("subject is forgotten")

	ErrEncryptDecryptFailure = newErr("failed to encrypt/decrypt")
	ErrForgetSubjectFailure  = newErr("failed to forget subject")
	ErrRecoverSubjectFailure = newErr("failed to recover subject")
	ErrClearCacheFailure     = newErr("failed to clear cache")
	ErrUnableRecoverSubject  = newErr("unable to recover subject")
	ErrSubjectForgotten      = newErr("subject is forgotten")
)

// Protector presents the interface of the service that encrypt,
// decrypt and crypto-erase subject's Personal data.
type Protector interface {
	Encrypt(ctx context.Context, structPts ...interface{}) error
	Decrypt(ctx context.Context, structPts ...interface{}) error
	Forget(ctx context.Context, subID string) error
	Recover(ctx context.Context, subID string) error
	Clear(ctx context.Context, force bool) error
	// LastActiveAt() time.Time
}

// ProtectorConfig presents Protector service configuration
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

// NewProtector returns a Protector service instance.
// It requires a namespace for the service, and accepts options to overwrite the default configuration.
//
// Options must fulfill protector the core.KeyEngine dependency. Otherwise, the function may panic.
//
// By default, Cache and Gracefull mode options are enabled.
func NewProtector(namespace string, engine core.KeyEngine, opts ...func(*ProtectorConfig)) Protector {
	if namespace == "" {
		namespace = "default"
	}

	p := &protector{
		namespace: namespace,
		ProtectorConfig: &ProtectorConfig{
			Encrypter:     aes.New256GCMEncrypter(),
			Engine:        engine,
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

	if p.Engine == nil {
		panic("invalid Key Engine service, nil value found")
	}

	if p.CacheEnabled {
		if _, ok := p.Engine.(core.KeyEngineCache); !ok {
			p.Engine = memory.NewCacheWrapper(p.Engine, p.CacheTTL)
		}
	}

	return p
}

// bufferToFieldFunc is a helper func used by Encrypt & Decrypt methods
// to ensure atomicity in case of bulk ops.
func bufferToFieldFunc(buffer map[int]string) func(fieldIdx int, val string) (string, error) {
	return func(fieldIdx int, val string) (string, error) {
		if _, ok := buffer[fieldIdx]; !ok {
			return val, nil
		}
		return buffer[fieldIdx], nil
	}
}

// Encrypt implements Protector
func (p *protector) Encrypt(ctx context.Context, structPtrs ...interface{}) (err error) {

	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	structs, err := scan(structPtrs...)
	if err != nil {
		return err
	}
	if len(structs) == 0 {
		return nil
	}

	keys, err := p.Engine.GetOrCreateKeys(ctx, p.namespace, structs.subjectIDs(), p.Encrypter.KeyGen())
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
				err = ErrSubjectForgotten.withSubject(s.subjectID())
				return
			}
			// idempotency: no need to re-encrypt field value if it's packed
			// packed implies already encrypted (unless a corruption occurred)
			if isPackedPII(val) {
				buffer[structIdx][fieldIdx] = val
				return
			}

			encVal, err := p.Encrypter.Encrypt(p.namespace, key, val)
			if err != nil {
				return
			}
			buffer[structIdx][fieldIdx] = packPII(encVal)
			return
		}

		if err = s.replace(fn); err != nil {
			return fmt.Errorf("%w at #%d", err, structIdx)
		}
	}

	// once all PII data are encrypted & pushed to buffer
	// iterate a second time to replace field values for real
	for structIdx, s := range structs {
		if err = s.replace(bufferToFieldFunc(buffer[structIdx])); err != nil {
			err = fmt.Errorf("%w at #%d", err, structIdx)
			return
		}
	}

	return
}

// Encrypt implements Protector
func (p *protector) Decrypt(ctx context.Context, values ...interface{}) (err error) {

	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.withBase(err).withNamespace(p.namespace)
		}
	}()

	structs, err := scan(values...)
	if err != nil {
		return
	}

	if len(structs) == 0 {
		return nil
	}

	keys, err := p.Engine.GetKeys(ctx, p.namespace, structs.subjectIDs()...)
	if err != nil {
		return
	}

	buffer := make(map[int]map[int]string)

	for structIdx, s := range structs {
		buffer[structIdx] = make(map[int]string)

		fn := func(fieldIdx int, val string) (newVal string, err error) {
			// always return the current field value
			defer func() {
				newVal = val
			}()

			// in contrast to encrypt logic, no need to return an error
			// if subject is not found, replace PII with relacement message from tag config.
			key, ok := keys[s.subjectID()]
			if !ok {
				buffer[structIdx][fieldIdx] = s.replacements[fieldIdx]
			} else {
				// make sure not to decrypt a plain text value
				// unpacked implies decrypted...YOLO
				if !isPackedPII(val) {
					buffer[structIdx][fieldIdx] = val
					return
				}

				plainVal, err := p.Encrypter.Decrypt(p.namespace, key, unpackPII(val))
				if err != nil {
					return "", err
				}
				buffer[structIdx][fieldIdx] = plainVal
			}

			return
		}
		if err = s.replace(fn); err != nil {
			err = fmt.Errorf("%w at #%d", err, structIdx)
			return
		}
	}

	for structIdx, s := range structs {
		if err = s.replace(bufferToFieldFunc(buffer[structIdx])); err != nil {
			err = fmt.Errorf("%w at #%d", err, structIdx)
			return
		}
	}
	return nil
}

// Encrypt implements Protector
func (p *protector) Forget(ctx context.Context, subID string) (err error) {

	defer func() {
		if err != nil {
			err = ErrForgetSubjectFailure.
				withBase(err).
				withNamespace(p.namespace).
				withSubject(subID)
		}
	}()

	if p.GracefullMode {
		err = p.Engine.DisableKey(ctx, p.namespace, subID)
		return
	}

	err = p.Engine.DeleteKey(ctx, p.namespace, subID)
	return
}

// Encrypt implements Protector
func (p *protector) Recover(ctx context.Context, subID string) (err error) {

	defer func() {
		if err != nil {
			if errors.Is(err, core.ErrKeyNotFound) {
				err = ErrUnableRecoverSubject.
					withBase(err).
					withNamespace(p.namespace).
					withSubject(subID)
			} else {
				err = ErrRecoverSubjectFailure.
					withBase(err).
					withNamespace(p.namespace).
					withSubject(subID)
			}

		}
	}()

	err = p.Engine.RenableKey(ctx, p.namespace, subID)
	return
}

// Encrypt implements Protector
func (p *protector) Clear(ctx context.Context, force bool) (err error) {
	defer func() {
		if err != nil {
			err = ErrClearCacheFailure.
				withBase(err).
				withNamespace(p.namespace).
				withSubject(p.namespace)
		}
	}()

	if cp, ok := p.Engine.(core.KeyEngineCache); ok {
		err = cp.ClearCache(ctx, p.namespace, force)
		return
	}

	return
}
