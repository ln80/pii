// Package PII offers tools to deal with
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

// Errors returned by Protector service
var (
	ErrEncryptDecryptFailure = newErr("failed to encrypt/decrypt")
	ErrForgetSubjectFailure  = newErr("failed to forget subject")
	ErrRecoverSubjectFailure = newErr("failed to recover subject")
	ErrClearCacheFailure     = newErr("failed to clear cache")
	ErrCannotRecoverSubject  = newErr("cannot recover subject")
	ErrSubjectForgotten      = newErr("subject is forgotten")
)

// Protector presents the service's interface that encrypts, decrypts,
// and crypto-erases subjects' Personal data.
type Protector interface {

	// Encrypt encrypts Personal data fields of the given structs pointers.
	// It does its best to ensure atomicity in case of multiple structs pointers.
	// It ensures idempotency and only encrypts fields once.
	Encrypt(ctx context.Context, structPts ...interface{}) error

	// Decrypt decrypts Personal data fields of the given structs pointers.
	// It does its best to ensure in case of multiple structs pointers.
	// It ensures idempotency and only decrypts fields once.
	//
	// It replaces the field value with a replacement message, defined in the tag,
	// if the subject is forgotten. Otherwise, the field will be kept empty.
	Decrypt(ctx context.Context, structPts ...interface{}) error

	// Forget removes the associated encryption materials of the given subject,
	// and crypto-erases its Personal data.
	Forget(ctx context.Context, subID string) error

	// Recover allows to recover encryption materials of the given subject.
	// It will fail if the grace period was exceeded, and encryption materials were hard deleted.
	Recover(ctx context.Context, subID string) error

	// Clear clears encryption materials' cache based on cache-related configuration.
	Clear(ctx context.Context, force bool) error
}

// ProtectorConfig presents the configuration of Protector service
type ProtectorConfig struct {

	// Engine presents an implementation of core.KeyEngine.
	// It manages encryption materials' life-cycle.
	Engine core.KeyEngine

	// Encrypter presents an implementation of core.Encrypter.
	// It allows using a specific encryption algorithm.
	Encrypter core.Encrypter

	// CacheEnabled used to enable/disable cache.
	CacheEnabled bool

	// CacheTTL defines the cache's time to live duration.
	CacheTTL time.Duration

	// GracefullMode allows first to disable the encryption materials during a graceful period.
	// Therefore recovery may succeed. Otherwise, encryption materials are immediately deleted.
	GracefullMode bool
}

type protector struct {
	namespace string

	*ProtectorConfig
}

var _ Protector = &protector{}

// NewProtector returns a Protector service instance.
// It requires a Key engine and accepts options to overwrite the default configuration.
//
// It panics if the given engine is nil.
// It uses a default namespace if the given namespace is empty.
//
// By default, Cache and Gracefull mode options are enabled and 'AES 256 GCM' encrypter is used.
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

// bufferToFieldFunc is a helper function used by Encrypt & Decrypt methods
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

	keys, err := p.Engine.GetKeys(ctx, p.namespace, structs.subjectIDs())
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
				err = ErrCannotRecoverSubject.
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
