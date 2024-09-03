// Package PII offers tools to deal with
// Personal Identified Information in struct-field level
package pii

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	Encrypt(ctx context.Context, structPts ...any) error

	// Decrypt decrypts Personal data fields of the given structs pointers.
	// It does its best to ensure in case of multiple structs pointers.
	// It ensures idempotency and only decrypts fields once.
	//
	// It replaces the field value with a replacement message, defined in the tag,
	// if the subject is forgotten. Otherwise, the field will be kept empty.
	Decrypt(ctx context.Context, structPts ...any) error

	// Forget removes the associated encryption materials of the given subject,
	// and crypto-erases its Personal data.
	Forget(ctx context.Context, subID string) error

	// Recover allows to recover encryption materials of the given subject.
	//
	// It fails if the grace period was exceeded, and encryption materials were hard deleted.
	Recover(ctx context.Context, subID string) error

	// Clear clears encryption materials' cache based on cache-related configuration.
	Clear(ctx context.Context, force bool) error

	core.TokenEngine
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

	// GracefulMode allows first to disable the encryption materials during a graceful period.
	// Therefore recovery may succeed. Otherwise, encryption materials are immediately deleted.
	GracefulMode bool

	// TokenEngine is an implementation of core.TokenEngine
	TokenEngine core.TokenEngine
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
// By default, Cache and Graceful mode options are enabled and 'AES 256 GCM' encrypter is used.
func NewProtector(namespace string, engine core.KeyEngine, opts ...func(*ProtectorConfig)) Protector {
	if namespace == "" {
		namespace = "default"
	}

	p := &protector{
		namespace: namespace,
		ProtectorConfig: &ProtectorConfig{
			Encrypter:    aes.New256GCMEncrypter(),
			Engine:       engine,
			CacheEnabled: true,
			GracefulMode: true,
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

func (p *protector) Encrypt(ctx context.Context, structPtrs ...any) (err error) {
	if err := p.encrypt(ctx, structPtrs); err != nil {
		return err
	}

	return nil
}

func (p *protector) encrypt(ctx context.Context, structPtrs []any) (err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	structs := make([]piiStruct, 0)
	subjectIDs := make([]string, 0)
	for _, strPtr := range structPtrs {
		strPtr := strPtr
		piiStruct, err := scan(strPtr, func(sc *scanConfig) {
			sc.requireSubject = true
		})
		if err != nil {
			return err
		}

		if piiStruct.typ.hasPII {
			structs = append(structs, piiStruct)
			subjectIDs = append(subjectIDs, piiStruct.subjectID())
		}
	}
	if len(structs) == 0 {
		return nil
	}

	slices.Sort(subjectIDs)
	subjectIDs = slices.Compact(subjectIDs)

	keys, err := p.Engine.GetOrCreateKeys(ctx, p.namespace, subjectIDs, p.Encrypter.KeyGen())
	if err != nil {
		return err
	}

	fn := func(rf ReplaceField, val string) (newVal string, err error) {
		key, ok := keys[rf.SubjectID]
		if !ok {
			err = ErrSubjectForgotten.withSubject(rf.SubjectID)
			return
		}
		// idempotency: no need to re-encrypt field value if it's packed
		// packed implies already encrypted (unless a corruption occurred)
		if isPackedPII(val) {
			newVal = val
			return
		}

		encVal, err := p.Encrypter.Encrypt(p.namespace, key, val)
		if err != nil {
			return
		}
		newVal = packPII(encVal)
		return
	}

	for idx, s := range structs {
		if err = s.replace(fn); err != nil {
			err = fmt.Errorf("%w at #%d", err, idx)
			return
		}
	}
	return
}

func (p *protector) Decrypt(ctx context.Context, values ...any) (err error) {
	if err := p.decrypt(ctx, values); err != nil {
		return err
	}
	return nil
}

func (p *protector) decrypt(ctx context.Context, structPtrs []any) (err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.withBase(err).withNamespace(p.namespace)
		}
	}()

	structs := make([]piiStruct, 0)
	subjectIDs := make([]string, 0)
	for _, strPtr := range structPtrs {
		strPtr := strPtr
		piiStruct, err := scan(strPtr, func(sc *scanConfig) {
			sc.requireSubject = true
		})
		if err != nil {
			return err
		}
		if piiStruct.typ.hasPII {
			structs = append(structs, piiStruct)
			subjectIDs = append(subjectIDs, piiStruct.subID)
		}
	}
	if len(structs) == 0 {
		return nil
	}

	slices.Sort(subjectIDs)
	subjectIDs = slices.Compact(subjectIDs)

	keys, err := p.Engine.GetKeys(ctx, p.namespace, subjectIDs)
	if err != nil {
		return
	}

	fn := func(rf ReplaceField, val string) (newVal string, err error) {
		key, ok := keys[rf.SubjectID]
		if !ok {
			newVal = rf.Replacement
			return
		}
		// idempotency: no need to re-encrypt field value if it's packed
		// packed implies already encrypted (unless a corruption occurred)
		if !isPackedPII(val) {
			newVal = val
			return
		}

		newVal, err = p.Encrypter.Decrypt(p.namespace, key, unpackPII(val))
		if err != nil {
			return "", err
		}
		return
	}

	for idx, s := range structs {

		if err = s.replace(fn); err != nil {
			err = fmt.Errorf("%w at #%d", err, idx)
			return
		}
	}

	return
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

	if p.GracefulMode {
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

// Detokenize implements Protector.
func (p *protector) Detokenize(ctx context.Context, namespace string, tokens []string) (core.TokenValueMap, error) {
	if p.TokenEngine == nil {
		panic("unsupported action. token engine not found")
	}
	return p.TokenEngine.Detokenize(ctx, namespace, tokens)
}

// Tokenize implements Protector.
func (p *protector) Tokenize(ctx context.Context, namespace string, values []core.TokenData, opts ...func(*core.TokenizeConfig)) (core.ValueTokenMap, error) {
	if p.TokenEngine == nil {
		panic("unsupported action. token engine not found")
	}
	return p.TokenEngine.Tokenize(ctx, namespace, values)
}

func (p *protector) DeleteToken(ctx context.Context, namespace string, token string) error {
	if p.TokenEngine == nil {
		panic("unsupported action. token engine not found")
	}
	return p.TokenEngine.DeleteToken(ctx, namespace, token)
}
