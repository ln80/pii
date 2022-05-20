package kms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ln80/pii/core"
)

func encryptContext(namespace string) map[string]string {
	return map[string]string{"namespace": namespace}
}

type engine struct {
	store core.KeyEngine

	kmsResolver KMSKeyResolver

	kmsvc Client
}

var _ core.KeyEngine = &engine{}
var _ core.KeyRotatorEngine = &engine{}

func NewKMSWrapper(kmsvc Client, resolver KMSKeyResolver, store core.KeyEngine) core.KeyEngine {
	if kmsvc == nil {
		panic("invalid KMS client service, nil value found")
	}
	if store == nil {
		panic("invalid Key Engine store, nil value found")
	}
	if resolver == nil {
		panic("invalid KMSKey resolver, nil value found")
	}

	return &engine{
		kmsvc:       kmsvc,
		kmsResolver: resolver,
		store:       store,
	}
}

func (e *engine) decryptDataKey(ctx context.Context, kmsKey string, encKey core.Key, encCtx map[string]string) (string, error) {
	out, err := e.kmsvc.Decrypt(ctx, &kms.DecryptInput{
		KeyId:             aws.String(kmsKey),
		CiphertextBlob:    []byte(encKey),
		EncryptionContext: encCtx,
	})
	if err != nil {
		return "", err
	}

	return string(out.Plaintext), nil
}

func (e *engine) GetKeys(ctx context.Context, namespace string, subIDs ...string) (core.KeyMap, error) {
	encKeys, err := e.store.GetKeys(ctx, namespace, subIDs...)
	if err != nil {
		return nil, err
	}

	if len(encKeys) == 0 {
		return nil, nil
	}

	encCtx := encryptContext(namespace)

	keys := core.NewKeyMap()
	for subID, k := range encKeys {
		kmsKey, err := e.kmsResolver.KeyOf(ctx, namespace, subID)
		if err != nil {
			return nil, err
		}
		pleinTxtkey, err := e.decryptDataKey(ctx, kmsKey, k, encCtx)
		if err != nil {
			return nil, err
		}
		keys[subID] = core.Key(pleinTxtkey)
	}

	return keys, nil
}

func (e *engine) GetOrCreateKeys(ctx context.Context, namespace string, subIDs []string, fallbackGen core.KeyGen) (core.KeyMap, error) {
	encCtx := encryptContext(namespace)
	newKeys := make(map[string]string)

	keyGen := func(ctx context.Context, namespace, subID string) (string, error) {
		kmsKey, err := e.kmsResolver.KeyOf(ctx, namespace, subID)
		if err != nil {
			return "", err
		}
		out, err := e.kmsvc.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
			KeyId:             aws.String(kmsKey),
			EncryptionContext: encCtx,
			NumberOfBytes:     aws.Int32(32),
		})
		if err != nil {
			return "", err
		}

		newKeys[subID] = string(out.Plaintext)

		return string(out.CiphertextBlob), nil
	}

	keys, err := e.store.GetOrCreateKeys(ctx, namespace, subIDs, keyGen)
	if err != nil {
		return nil, err
	}

	for subID, k := range keys {
		if nk, ok := newKeys[subID]; ok {
			keys[subID] = core.Key(nk)
		} else {
			kmsKey, err := e.kmsResolver.KeyOf(ctx, namespace, subID)
			if err != nil {
				return nil, err
			}
			pleinTxtkey, err := e.decryptDataKey(ctx, kmsKey, k, encCtx)
			if err != nil {
				return nil, err
			}
			keys[subID] = core.Key(pleinTxtkey)
		}
	}

	return keys, nil
}

func (e *engine) DisableKey(ctx context.Context, namespace, subID string) error {
	return e.store.DisableKey(ctx, namespace, subID)
}

func (e *engine) DeleteKey(ctx context.Context, namespace, subID string) error {
	return e.store.DeleteKey(ctx, namespace, subID)
}

func (e *engine) RotateKeys(ctx context.Context, namespace, subIDs string) error {
	if _, ok := e.store.(core.KeyUpdaterEngine); !ok {
		return fmt.Errorf(
			"%w: KMS engine failed to rotate keys, store does not support update keys op",
			core.ErrUnsupportedKeyOperation)
	}

	keys, err := e.store.GetKeys(ctx, namespace, subIDs)
	if err != nil {
		return err
	}

	updatedKeys := []core.IDKey{}
	for subID, key := range keys {
		ok, new, old, err := e.kmsResolver.HasNewKey(ctx, namespace, subID)
		if err != nil {
			return err
		}
		if ok {
			out, err := e.kmsvc.ReEncrypt(ctx, &kms.ReEncryptInput{
				CiphertextBlob:               []byte(key),
				DestinationKeyId:             aws.String(new),
				SourceKeyId:                  aws.String(old),
				SourceEncryptionContext:      encryptContext(namespace),
				DestinationEncryptionContext: encryptContext(namespace),
			})
			if err != nil {
				return err
			}
			updatedKeys = append(updatedKeys, core.NewIDKey(subID, string(out.CiphertextBlob)))
		}
	}

	return e.store.(core.KeyUpdaterEngine).UpdateKeys(ctx, namespace, updatedKeys)
}
