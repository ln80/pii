package kms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ln80/pii/core"
)

func encryptContext(namespace string) map[string]string {
	return map[string]string{"namespace": namespace}
}

type engine struct {
	origin core.KeyEngine

	kmsResolver KMSKeyResolver

	kmsvc ClientAPI
}

var _ core.KeyEngineWrapper = &engine{}

// var _ core.KeyRotatorEngine = &engine{}

// NewKMSWrapper allows to perform Envelope encryption.
// In this case, origin engine keys are considered "Data keys" and KMS ones are the "Masters".
// KMSWrapper will ensure rotation at the master key level. Thus, KMS keys will be associated to a limited amount of datakeys
// which limit the capabilities of cryptanalysis based attacks.
// Somehow using KMSWrapper on top of the original engine lighten security requirements of the later which can be a regular database
// the same used for the rest of the application data.
// Using a cacheWrapper on top of KMSWrapper may significantly reduce costs related to the later in exchange of
// some risks i.e plain text data keys may be kept longer in memory.
func NewKMSWrapper(kmsvc ClientAPI, resolver KMSKeyResolver, origin core.KeyEngine) core.KeyEngine {
	if kmsvc == nil {
		panic("invalid KMS client service, nil value found")
	}
	if origin == nil {
		panic("invalid origin Key Engine, nil value found")
	}
	if resolver == nil {
		panic("invalid KMSKey resolver, nil value found")
	}

	return &engine{
		kmsvc:       kmsvc,
		kmsResolver: resolver,
		origin:      origin,
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

func (e *engine) GetKeys(ctx context.Context, namespace string, keyIDs ...string) (core.KeyMap, error) {
	var encKeys core.KeyMap
	encKeys, err := e.origin.GetKeys(ctx, namespace, keyIDs...)
	if err != nil {
		return nil, err
	}

	keys := core.NewKeyMap()

	if len(encKeys) == 0 {
		return keys, nil
	}

	encCtx := encryptContext(namespace)

	for keyID, k := range encKeys {
		kmsKey, err := e.kmsResolver.KeyOf(ctx, namespace, keyID)
		if err != nil {
			return nil, err
		}
		pleinTxtkey, err := e.decryptDataKey(ctx, kmsKey, k, encCtx)
		if err != nil {
			return nil, err
		}
		keys[keyID] = core.Key(pleinTxtkey)
	}

	return keys, nil
}

func (e *engine) GetOrCreateKeys(ctx context.Context, namespace string, keyIDs []string, fallbackGen core.KeyGen) (core.KeyMap, error) {
	encCtx := encryptContext(namespace)
	newKeys := make(map[string]string)

	keyGen := func(ctx context.Context, namespace, keyID string) (string, error) {
		kmsKey, err := e.kmsResolver.KeyOf(ctx, namespace, keyID)
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

		newKeys[keyID] = string(out.Plaintext)

		return string(out.CiphertextBlob), nil
	}

	keys, err := e.origin.GetOrCreateKeys(ctx, namespace, keyIDs, keyGen)
	if err != nil {
		return nil, err
	}

	for keyID, k := range keys {
		if nk, ok := newKeys[keyID]; ok {
			keys[keyID] = core.Key(nk)
		} else {
			kmsKey, err := e.kmsResolver.KeyOf(ctx, namespace, keyID)
			if err != nil {
				return nil, err
			}
			pleinTxtkey, err := e.decryptDataKey(ctx, kmsKey, k, encCtx)
			if err != nil {
				return nil, err
			}
			keys[keyID] = core.Key(pleinTxtkey)
		}
	}

	return keys, nil
}

func (e *engine) DisableKey(ctx context.Context, namespace, keyID string) error {
	return e.origin.DisableKey(ctx, namespace, keyID)
}

func (e *engine) RenableKey(ctx context.Context, namespace, keyID string) error {
	return e.origin.RenableKey(ctx, namespace, keyID)
}

func (e *engine) DeleteKey(ctx context.Context, namespace, keyID string) error {
	return e.origin.DeleteKey(ctx, namespace, keyID)
}

// Origin implements core.KeyRotatorEngine
func (e *engine) Origin() core.KeyEngine {
	return e.origin
}

// func (e *engine) RotateKeys(ctx context.Context, namespace, keyIDs string) error {
// 	keys, err := e.origin.GetKeys(ctx, namespace, keyIDs)
// 	if err != nil {
// 		return err
// 	}

// 	updatedKeys := []core.IDKey{}
// 	for keyID, key := range keys {
// 		ok, new, old, err := e.kmsResolver.HasNewKey(ctx, namespace, keyID)
// 		if err != nil {
// 			return err
// 		}
// 		if ok {
// 			out, err := e.kmsvc.ReEncrypt(ctx, &kms.ReEncryptInput{
// 				CiphertextBlob:               []byte(key),
// 				DestinationKeyId:             aws.String(new),
// 				SourceKeyId:                  aws.String(old),
// 				SourceEncryptionContext:      encryptContext(namespace),
// 				DestinationEncryptionContext: encryptContext(namespace),
// 			})
// 			if err != nil {
// 				return err
// 			}
// 			updatedKeys = append(updatedKeys, core.NewIDKey(keyID, string(out.CiphertextBlob)))
// 		}
// 	}

// 	return e.origin.UpdateKeys(ctx, namespace, updatedKeys)
// }
