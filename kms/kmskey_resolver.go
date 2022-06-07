package kms

import "context"

// KMSKeyResolver allows to map a namespace or subject to a KMS Key.
type KMSKeyResolver interface {
	KeyOf(ctx context.Context, namespace, subID string) (kmsKey string, err error)
}

type staticKMSKeyResolver struct{ key string }

var _ KMSKeyResolver = &staticKMSKeyResolver{}

// NewStaticKMSKeyResolver returns KMSKeyResolver that associate the given KMS Key to all namespaces.
func NewStaticKMSKeyResolver(kmsKey string) KMSKeyResolver {
	return &staticKMSKeyResolver{
		key: kmsKey,
	}
}

// KeyOf implements KMSKeyResolver
func (r *staticKMSKeyResolver) KeyOf(ctx context.Context, namespace, subID string) (string, error) {
	return r.key, nil
}
