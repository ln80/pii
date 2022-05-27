package kms

import "context"

type KMSKeyResolver interface {
	KeyOf(ctx context.Context, namespace, subID string) (kmsKey string, err error)
	// HasNewKey(ctx context.Context, namespace, subID string) (ok bool, oldKmsKey, newKmsKey string, err error)
}

type staticKMSKeyResolver struct{ key string }

var _ KMSKeyResolver = &staticKMSKeyResolver{}

func NewStaticKMSKeyResolver(kmsKey string) KMSKeyResolver {
	return &staticKMSKeyResolver{
		key: kmsKey,
	}
}

func (r *staticKMSKeyResolver) KeyOf(ctx context.Context, namespace, subID string) (string, error) {
	return r.key, nil
}

// func (r *staticKMSKeyResolver) HasNewKey(ctx context.Context, namespace, subID string) (bool, string, string, error) {
// 	return r.current != r.new && r.new != "", r.current, r.new, nil
// }
