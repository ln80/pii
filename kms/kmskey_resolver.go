package kms

import "context"

type KMSKeyResolver interface {
	KeyOf(ctx context.Context, namespace, subID string) (kmsKey string, err error)
	HasNewKey(ctx context.Context, namespace, subID string) (ok bool, oldKmsKey, newKmsKey string, err error)
}

type staticKMSKeyResolver struct{ current, new string }

var _ KMSKeyResolver = &staticKMSKeyResolver{}

func NewStaticKMSKeyResolver(currentKey, newKey string) KMSKeyResolver {
	return &staticKMSKeyResolver{
		current: currentKey,
		new:     newKey,
	}
}

func (r *staticKMSKeyResolver) KeyOf(ctx context.Context, namespace, subID string) (string, error) {
	return r.current, nil
}

func (r *staticKMSKeyResolver) HasNewKey(ctx context.Context, namespace, subID string) (bool, string, string, error) {
	return r.current != r.new && r.new != "", r.current, r.new, nil
}
