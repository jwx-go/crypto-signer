package awssigner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// WithAlgorithm associates a new types.SigningAlgorithmSpec with the object, which will be used for Sign() and Public()
func (cs *ECDSA) WithAlgorithm(v types.SigningAlgorithmSpec) *ECDSA {
	return &ECDSA{
		client: cs.client,
		alg:    v,
		cache:  cs.cache,
		ctx:    cs.ctx,
		kid:    cs.kid,
	}
}

// WithCache specifies the cache storage for frequently used items.
// Currently only the public key is cached.
//
// If it is not specified, nothing will be cached.
//
// Since it would be rather easy for the key in AWS KMS and the cache
// to be out of sync, make sure to either purge the cache periodically
// or use a cache with some sort of auto-eviction mechanism.
func (cs *ECDSA) WithCache(v Cache) *ECDSA {
	return &ECDSA{
		client: cs.client,
		alg:    cs.alg,
		cache:  v,
		ctx:    cs.ctx,
		kid:    cs.kid,
	}
}

// WithContext associates a new context.Context with the object, which will be used for Sign() and Public()
func (cs *ECDSA) WithContext(v context.Context) *ECDSA {
	return &ECDSA{
		client: cs.client,
		alg:    cs.alg,
		cache:  cs.cache,
		ctx:    v,
		kid:    cs.kid,
	}
}

// WithKeyID associates a new string with the object, which will be used for Sign() and Public()
func (cs *ECDSA) WithKeyID(v string) *ECDSA {
	return &ECDSA{
		client: cs.client,
		alg:    cs.alg,
		cache:  cs.cache,
		ctx:    cs.ctx,
		kid:    v,
	}
}
