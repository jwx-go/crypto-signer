package gcpsigner

import "context"

// WithCache specifies the cache storage for frequently used items.
// Currently only the public key is cached.
//
// If it is not specified, nothing will be cached.
//
// Since it would be rather easy for the key in AWS KMS and the cache
// to be out of sync, make sure to either purge the cache periodically
// or use a cache with some sort of auto-eviction mechanism.
func (cs *Signer) WithCache(v Cache) *Signer {
	return &Signer{
		client: cs.client,
		cache:  v,
		ctx:    cs.ctx,
		name:   cs.name,
	}
}

// WithContext associates a new context.Context with the object, which will be used for Sign() and Public()
func (cs *Signer) WithContext(v context.Context) *Signer {
	return &Signer{
		client: cs.client,
		cache:  cs.cache,
		ctx:    v,
		name:   cs.name,
	}
}

// WithName associates a new string with the object, which will be used for Sign() and Public()
func (cs *Signer) WithName(v string) *Signer {
	return &Signer{
		client: cs.client,
		cache:  cs.cache,
		ctx:    cs.ctx,
		name:   v,
	}
}
