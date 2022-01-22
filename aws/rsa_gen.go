package awssigner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// WithAlgorithm associates a new types.SigningAlgorithmSpec with the object, which will be used for Sign() and Public()
func (cs *RSA) WithAlgorithm(v types.SigningAlgorithmSpec) *RSA {
	return &RSA{
		client: cs.client,
		alg:    v,
		ctx:    cs.ctx,
		kid:    cs.kid,
	}
}

// WithContext associates a new context.Context with the object, which will be used for Sign() and Public()
func (cs *RSA) WithContext(v context.Context) *RSA {
	return &RSA{
		client: cs.client,
		alg:    cs.alg,
		ctx:    v,
		kid:    cs.kid,
	}
}

// WithKeyID associates a new string with the object, which will be used for Sign() and Public()
func (cs *RSA) WithKeyID(v string) *RSA {
	return &RSA{
		client: cs.client,
		alg:    cs.alg,
		ctx:    cs.ctx,
		kid:    v,
	}
}
