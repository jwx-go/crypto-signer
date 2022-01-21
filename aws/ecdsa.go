package awssigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Cache is used internally to store items that are frequently
// accessed. In particular, the public key is accessed for both
// signing _and_ verifying, and is cached if you provide storage for it.
type Cache interface {
	Get(interface{}) (interface{}, bool)
	Set(interface{}, interface{})
}

type ECDSA struct {
	alg    types.SigningAlgorithmSpec
	client *kms.Client
	cache  Cache
	ctx    context.Context
	kid    string
}

// NewECDSA creates a new ECDSA object. This object isnot complete by itself -- it
// needs to be setup with the algorithm name to use (see
// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/kms/types#SigningAlgorithmSpec),
// a key ID, and a context.Context object to use while the AWS SDK makes network
// requests.
func NewECDSA(client *kms.Client) *ECDSA {
	return &ECDSA{
		client: client,
	}
}

func (sv *ECDSA) WithAlgorithm(alg types.SigningAlgorithmSpec) *ECDSA {
	return &ECDSA{
		alg:    alg,
		cache:  sv.cache,
		client: sv.client,
		ctx:    sv.ctx,
		kid:    sv.kid,
	}
}

// WithContext creates a new ECDSA object with the context.Context
// associated with it.
func (sv *ECDSA) WithContext(ctx context.Context) *ECDSA {
	return &ECDSA{
		alg:    sv.alg,
		cache:  sv.cache,
		client: sv.client,
		ctx:    ctx,
		kid:    sv.kid,
	}
}

// WithKeyID creates a new ECDSA object with the key ID
// associated with it.
func (sv *ECDSA) WithKeyID(kid string) *ECDSA {
	return &ECDSA{
		alg:    sv.alg,
		cache:  sv.cache,
		client: sv.client,
		ctx:    sv.ctx,
		kid:    kid,
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
func (sv *ECDSA) WithCache(c Cache) *ECDSA {
	return &ECDSA{
		alg:    sv.alg,
		cache:  c,
		client: sv.client,
		ctx:    sv.ctx,
		kid:    sv.kid,
	}
}

// Sign generates a signature from the given digest.
func (sv *ECDSA) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if sv.alg == "" {
		return nil, fmt.Errorf(`aws.ECDSA.Sign() requires the types.SigningAlgorithmSpec`)
	}
	if sv.kid == "" {
		return nil, fmt.Errorf(`aws.ECDSA.Sign() requires the key ID`)
	}
	if sv.ctx == nil {
		return nil, fmt.Errorf(`aws.ECDSA.Sign() required context.Context`)
	}

	input := kms.SignInput{
		KeyId:            aws.String(sv.kid),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: sv.alg,
	}
	signed, err := sv.client.Sign(sv.ctx, &input)
	if err != nil {
		return nil, fmt.Errorf(`failed to sign via KMS: %w`, err)
	}

	return signed.Signature, nil
}

// Public returns the corresponding public key.
//
// Because the crypto.Signer API does not allow for an error to be returned,
// the return value from this function cannot describe what kind of error
// occurred.
func (sv *ECDSA) Public() crypto.PublicKey {
	pubkey, _ := sv.GetPublicKey()
	return pubkey
}

// This method is an escape hatch for those cases where the user needs
// to debug what went wrong during the GetPublicKey operation.
func (sv *ECDSA) GetPublicKey() (crypto.PublicKey, error) {
	if sv.kid == "" {
		return nil, fmt.Errorf(`aws.ECDSA.Sign() requires the key ID`)
	}

	if cache := sv.cache; cache != nil {
		v, ok := cache.Get(sv.kid)
		if ok {
			if pubkey, ok := v.(*ecdsa.PublicKey); ok {
				return pubkey, nil
			}
		}
	}

	if sv.ctx == nil {
		return nil, fmt.Errorf(`aws.ECDSA.Sign() required context.Context`)
	}

	input := kms.GetPublicKeyInput{
		KeyId: aws.String(sv.kid),
	}
	output, err := sv.client.GetPublicKey(sv.ctx, &input)
	if err != nil {
		return nil, fmt.Errorf(`failed to get public key from KMS: %w`, err)
	}

	if output.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf(`invalid key usage. expected SIGN_VERIFY, got %q`, output.KeyUsage)
	}

	key, err := x509.ParsePKIXPublicKey(output.PublicKey)
	if err != nil {
		return nil, fmt.Errorf(`failed to parse key: %w`, err)
	}

	if cache := sv.cache; cache != nil {
		cache.Set(sv.kid, key)
	}

	return key, nil
}
