package awssigner

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type RSA struct {
	alg    types.SigningAlgorithmSpec
	client *kms.Client
	ctx    context.Context
	kid    string
}

// NewRSA creates a new RSA object. This object isnot complete by itself -- it
// needs to be setup with the algorithm name to use (see
// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/kms/types#SigningAlgorithmSpec),
// a key ID, and a context.Context object to use while the AWS SDK makes network
// requests.
func NewRSA(client *kms.Client) *RSA {
	return &RSA{
		client: client,
	}
}

func (sv *RSA) getContext() context.Context {
	ctx := sv.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx
}

// Sign generates a signature from the given digest.
func (sv *RSA) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if sv.alg == "" {
		return nil, fmt.Errorf(`aws.RSA.Sign() requires the types.SigningAlgorithmSpec`)
	}
	if sv.kid == "" {
		return nil, fmt.Errorf(`aws.RSA.Sign() requires the key ID`)
	}

	// sv.ctx is NOT required, but we will use context.Background here
	// which means there will not be a (clean) way to interrupt this
	// operation
	ctx := sv.getContext()

	input := kms.SignInput{
		KeyId:            aws.String(sv.kid),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: sv.alg,
	}
	signed, err := sv.client.Sign(ctx, &input)
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
func (sv *RSA) Public() crypto.PublicKey {
	pubkey, _ := sv.GetPublicKey()
	return pubkey
}

// This method is an escape hatch for those cases where the user needs
// to debug what went wrong during the GetPublicKey operation.
func (sv *RSA) GetPublicKey() (crypto.PublicKey, error) {
	if sv.kid == "" {
		return nil, fmt.Errorf(`aws.RSA.Sign() requires the key ID`)
	}

	// sv.ctx is NOT required, but we will use context.Background here
	// which means there will not be a (clean) way to interrupt this
	// operation
	ctx := sv.getContext()

	input := kms.GetPublicKeyInput{
		KeyId: aws.String(sv.kid),
	}
	output, err := sv.client.GetPublicKey(ctx, &input)
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

	return key, nil
}
