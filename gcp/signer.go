package gcpsigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type Signer struct {
	cache  Cache
	client *kms.KeyManagementClient
	ctx    context.Context
	name   string
}

func New(client *kms.KeyManagementClient) *Signer {
	return &Signer{
		client: client,
	}
}

func (sv *Signer) getContext() context.Context {
	ctx := sv.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx
}

func (cs *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// We need to get the public key, otherwise we have no way of knowing
	// hints about the private key when signing
	key, err := cs.GetPublicKey()
	var pbdigest kmspb.Digest
	switch key := key.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			pbdigest.Digest = &kmspb.Digest_Sha256{
				Sha256: digest,
			}
		case 384:
			pbdigest.Digest = &kmspb.Digest_Sha384{
				Sha384: digest,
			}
		case 512:
			pbdigest.Digest = &kmspb.Digest_Sha512{
				Sha512: digest,
			}
		default:
			return nil, fmt.Errorf(`unsupported digest size: %d`, key.Size())
		}
	case *ecdsa.PublicKey:
		switch size := key.Curve.Params().BitSize; size {
		case 256:
			pbdigest.Digest = &kmspb.Digest_Sha256{
				Sha256: digest,
			}
		case 384:
			pbdigest.Digest = &kmspb.Digest_Sha384{
				Sha384: digest,
			}
		case 512:
			pbdigest.Digest = &kmspb.Digest_Sha512{
				Sha512: digest,
			}
		default:
			return nil, fmt.Errorf(`unsupported digest size: %d`, size)
		}
	}

	req := &kmspb.AsymmetricSignRequest{
		Name:   cs.name,
		Digest: &pbdigest,
	}

	ctx := cs.getContext()

	res, err := cs.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf(`failed to sign digest: %w`, err)
	}

	return res.Signature, nil
}

func (cs *Signer) Public() crypto.PublicKey {
	key, _ := cs.GetPublicKey()
	return key
}

func (cs *Signer) GetPublicKey() (crypto.PublicKey, error) {
	if cache := cs.cache; cache != nil {
		pubkey, ok := cache.Get(cs.name)
		if ok {
			return pubkey, nil
		}
	}

	ctx := cs.getContext()

	res, err := cs.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: cs.name})
	if err != nil {
		return nil, fmt.Errorf(`failed to get public key: %w`, err)
	}

	block, _ := pem.Decode([]byte(res.Pem))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(`failed to parse key: %w`, err)
	}

	if cache := cs.cache; cache != nil {
		cache.Set(cs.name, key)
	}

	return key, nil
}
