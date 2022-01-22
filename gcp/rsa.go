package gcpsigner

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type RSA struct {
	client *kms.KeyManagementClient
	ctx    context.Context
	name   string
}

func NewRSA(client *kms.KeyManagementClient) *RSA {
	return &RSA{
		client: client,
	}
}

func (cs *RSA) WithContext(ctx context.Context) *RSA {
	return &RSA{
		client: cs.client,
		ctx:    ctx,
	}
}

func (sv *RSA) getContext() context.Context {
	ctx := sv.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx
}

func (cs *RSA) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// We need to get the public key, otherwise we have no way of knowing
	// hints about the private key when signing
	key, err := cs.GetPublicKey()
	pubkey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf(`specified key is not an RSA key`)
	}

	var pbdigest kmspb.Digest
	switch pubkey.Size() {
	case 32: //256
		pbdigest.Digest = &kmspb.Digest_Sha256{
			Sha256: digest,
		}
	case 48: //384
		pbdigest.Digest = &kmspb.Digest_Sha384{
			Sha384: digest,
		}
	case 64: //512
		pbdigest.Digest = &kmspb.Digest_Sha512{
			Sha512: digest,
		}
	default:
		return nil, fmt.Errorf(`unsupported digest size: %d`, pubkey.Size())
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

func (cs *RSA) Public() crypto.PublicKey {
	key, _ := cs.GetPublicKey()
	return key
}

func (cs *RSA) GetPublicKey() (crypto.PublicKey, error) {
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

	return key, nil
}
