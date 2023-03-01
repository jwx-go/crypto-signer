package gcpsigner_test

import (
	"bytes"
	"context"
	"crypto"
	"os"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	gcpsigner "github.com/jwx-go/crypto-signer/v2/gcp"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

var _ crypto.Signer = &gcpsigner.Signer{}

type DumbCache struct {
	storage map[interface{}]interface{}
}

func NewDumbCache() *DumbCache {
	return &DumbCache{
		storage: make(map[interface{}]interface{}),
	}
}

func (c *DumbCache) Get(key interface{}) (interface{}, bool) {
	v, ok := c.storage[key]
	return v, ok
}

func (c *DumbCache) Set(key, value interface{}) {
	c.storage[key] = value
}

func ExampleRSA() {
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
		return
	}

	payload := []byte("obla-di-obla-da")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		panic(err.Error())
	}

	ks := gcpsigner.KeySpec{
		Project:  os.Getenv(`GCP_SIGNER_PROJECT`),
		Location: os.Getenv(`GCP_SIGNER_LOCATION`),
		KeyRing:  os.Getenv(`GCP_SIGNER_KEY_RING`),
		Key:      os.Getenv(`GCP_SIGNER_RSA_KEY`),
	}

	s := gcpsigner.New(client).
		WithName(ks.String()).
		WithCache(NewDumbCache())

	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256, s.WithContext(ctx)))
	if err != nil {
		panic(err.Error())
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwa.RS256, s.WithContext(ctx)))
	if err != nil {
		panic(err.Error())
	}

	if bytes.Compare(payload, verified) != 0 {
		panic("payload and verified does not match")
	}
	//OUTPUT:
}

func ExampleECDSA() {
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
		return
	}

	payload := []byte("obla-di-obla-da")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		panic(err.Error())
	}

	ks := gcpsigner.KeySpec{
		Project:  os.Getenv(`GCP_SIGNER_PROJECT`),
		Location: os.Getenv(`GCP_SIGNER_LOCATION`),
		KeyRing:  os.Getenv(`GCP_SIGNER_KEY_RING`),
		Key:      os.Getenv(`GCP_SIGNER_ECDSA_KEY`),
	}

	s := gcpsigner.New(client).
		WithName(ks.String()).
		WithCache(NewDumbCache())

	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, s.WithContext(ctx)))
	if err != nil {
		panic(err.Error())
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwa.ES256, s.WithContext(ctx)))
	if err != nil {
		panic(err.Error())
	}

	if bytes.Compare(payload, verified) != 0 {
		panic("payload and verified does not match")
	}
	//OUTPUT:
}
