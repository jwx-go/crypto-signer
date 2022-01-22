package gcpsigner_test

import (
	"bytes"
	"context"
	"crypto"
	"log"
	"os"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	gcpsigner "github.com/jwx-go/crypto-signer/gcp"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
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

func Example() {
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
		Key:      os.Getenv(`GCP_SIGNER_KEY`),
	}

	log.Printf(ks.String())
	s := gcpsigner.New(client).
		WithName(ks.String()).
		WithCache(NewDumbCache())

	signed, err := jws.Sign(payload, jwa.ES256, s.WithContext(ctx))
	if err != nil {
		panic(err.Error())
	}

	verified, err := jws.Verify(signed, jwa.ES256, s.WithContext(ctx))
	if err != nil {
		panic(err.Error())
	}

	if bytes.Compare(payload, verified) != 0 {
		panic("payload and verified does not match")
	}
	//OUTPUT:
}
