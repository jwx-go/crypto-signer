package awssigner_test

import (
	"bytes"
	"context"
	"crypto"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	awssigner "github.com/jwx-go/crypto-signer/aws"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
)

var _ crypto.Signer = &awssigner.RSA{}

func ExampleRSA() {
	// Make sure to set AWS_* environment variable, if you
	// need to configure them.
	awscfg, err := config.LoadDefaultConfig(
		context.Background(),
	)
	if err != nil {
		panic(err.Error())
	}

	kid := os.Getenv(`AWS_KMS_KEY_ID_RSA`)
	if kid == "" {
		panic(`missing AWS_KMS_KEY_ID_RSA`)
	}
	payload := []byte("obla-di-obla-da")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	sv := awssigner.NewRSA(kms.NewFromConfig(awscfg)).
		WithAlgorithm(types.SigningAlgorithmSpecRsassaPkcs1V15Sha256).
		WithKeyID(kid)

	signed, err := jws.Sign(payload, jwa.RS256, sv.WithContext(ctx))
	if err != nil {
		panic(err.Error())
	}

	verified, err := jws.Verify(signed, jwa.RS256, sv.WithContext(ctx))
	if err != nil {
		panic(err.Error())
	}

	if bytes.Compare(payload, verified) != 0 {
		panic("payload and verified does not match")
	}
	//OUTPUT:
}

func ExampleECDSA() {
	// Make sure to set AWS_* environment variable, if you
	// need to configure them.
	awscfg, err := config.LoadDefaultConfig(
		context.Background(),
	)
	if err != nil {
		panic(err.Error())
	}

	kid := os.Getenv(`AWS_KMS_KEY_ID_ECDSA`)
	if kid == "" {
		panic(`missing AWS_KMS_KEY_ID_ECDSA`)
	}
	payload := []byte("obla-di-obla-da")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	sv := awssigner.NewECDSA(kms.NewFromConfig(awscfg)).
		WithAlgorithm(types.SigningAlgorithmSpecEcdsaSha256).
		WithKeyID(kid)

	signed, err := jws.Sign(payload, jwa.ES256, sv.WithContext(ctx))
	if err != nil {
		panic(err.Error())
	}

	verified, err := jws.Verify(signed, jwa.ES256, sv.WithContext(ctx))
	if err != nil {
		panic(err.Error())
	}

	if bytes.Compare(payload, verified) != 0 {
		panic("payload and verified does not match")
	}
	//OUTPUT:
}
