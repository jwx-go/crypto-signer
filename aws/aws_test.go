package awssigner_test

import (
	"context"
	"crypto"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	awssigner "github.com/jwx-go/crypto-signer/aws"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
)

var _ crypto.Signer = &awssigner.RSA{}

func Example() {
	awscfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithRegion("us-central-1"),
	)
	if err != nil {
		panic(err.Error())
	}

	kid := "your AWS kid"
	payload := []byte("obla-di-obla-da")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	sv := awssigner.NewRSA(kms.NewFromConfig(awscfg)).
		WithAlgorithm(types.SigningAlgorithmSpecRsassaPkcs1V15Sha256).
		WithKeyID(kid)

	signed, err := jws.Sign(payload, jwa.ES256, sv.WithContext(ctx))
	if err != nil {
		panic(err.Error())
	}
	if _, err := jws.Verify(signed, jwa.ES256, sv.WithContext(ctx)); err != nil {
		panic(err.Error())
	}
}
