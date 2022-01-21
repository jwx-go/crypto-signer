# `crypto.Signer` Interface for AWS Go SDK

This module implements a wrapper around AWS Go SDK's KMS service
which satisfies the built-in `crypto.Signer` interface.

Objects in this module can be passed to act as keys for
signing/verifying payloads (among many other things),
without having to make your private keys available in your program
because AWS KMS service will do this for you.

This means you can use this as keys in github.com/lestrrat-go/jwx:

```go
func Example() {
  // Make sure to set AWS_* environment variable, if you
  // need to configure them.
  awscfg, err := config.LoadDefaultConfig(
    context.Background(),
  )
  if err != nil {
    panic(err.Error())
  }

  kid := os.Getenv(`AWS_KMS_KEY_ID`)
  if kid == "" {
    panic(`missing AWS_KMS_KEY_ID`)
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
```
