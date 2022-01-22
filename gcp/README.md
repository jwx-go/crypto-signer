# `crypto.Signer` Interface for Google Cloud Platform Go SDK

This module implements a wrapper around Google Cloud Platform Go SDK's KMS service
which satisfies the built-in `crypto.Signer` interface.

Objects in this module can be passed to act as keys for
signing/verifying payloads (among many other things),
without having to make your private keys available in your program
because Google Cloud KMS service will do this for you.

This means you can use this as keys in github.com/lestrrat-go/jwx:

```go
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

  signed, err := jws.Sign(payload, jwa.RS256, s.WithContext(ctx))
  if err != nil {
    panic(err.Error())
  }

  verified, err := jws.Verify(signed, jwa.RS256, s.WithContext(ctx))
  if err != nil {
    panic(err.Error())
  }

  if bytes.Compare(payload, verified) != 0 {
    panic("payload and verified does not match")
  }
  //OUTPUT:
}
```
