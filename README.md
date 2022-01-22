# crypto-signer

This repository holds `crypto.Signer` implementations for Go.
Current the following implementations are evailable

* [ghtub.com/jwx-go/crypto-signer/aws](./aws) - `crypto.Signer` adaptor for AWS KMS
* [ghtub.com/jwx-go/crypto-signer/gcp](./gcp) - `crypto.Signer` adaptor for GCP KMS

They are built for the purpose of using along with `github.com/lestrrat-go/jwx`,
but they should work for general use cases too.
