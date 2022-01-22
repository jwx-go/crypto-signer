#!/bin/bash

pushd internal/cmd/gensigners
go build -o gensigners main.go
popd

./internal/cmd/gensigners/gensigners -objects=internal/cmd/gensigners/objects.yml

rm internal/cmd/gensigners/gensigners
