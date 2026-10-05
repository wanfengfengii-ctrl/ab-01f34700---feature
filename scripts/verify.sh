#!/bin/sh
# One-shot verification. Exit code 0 only if all three stages pass:
#   1. unit tests            (go test ./...)
#   2. in-image project build (go build ./...)
#   3. live smoke            (real TCP writes + HTTP queries against app)
set -eu

cd /src

echo "==> [1/3] go test ./..."
go test ./...

echo "==> [2/3] go build ./... (in-image build)"
go build ./...

echo "==> [3/3] live smoke against ${APP_HTTP_ADDR:-http://app:8080} / ${APP_TCP_ADDR:-app:9000}"
go run ./cmd/verify

echo "VERIFY PASSED"
