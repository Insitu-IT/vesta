VERSION := $(shell cat VERSION)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build build-kubevirt gen-contracts test test-kubevirt lint clean

build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o bin/vnbui-agent ./cmd/vnbui-agent

build-kubevirt:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -tags kubevirt -ldflags="$(LDFLAGS)" -o bin/vnbui-agent-kubevirt ./cmd/vnbui-agent

gen-contracts:
	go run ./cmd/gen-contracts contracts/contracts.py

test:
	go test -race -count=1 ./...

test-kubevirt:
	go test -tags kubevirt -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
