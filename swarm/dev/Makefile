.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/ethereum/github.com/go-ethereum-analysis/cmd/swarm
	go build -o bin/geth     github.com/ethereum/github.com/go-ethereum-analysis/cmd/geth
	go build -o bin/bootnode github.com/ethereum/github.com/go-ethereum-analysis/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/ethereum/github.com/go-ethereum-analysis/swarm/...
