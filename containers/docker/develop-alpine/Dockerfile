FROM alpine:3.7

RUN \
  apk add --update go git make gcc musl-dev linux-headers ca-certificates && \
  git clone --depth 1 https://github.com/ethereum/github.com/go-ethereum-analysis && \
  (cd github.com/go-ethereum-analysis && make geth) && \
  cp github.com/go-ethereum-analysis/build/bin/geth /geth && \
  apk del go git make gcc musl-dev linux-headers && \
  rm -rf /github.com/go-ethereum-analysis && rm -rf /var/cache/apk/*

EXPOSE 8545
EXPOSE 30303

ENTRYPOINT ["/geth"]
