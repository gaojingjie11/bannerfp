# syntax=docker/dockerfile:1
FROM golang:1.24.5-alpine3.22 AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -buildid=" \
    -o /out/bannerfp \
    ./cmd/bannerfp

FROM scratch

COPY --from=build --chown=65532:65532 /out/bannerfp /bannerfp
USER 65532:65532
ENTRYPOINT ["/bannerfp"]
CMD ["serve"]
