.PHONY: build test vet check compose-config up down logs

build:
	CGO_ENABLED=0 go build -trimpath -o bannerfp ./cmd/bannerfp

test:
	go test ./...

vet:
	go vet ./...

compose-config:
	docker compose config --quiet

check: test vet compose-config

up:
	docker compose up --build

down:
	docker compose down --remove-orphans

logs:
	docker compose logs client
