.PHONY: all check test fmt lint build clean dev-up dev-down proto

all: check test

## Build
build:
	cargo build --workspace

build-release:
	cargo build --workspace --release

## Dev
check:
	cargo check --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace -- -D warnings

clean:
	cargo clean

## Proto
proto:
	cargo build -p nac-proto

## Docker infra
dev-up:
	docker compose up -d
	@echo "Waiting for services..."
	@sleep 3
	@docker compose ps

dev-down:
	docker compose down

dev-logs:
	docker compose logs -f

## Run services (dev)
run-sensor:
	cargo run -p sensor

run-enforcement:
	cargo run -p enforcement

run-policy-manager:
	cargo run -p policy-manager

run-aaa:
	cargo run -p aaa

run-api-gateway:
	cargo run -p api-gateway
