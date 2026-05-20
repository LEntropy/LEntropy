.PHONY: all check test fmt lint build clean dev-up dev-down dev-lab-up dev-lab-down \
        proto watch audit setup

all: check test

## 최초 환경 초기화 (처음 한 번만 실행)
setup:
	@if [ ! -f .env ]; then cp .env.example .env; echo "✓ .env 생성됨 (값을 확인하세요)"; \
	else echo "✓ .env 이미 존재"; fi
	docker compose up -d
	@echo "Waiting for services to be healthy..."
	@sleep 5
	@docker compose ps

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

## 통합 테스트 랩
dev-lab-up:
	docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d

dev-lab-down:
	docker compose -f docker-compose.yml -f docker-compose.lab.yml down

## Watch (파일 변경 시 자동 체크)
watch:
	cargo watch -x 'check --workspace'

watch-test:
	cargo watch -x 'test --workspace'

## 보안 감사
audit:
	cargo audit

deny:
	cargo deny check

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
