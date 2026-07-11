# Archon Makefile
# Common development and deployment commands

.PHONY: help up down logs test lint typecheck build clean benchmark run-battle run-normal-user

# Default target
help:
	@echo "Archon - Adversarial Agent Security Framework"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Development:"
	@echo "  up              Start all services with docker-compose"
	@echo "  down            Stop all services"
	@echo "  logs            View logs from all services"
	@echo "  shell           Open shell in orchestrator container"
	@echo ""
	@echo "Testing & Quality:"
	@echo "  test            Run unit tests"
	@echo "  test-cov        Run tests with coverage"
	@echo "  lint            Run ruff linter"
	@echo "  typecheck       Run mypy type checker"
	@echo "  check           Run all quality checks (lint + typecheck + test)"
	@echo ""
	@echo "Building:"
	@echo "  build           Build docker images"
	@echo "  build-dev       Build development docker images"
	@echo ""
	@echo "Running Battles:"
	@echo "  run-battle      Run a battle (usage: make run-battle SCENARIO=portfolioiq)"
	@echo "  run-normal-user Run normal user test (usage: make run-normal-user SCENARIO=portfolioiq)"
	@echo ""
	@echo "Benchmarking:"
	@echo "  benchmark       Run full benchmark suite"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean           Clean up build artifacts"
	@echo "  clean-all       Clean everything including docker volumes"

# Variables
SCENARIO ?= portfolioiq
UV := uv run

# Development commands
up:
	docker-compose up -d --build

down:
	docker-compose down

logs:
	docker-compose logs -f

shell:
	docker-compose exec orchestrator bash

# Testing & Quality
test:
	$(UV) pytest tests/ -v

test-cov:
	$(UV) pytest tests/ --cov=src/archon --cov=scenarios --cov-report=term-missing --cov-report=html

lint:
	$(UV) ruff check src/ tests/ scenarios/
	$(UV) ruff format --check src/ tests/ scenarios/

typecheck:
	$(UV) mypy src/archon --strict

check: lint typecheck test

# Building
build:
	docker-compose build

build-dev:
	docker-compose -f docker-compose.yml -f docker-compose.override.yml.example build

# Running Battles
run-battle:
	@echo "Running battle for scenario: $(SCENARIO)"
	$(UV) python -m scenarios.security_arena.orchestrator --host 0.0.0.0 --port 9010 &
	$(UV) python -m scenarios.security_arena.agents.attacker.agent --host 0.0.0.0 --port 9021 &
	$(UV) python -m scenarios.security_arena.agents.defender.agent --host 0.0.0.0 --port 9020 &
	$(UV) python -m scenarios.security_arena.agents.normal_user.agent --host 0.0.0.0 --port 9022 &
	sleep 10
	$(UV) python -m archon.client_cli scenarios/security_arena/scenario_$(SCENARIO).toml

run-normal-user:
	@echo "Running normal user test for scenario: $(SCENARIO)"
	$(UV) python -m archon.client_cli scenarios/security_arena/scenario_$(SCENARIO).toml --normal-user

# Benchmarking
benchmark:
	$(UV) python scripts/benchmark.py

# Cleaning
clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

clean-all: clean
	docker-compose down -v
	docker system prune -f