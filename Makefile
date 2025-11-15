.PHONY: examples tests

SHELL=/bin/bash

# Installation
install:
	@echo "Installing dependencies..."
	@uv pip install -e ".[dev]"

# Development
dev:
	@echo "Starting Redis container..."
	docker compose up -d

dev-down:
	@echo "Stopping Redis container..."
	docker compose down

# Testing
test:
	@echo "Running all tests..."
	@pytest tests/ -v

test-integration:
	@echo "Running integration tests..."
	@pytest tests/integration/ -v

test-cov:
	@echo "Running tests with coverage..."
	@pytest tests/ --cov=redis_session_manager --cov-report=term-missing

test-cov-html:
	@echo "Running tests with HTML coverage report..."
	@pytest tests/ --cov=redis_session_manager --cov-report=html
	@echo "Coverage report generated in htmlcov/index.html"

# Code quality
lint:
	@echo "Running linter..."
	@ruff check src/ tests/

format:
	@echo "Formatting code..."
	@ruff format src/ tests/

# Examples
run-basic:
	@source .venv/bin/activate \
		&& uv run -m examples.basic_usage

# Help
help:
	@echo "Available commands:"
	@echo "  make install              - Install dependencies"
	@echo "  make dev                  - Start Redis container"
	@echo "  make dev-down             - Stop Redis container"
	@echo "  make test                 - Run all tests"
	@echo "  make test-integration     - Run integration tests only"
	@echo "  make test-cov             - Run tests with coverage report"
	@echo "  make test-cov-html        - Run tests with HTML coverage report"
	@echo "  make lint                 - Run linter"
	@echo "  make format               - Format code"
	@echo "  make run-basic            - Run basic example"
