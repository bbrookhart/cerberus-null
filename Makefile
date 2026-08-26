SHELL := /bin/bash
UV_CACHE_DIR ?= .cache/uv
export UV_CACHE_DIR
export UV_LINK_MODE := copy

.PHONY: bootstrap format lint typecheck test test-adversarial test-properties security sbom up health demo evaluate evidence docs down clean

bootstrap:
	uv sync --frozen --extra dev

format:
	uv run ruff format .

lint:
	uv run ruff format --check .
	uv run ruff check .

typecheck:
	uv run mypy cerberus_null

test:
	uv run pytest --cov=cerberus_null --cov-branch --cov-report=term-missing

test-adversarial:
	uv run pytest -m adversarial tests/adversarial

test-properties:
	uv run pytest -m property tests/property

security:
	uv run bandit -q -c pyproject.toml -r cerberus_null
	uv run pip-audit --cache-dir .cache/pip-audit

sbom:
	mkdir -p build
	uv run cyclonedx-py environment --output-format JSON --output-file build/sbom.cdx.json

up:
	docker compose up --build --detach

health:
	curl --fail --silent http://127.0.0.1:8080/health

demo:
	uv run cerberus demo --output evidence

evaluate:
	uv run cerberus evaluation run all --output evidence

evidence:
	uv run cerberus evidence verify evidence/baseline-v0.1.0

docs:
	test -s README.md
	test -s docs/reviewer-guide.md
	test -s docs/assurance-case.md

down:
	docker compose down --remove-orphans

clean:
	rm -rf build dist htmlcov .coverage .pytest_cache .mypy_cache .ruff_cache
