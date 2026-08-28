SHELL := /bin/bash
UV_CACHE_DIR ?= .cache/uv
export UV_CACHE_DIR
export UV_LINK_MODE := copy

.PHONY: bootstrap format lint typecheck test test-adversarial test-properties coverage mutation formal experiment security sbom up health demo evaluate evidence results docs down clean

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

coverage:
	uv run pytest --cov=cerberus_null --cov-branch --cov-report=term-missing

mutation:
	uv run python scripts/run_mutation_checks.py

formal:
	formal/scripts/model_check.sh

experiment: test formal
	uv run cerberus experiment run --output evidence --figure assets/compromised-planner-results.svg

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
	uv run cerberus evidence verify evidence/EXP-CN-001-v0.1.0
	uv run cerberus experiment verify-results evidence/EXP-CN-001-v0.1.0

results: formal mutation evidence
	test -s formal/results/v0.1-model-check.md
	test -s evidence/EXP-CN-001-v0.1.0/comparison.md

docs:
	test -s README.md
	test -s docs/reviewer-guide.md
	test -s docs/assurance-case.md
	test -s docs/CERBERUS-NULL-v0.1-research-report.md
	test -s docs/formal-implementation-map.md
	test -s docs/mutation-results.md

down:
	docker compose down --remove-orphans

clean:
	rm -rf build dist htmlcov .coverage .pytest_cache .mypy_cache .ruff_cache
