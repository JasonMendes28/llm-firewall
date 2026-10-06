.PHONY: help install lint format test test-unit test-integration test-redteam scan run docker-build docker-up docker-down

PY := PYTHONPATH=src python

help:
	@echo "make install           - install dev deps"
	@echo "make lint              - ruff + black check"
	@echo "make format            - apply black + ruff --fix"
	@echo "make test              - unit + integration tests"
	@echo "make test-unit         - unit tests only"
	@echo "make test-integration  - integration tests"
	@echo "make test-redteam      - full red-team suite"
	@echo "make scan              - pip-audit vulnerability scan"
	@echo "make run               - run the firewall locally"
	@echo "make docker-build      - build the container image"
	@echo "make docker-up         - docker compose up (dev)"
	@echo "make docker-down       - docker compose down"

install:
	pip install -r requirements-dev.txt

lint:
	ruff check src tests
	black --check src tests

format:
	ruff check --fix src tests
	black src tests

test-unit:
	$(PY) -m pytest tests/unit -x

test-integration:
	$(PY) -m pytest tests/integration -x

test-redteam:
	$(PY) -m pytest tests/redteam -x

test: test-unit test-integration

scan:
	pip-audit -r requirements.txt

run:
	$(PY) -m uvicorn firewall.main:app --host 0.0.0.0 --port 8080 --reload

docker-build:
	docker build -t llm-firewall:0.1.0 .

docker-up:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

docker-down:
	docker compose down
