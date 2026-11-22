SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

PYTHON ?= python3
KUSTO_IMAGE := mcr.microsoft.com/azuredataexplorer/kustainer-linux@sha256:3e3ad07290728f8e47cc1cba78a726c64f4a9980e11a20502a45c0a242d6f8b3

.PHONY: help install lint test kql check emulator emulator-stop emulator-test arm clean

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'

install: ## Install pinned Python and Node dependencies
	$(PYTHON) -m pip install --require-hashes -r requirements-dev.txt
	npm ci --ignore-scripts --prefix tools/kql-parser

lint: ## Ruff, then the detection content linter
	$(PYTHON) -m ruff check tools tests
	$(PYTHON) -m ruff format --check tools tests
	$(PYTHON) -m tools.lint

test: ## Unit tests for the tooling
	$(PYTHON) -m unittest discover -s tests -t .

kql: ## Parse every query with the Kusto language service
	$(PYTHON) -m tools.catalog | node tools/kql-parser/check.js

check: lint test kql ## Everything that runs without Docker

emulator: ## Start the Kusto emulator on localhost:8080
	docker run -d --rm --name kustainer -p 8080:8080 -e ACCEPT_EULA=Y -m 4G $(KUSTO_IMAGE)

emulator-stop: ## Stop the Kusto emulator
	docker stop kustainer

emulator-test: ## Run every query against its test cases on the emulator
	$(PYTHON) -m tools.emulator_test --wait 120

arm: ## Build the ARM template into build/
	$(PYTHON) -m tools.build_arm -o build/sentinel-analytics.json

clean: ## Remove build output
	rm -rf build
