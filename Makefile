# WhiteHatHacker AI — Makefile
# Common commands for development, testing and deployment

.PHONY: help install install-dev test lint format check health setup run serve clean docker docker-gpu

PYTHON ?= python3
PIP ?= pip3

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Installation ──

install: ## Install production dependencies
	$(PIP) install -r requirements.txt

install-dev: ## Install with dev/test dependencies
	$(PIP) install -e ".[dev]"

install-gpu: ## Install with GPU (CUDA) support
	CMAKE_ARGS="-DGGML_CUDA=on" $(PIP) install llama-cpp-python --force-reinstall --no-binary :all:
	$(PIP) install -r requirements.txt

# ── Setup ──

setup: install ## Full setup (tools + wordlists + health check)
	bash scripts/setup_kali_tools.sh
	bash scripts/setup_go_tools.sh
	bash scripts/setup_wordlists.sh
	bash scripts/health_check.sh

setup-tools: ## Install security tools only
	bash scripts/setup_kali_tools.sh
	bash scripts/setup_go_tools.sh

setup-models: ## Download LLM models
	bash scripts/download_models.sh

setup-wordlists: ## Download wordlists
	bash scripts/setup_wordlists.sh

health: ## Run health check
	bash scripts/health_check.sh

# ── Running ──

run: ## Run interactive CLI scan (TARGET required)
	$(PYTHON) -m src.main scan --target $(TARGET) --profile balanced

recon: ## Quick recon only (TARGET required)
	$(PYTHON) -m src.main recon --target $(TARGET)

serve: ## Start API server
	$(PYTHON) -m uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

# ── Testing ──

test: ## Run all tests
	$(PYTHON) -m pytest tests/ -v

test-fast: ## Run tests excluding slow/integration
	$(PYTHON) -m pytest tests/ -v -m "not slow and not integration"

test-cov: ## Run tests with coverage report
	$(PYTHON) -m pytest tests/ --cov=src --cov-report=html --cov-report=term-missing

test-brain: ## Test brain engine only
	$(PYTHON) -m pytest tests/test_brain/ -v

test-tools: ## Test tool wrappers only
	$(PYTHON) -m pytest tests/test_tools/ -v

test-fp: ## Test FP engine only
	$(PYTHON) -m pytest tests/test_fp_engine/ -v

# ── Code Quality ──

lint: ## Run linter (ruff)
	$(PYTHON) -m ruff check src/ tests/

format: ## Auto-format code (ruff + black)
	$(PYTHON) -m ruff check --fix src/ tests/
	$(PYTHON) -m black src/ tests/

typecheck: ## Run type checker (mypy)
	$(PYTHON) -m mypy src/

check: lint typecheck ## Run all checks (lint + type)

compile-check: ## Verify all Python files compile
	find src tests -name "*.py" -exec $(PYTHON) -m py_compile {} +
	@echo "All files compile successfully."

# ── Docker ──

docker: ## Build and run CPU Docker container
	docker compose -f docker/docker-compose.yaml --profile cpu up --build -d

docker-gpu: ## Build and run GPU Docker container
	docker compose -f docker/docker-compose.yaml --profile gpu up --build -d

docker-down: ## Stop all containers
	docker compose -f docker/docker-compose.yaml down

docker-logs: ## Tail container logs
	docker compose -f docker/docker-compose.yaml logs -f

# ── Cleanup ──

clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf htmlcov/ .coverage dist/ build/ *.egg-info

clean-output: ## Remove scan outputs (reports, evidence, logs)
	rm -rf output/reports/* output/screenshots/* output/evidence/* output/logs/*
