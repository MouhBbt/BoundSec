.PHONY: help install test test-unit test-integration lint fmt demo clean docker-build docker-demo

# ── Variables ────────────────────────────────────────────────────────────────
PYTHON      := .venv/bin/python
PIP         := .venv/bin/pip
PYTEST      := .venv/bin/pytest
RUFF        := .venv/bin/ruff
UVICORN     := .venv/bin/uvicorn
MOCK_PORT   := 8000
MOCK_PID    := /tmp/agentfuzz_mock.pid

# ── Help ─────────────────────────────────────────────────────────────────────
help: ## Show this help message
	@echo "AgentFuzz – Development Commands"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "%-20s %s\n", "Target", "Description"} \
	      /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ── Setup ────────────────────────────────────────────────────────────────────
install: ## Create venv and install all dependencies
	python3 -m venv .venv
	$(PIP) install --upgrade pip -q
	$(PIP) install -r requirements.txt -q
	$(PIP) install -e . -q
	@echo "✅ Environment ready. Activate with: source .venv/bin/activate"

# ── Testing ──────────────────────────────────────────────────────────────────
test-unit: ## Run unit tests only (no server required, fast)
	$(PYTEST) tests/test_agentfuzz.py -k "not e2e and not End" -v --tb=short

test-integration: _start-mock ## Run full test suite including e2e integration tests
	$(PYTEST) tests/ -v --tb=short
	@$(MAKE) _stop-mock

test: test-unit test-integration ## Run all tests

_start-mock: ## (internal) Start mock target on port 8001
	@echo "Starting mock target on port 8001…"
	@$(UVICORN) tests.target_mock:app --host 0.0.0.0 --port 8001 --log-level error & \
	 echo $$! > $(MOCK_PID)
	@sleep 2

_stop-mock: ## (internal) Stop mock target
	@kill $$(cat $(MOCK_PID) 2>/dev/null) 2>/dev/null || true
	@rm -f $(MOCK_PID)

# ── Code Quality ─────────────────────────────────────────────────────────────
lint: ## Run ruff linter (check only)
	$(RUFF) check agentfuzz/ tests/

fmt: ## Auto-format code with ruff
	$(RUFF) format agentfuzz/ tests/
	$(RUFF) check --fix agentfuzz/ tests/

# ── Demo ─────────────────────────────────────────────────────────────────────
demo: ## Start mock target + run fuzzer (full live demo)
	@echo "⚠️  Starting vulnerable mock target on port $(MOCK_PORT)…"
	@$(UVICORN) tests.target_mock:app --host 0.0.0.0 --port $(MOCK_PORT) --log-level error & \
	 echo $$! > $(MOCK_PID)
	@sleep 2
	@echo ""
	$(PYTHON) -m agentfuzz fuzz \
		--target http://localhost:$(MOCK_PORT)/chat \
		--verbose \
		--output reports/demo_$$(date +%Y%m%d_%H%M%S).json || true
	@$(MAKE) _stop-mock

# ── Docker ───────────────────────────────────────────────────────────────────
docker-build: ## Build the Docker image
	docker build -t agentfuzz:latest .

docker-demo: ## Run a full demo using Docker Compose
	docker compose up --abort-on-container-exit

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean: ## Remove build artifacts and caches
	rm -rf .venv .pytest_cache agentfuzz.egg-info dist build reports/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "✅ Cleaned"
