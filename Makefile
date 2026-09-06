# BoundSec - developer tasks
.PHONY: help install test lint demo benchmark experiment experiment-quick figures clean

PY := python

help:
	@echo "BoundSec - coverage-guided LLM-agent security fuzzing"
	@echo ""
	@echo "  make install           Install package + dev deps (editable)"
	@echo "  make test              Run the test suite"
	@echo "  make demo              One coverage-guided campaign vs the hardened gym"
	@echo "  make benchmark         Quick 4-strategy comparison table"
	@echo "  make experiment-quick  Fast evaluation (budget 300, 5 seeds)"
	@echo "  make experiment        Full evaluation (budget 600, 15 seeds) + figures"
	@echo "  make figures           Regenerate figures from results/"
	@echo "  make clean             Remove caches"

install:
	$(PY) -m pip install -e ".[dev,live]"

test:
	$(PY) -m pytest tests/ -q

lint:
	ruff check boundsec tests

demo:
	$(PY) -m boundsec.cli fuzz --target gym:hardened --strategy coverage_guided --budget 400 --verbose

benchmark:
	$(PY) -m boundsec.cli benchmark --profile hardened --budget 400 --seeds 5

experiment-quick:
	$(PY) experiments/run_full_suite.py --budget 300 --seeds 5

experiment:
	$(PY) experiments/run_full_suite.py --budget 600 --seeds 15

figures:
	$(PY) -m boundsec.cli figures results --out figures

clean:
	rm -rf .pytest_cache **/__pycache__ *.egg-info build dist
