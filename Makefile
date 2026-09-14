.PHONY: install test lint golden clean

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

test:
	.venv/bin/pytest -q

lint:
	.venv/bin/ruff check .

golden:
	.venv/bin/python tools/regen_golden.py

clean:
	rm -rf .pytest_cache .ruff_cache **/__pycache__
