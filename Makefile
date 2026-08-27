.PHONY: check format test

check:
	.venv/bin/ruff check src tests neurons
	.venv/bin/ruff format --check src tests neurons
	.venv/bin/pytest

format:
	.venv/bin/ruff check --fix src tests neurons
	.venv/bin/ruff format src tests neurons

test:
	.venv/bin/pytest
