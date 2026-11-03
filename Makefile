.PHONY: demo test lint report

demo:
	python -m uvicorn shieldgate.api:app --host 127.0.0.1 --port 8000

test:
	python -m pytest -q --cov=shieldgate --cov-report=term-missing

lint:
	python -m ruff check src redteam tests
	python -m mypy src redteam

report:
	python -m redteam.runner --report
