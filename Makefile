.PHONY: example-dev example-run

example-dev:
	@poetry run python3 examples/snippets/simple_app.py

example-run:
	@poetry run hypercorn examples.snippets.simple_app:app
