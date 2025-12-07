.PHONY: example-dev example-run

example-dev:
	@uv run examples/snippets/simple_app.py

example-run:
	@uv run hypercorn examples.snippets.simple_app:app
