# asfquart - a Quart framework for the ASF

<a href="https://pypi.org/project/asfquart"><img alt="PyPI" src="https://img.shields.io/pypi/v/asfquart.svg?color=blue&maxAge=600" /></a>
<a href="https://pypi.org/project/asfquart"><img alt="PyPI - Python Versions" src="https://img.shields.io/pypi/pyversions/asfquart.svg?maxAge=600" /></a>
<a href="https://github.com/apache/infrastructure-asfquart/actions/workflows/unit-tests.yml?query=branch%3Amain"><img alt="Unit Tests" src="https://github.com/apache/infrastructure-asfquart/actions/workflows/unit-tests.yml/badge.svg?branch=main" /></a>
<a href="https://github.com/apache/infrastructure-asfquart/blob/main/LICENSE"><img alt="Apache License" src="https://img.shields.io/github/license/apache/infrastructure-asfquart" /></a>

This is a [Quart](https://github.com/pallets/quart/) framework for ASF web applications.

On top of Quart, this package layers a lot of functionality, much of which is specific to
the ASF and its infrastructure and preferred approaches for website application development.

asfquart adds the following items to basic quart:

* simple construction of the `APP`
* default `config.yaml`
* watching the .py and config for changes, to cause a restart/reload
* watch SIGINT to halt and SIGUSR2 to restart/reload
* template watching and rendering for EZT templates
* URL path routing for pages and API endpoints
* Oauth with our ASF provider for authn
* LDAP group testing for authz
* long-running tasks and their lifecycle management

Current (known, public) users of asfquart:

* [Apache Trusted Releases platform](https://github.com/apache/tooling-trusted-releases)
* [Infrastructure's Reporting Dashboard](https://github.com/apache/infrastructure-reporting-dashboard)
* [ASF Self Serve Portal](https://github.com/apache/infrastructure-selfserve-portal)

Future users of asfquart:

* [Apache STeVe](https://github.com/apache/steve)
* [ASF Identity management](https://id.apache.org)
* [ASF GitBox UI](https://gitbox.apache.org/repos/asf)
* others, to be listed

## Primer

See the [documentation page](docs/README.md) for more information.

```python
import asfquart
from asfquart.auth import Requirements as R

def my_app() -> asfquart.base.QuartApp:
    # Construct the quart service. By default, the oauth gateway is enabled at /oauth.
    app = asfquart.construct("my_app_service")

    @app.route("/")
    async def homepage():
        return "Hello!"

    @app.route("/secret")
    @asfquart.auth.require(R.committer)
    async def secret_page():
      return "Secret stuff!"

    return app

if __name__ == "__main__":
    app = my_app()

    # Run the application in an extended debug mode:
    #  - reload the app when any source / config file get changed
    app.runx(port=8000)
else:
    # Serve the application via an ASGI server, e.g. hypercorn
    app = my_app()
```

## Installation

Create and activate a virtual environment and then install `asfquart` using [uv](https://docs.astral.sh/uv/) or [pip](https://pip.pypa.io):

```shell
# With uv
uv add asfquart

# With uv pip-compatible interface
uv pip install asfquart

# With standard pip
pip install asfquart
```

Note: Adding the `[aioldap]` extra will install optional dependencies for LDAP support that will
require additional [system dependencies](https://github.com/noirello/bonsai?tab=readme-ov-file#requirements-for-building):

```shell
# With uv
uv add asfquart --extra aioldap

# With uv pip-compatible interface
uv pip install "asfquart[aioldap]"

# With standard pip
pip install "asfquart[aioldap]"
```

## Development

### Install development environment

Install the required dependencies for development:

```shell
uv sync
```

Install the optional dependencies for development:

```shell
uv sync --extra aioldap
```

### Building asfquart package

Running the tests:

```shell
uv sync --all-extras --group test

uv run pytest
```

Building the package:

```shell
uv build
```

## Examples

There is a simple test application included (`./examples/snippets/simple_app.py`) to outline the basic setup.
To run the application in development mode, type:

```shell
make example-dev
```

to run it with an ASGI server for production, type:

```shell
make example-run
```
