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

**An asfquart application runs as one process.** Serve it with one worker, and run one
instance of it. Logins in progress and the application secret are not shared between
processes, so more than one worker, or several instances behind a load balancer, will fail in
ways that are hard to see. [One process](docs/one-process.md) explains what assumes this, and
what would have to change to lift it.

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

Note: LDAP is used only for HTTP Basic authentication, which is off by default (see
[docs/sessions.md](docs/sessions.md#http-basic-authentication)). An application that turns it on
needs the `[aioldap]` extra, which has additional
[system dependencies](https://github.com/noirello/bonsai?tab=readme-ov-file#requirements-for-building):

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

Linting and formatting, with the rules in `pyproject.toml`:

```shell
uv run --group lint ruff check
uv run --group lint ruff format
uv run --group lint pyright
```

Building the package:

```shell
uv build
```

### Keeping your branch up to date

`main` has no merge commits, which are the commits that `git merge` and a plain `git pull` make
when they join two lines of work. GitHub refuses any push to `main` that contains one, and the
checks fail on any pull request that contains one.

So never merge `main` into your branch. To catch up, move your commits on top of the latest
`main`, then replace your branch on GitHub:

```shell
git pull --rebase origin main
git push --force-with-lease
```

The button on a pull request page that updates the branch merges by default, so if you use it,
choose its rebase option instead. If you push to `main` directly, run
`git config pull.rebase true` once, so that `git pull` never makes a merge commit.

The same two commands fix a pull request whose checks fail with "merge commits are not allowed,
so rebase instead". They also fix one that was started during a release and fails the version
check, once the release has finished.

## Releasing

Releases are numbered `0.2.N`. Between releases, the version on `main` is that of the next
release with `.dev0+dev` appended, such as `0.2.0.dev0+dev` before 0.2.0. The `+dev` makes it a
local version, which PyPI will not accept, so a build from source can never be published as a
release.

Before a release, check that `CHANGELOG.md` has a section for it, such as "Changes in 0.2.0:".
Then run `sh scripts/phase.sh release` on an up to date `main`. It changes the version from
`0.2.N.dev0+dev` to `0.2.N`, commits, tags that commit `v0.2.N`, and pushes the commit and the
tag together. The upload to PyPI waits until two members of the `tooling` or `infrastructure`
LDAP service groups approve it at https://releases.apache.org/gates. Only members of those
groups can start a release. If anyone else pushes the tag, ATR rejects the run, and a member can
re-run it.

Straight afterwards, before anything else is merged, run `sh scripts/phase.sh develop` to change
the version to `0.2.(N+1).dev0+dev`, commit, and push.

If a release does not go through, because the checks fail on the tag or it is not approved, its
number is spent: a `v` tag can be neither deleted nor moved. Run `sh scripts/phase.sh develop`
as usual, fix what was wrong, and release the next number.

If something was merged after `release` and before `develop`, `develop` refuses, as the latest
commit on `main` is then not the tagged one. Set the version by hand with
`uv version --no-config --no-sync 0.2.(N+1).dev0+dev`, commit, and push.

To start a new series, such as 0.3, change `series` in `scripts/phase.sh` and `_SERIES` in
`scripts/check_version.py`, and run `uv version --no-config --no-sync 0.3.0.dev0+dev`, all in
one commit.

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
