# asfquart - a Quart framework for the ASF
![Unit Tests](https://github.com/apache/infrastructure-asfquart/actions/workflows/unit-tests.yml/badge.svg)
  
This is a [Quart](https://github.com/pallets/quart/) framework for ASF web applications.

## Primer

See the [documentation page](docs/readme.md) for more information.

~~~python
import asfquart
from asfquart.auth import Requirements as R

def my_app():
    # Construct the quart service. By default, the oauth gateway is enabled at /oauth.
    app = asfquart.construct("my_app_service")

    @app.route("/")
    async def homepage():
        return "Hello!"

    @app.route("/secret")
    @asfquart.auth.require(R.committer)
    async def secret_page():
      return "Secret stuff!"
    
    asfquart.APP.run(port=8000)


if __name__ == "__main__":
    my_app()

~~~

## Running unit tests for asfquart

To run manually, use the following commands from the root dir of this repo:

~~~shell
poetry run pytest
~~~
