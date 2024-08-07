  # asfquart - a Quart framework for the ASF
  ![Unit Tests](https://github.com/apache/infrastructure-asfquart/actions/workflows/unit-tests.yml/badge.svg)
  
  This repository will house the future [Quart](https://github.com/pallets/quart/) framework for use 
  within ASF web applications. Nothing much to see here yet...

  For more detailed documentation, see the [documentation page](docs/readme.md).
  
## Primer

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
