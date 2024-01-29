  # asfquart - a Quart framework for the ASF
  ![Unit Tests](https://github.com/apache/infrastructure-asfquart/actions/workflows/unit-tests.yml/badge.svg)
  
  This repository will house the future [Quart](https://github.com/pallets/quart/) framework for use 
  within ASF web applications. Nothing much to see here yet...

  
## Primer

~~~python
import asfquart
import asfquart.auth
import asfquart.generics

def my_app():
    asfquart.construct("my_app_service")
    asfquart.generics.setup_oauth()   # Sets up /auth for OAuth handling
    asfquart.generics.enforce_login() # If not logged in, redirect to the above default login flow

    @asfquart.APP.route("/")
    async def homepage():
        return "Hello!"

    @asfquart.APP.route("/secret")
    @asfquart.auth.require(asfquart.auth.Requirements.committer)
    async def secret_page():
      return "Secret stuff!"
    
    asfquart.APP.run(port=8000)


if __name__ == "__main__":
    my_app()

~~~