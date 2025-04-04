#!/usr/bin/env python3
"""Simple ASFQuart server example - one file for everything"""

import asfquart
import asfquart.auth
import asfquart.generics
import asfquart.session


def my_app() -> asfquart.base.QuartApp:
    # Construct the base app. The /oauth gateway is enabled by default.
    # To disable it, use construct("my_app", oauth=False)
    app = asfquart.construct("my_simple_app", cfg_file="config.yaml")

    # Default homepage
    @app.route("/")
    async def homepage():
        return "Hello!"

    # the /secret URI, which shows the session data or forces a login
    @app.route("/secret")
    @asfquart.auth.require(asfquart.auth.Requirements.committer)
    async def secret_page():
        return await asfquart.session.read()

    # Authentication failures redirect to login flow.
    asfquart.generics.enforce_login(app)

    # Print some message to indicate that the application has been loaded.
    print(f"Loaded app '{app.name}'.")
    return app


if __name__ == "__main__":
    app = my_app()

    # Run the application in an extended debug mode:
    #  - reload the app when any source / config file get changed
    app.runx(port=8000)
else:
    # Serve the application via an ASGI server, e.g. hypercorn
    app = my_app()
