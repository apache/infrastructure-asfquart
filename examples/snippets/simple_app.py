#!/usr/bin/env python3
"""Simple ASFQuart server example - one file for everything"""

import asfquart
import asfquart.auth
import asfquart.generics
import asfquart.session

def my_app():
    asfquart.construct("my_simple_app")
    asfquart.generics.setup_oauth()  # Sets up /auth for OAuth handling

    # Default homepage
    @asfquart.APP.route("/")
    async def homepage():
        return "Hello!"

    # the /secret URI, which shows the session data or forces a login
    @asfquart.APP.route("/secret")
    @asfquart.auth.require(asfquart.auth.Requirements.committer)
    async def secret_page():
        return await asfquart.session.read()

    asfquart.generics.enforce_login()

    asfquart.APP.run(port=8000)

if __name__ == "__main__":
    my_app()
