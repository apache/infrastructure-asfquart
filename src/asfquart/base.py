#!/usr/bin/env python3

"""ASFQuart - Base loop module"""

import asyncio
import hashlib
import pathlib
import secrets
import os
import sys
import quart

import __main__


loop = asyncio.get_event_loop()

# Locate the app dir as best we can. This is used for app ID and token filepath generation
APP_DIR = pathlib.Path(__main__.__file__).parent

# Read, or set and write, the application secret token for session encryption.
# We prefer permanence for the session encryption, but will fall back to a new secret if we
# cannot write a permanent token to disk...with a warning!
_token_filename = APP_DIR / "apptoken.txt"
if os.path.isfile(_token_filename):  # Token file exists, try to read it
    APP_SECRET = open(_token_filename).read()
else:  # No token file yet, try to write, warn if we cannot
    APP_SECRET = secrets.token_hex()
    ### TBD: throw the PermissionError once we stabilize how to locate
    ### the APP directory (which can be thrown off during testing)
    try:
        with open(_token_filename, "w") as f:
            f.write(APP_SECRET)
    except PermissionError:
        sys.stderr.write(
            f"ASFQuart: Could not open {_token_filename} for writing. Session permanence cannot be guaranteed!"
        )


class QuartApp(quart.Quart):
    """Sub-class of quart.Quart with an additional init function for handling session identifiers and secrets"""
    def __init__(self):
        super().__init__(__name__)
        self._app_id = None

        @self.before_serving
        async def validate_app_id():
            if not self._app_id:
                raise ValueError("App ID has not been set! Call asfquart.init(name) prior to running the app.")

    @property
    def app_id(self):
        if not self._app_id:
            raise ValueError("No App ID set yet!")
        return self._app_id

    def init(self, name: str):
        """Sets up the name of the quart app and its session secrets"""
        assert name, "The Quart app must have a non-empty name set!"
        self._app_id = name
        self.secret_key = APP_SECRET


if hasattr(__main__, "__file__"):
    APP = QuartApp()
else:
    APP = None
