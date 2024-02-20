#!/usr/bin/env python3

"""ASFQuart - Base application/event-loop module.

USAGE:

  main.py:
    import asfquart
    APP = asfquart.construct('selfserve')

  anywhere else:
    import asfquart
    APP = asfquart.APP


Quart.app defines a "name" property which can be used as an APP "ID"
(eg. discriminator for cookies). While most Quart apps use the module
name for this (and internally Quart calls this .import_name), it can
be anything and the .name property treats it as arbitrary.
"""

import asyncio
import pathlib
import secrets
import os
import logging

import quart

import __main__

LOGGER = logging.getLogger(__name__)

loop = asyncio.get_event_loop()


class ASFQuartException(Exception):
    """Global ASFQuart exception with a message and an error code, for the HTTP response."""
    def __init__(self, message: str = "An error occurred", errorcode: int = 500):
        self.message = message
        self.errorcode = errorcode
        super().__init__(self.message)


class QuartApp(quart.Quart):
    """Subclass of quart.Quart to include our specific features."""

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        assert len(args) > 0, "You need to specify a name for this quart app"
        # Locate the app dir as best we can. This is used for app ID
        # and token filepath generation
        ### is __main__ module good, and is the __file__ attribute
        ### always present? Do we need some fixes here. Should the
        ### construct() function pass the app_dir?
        self.app_dir = pathlib.Path(__main__.__file__).parent
        self.app_id = args[0]

        # Read, or set and write, the application secret token for
        # session encryption. We prefer permanence for the session
        # encryption, but will fall back to a new secret if we
        # cannot write a permanent token to disk...with a warning!
        _token_filename = self.app_dir / "apptoken.txt"
        if os.path.isfile(_token_filename):  # Token file exists, try to read it
            self.secret_key = open(_token_filename).read()
        else:  # No token file yet, try to write, warn if we cannot
            self.secret_key = secrets.token_hex()
            ### TBD: throw the PermissionError once we stabilize how to locate
            ### the APP directory (which can be thrown off during testing)
            try:
                with open(_token_filename, "w") as f:
                    f.write(self.secret_key)
            except PermissionError:
                LOGGER.error(
                    f"Could not open {_token_filename} for writing. Session permanence cannot be guaranteed!"
                )


def construct(name, *args, **kw):
    ### add/alter/update ARGS and KW for our specific preferences

    global APP
    APP = QuartApp(name, *args, **kw)

    @APP.errorhandler(ASFQuartException)  # ASFQuart exception handler
    async def handle_exception(error):
        # If an error is thrown before the request body has been consumed, eat it quietly.
        if not quart.request.body._complete.is_set():
            async for _data in quart.request.body:
                pass
        return quart.Response(status=error.errorcode, response=error.message)

    # Now stash this into the package module, for later pick-up.
    import asfquart
    import asfquart.utils
    APP.url_map.converters['filename'] = asfquart.utils.FilenameConverter
    asfquart.APP = APP
    return APP
