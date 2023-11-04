#!/usr/bin/env python3

"""ASFQuart - Base loop module"""

import asyncio
import hashlib
import pathlib
import secrets
import os
import sys

import __main__


loop = asyncio.get_event_loop()

# Locate the app dir as best we can. This is used for app ID and token filepath generation
APP_DIR = pathlib.Path(__main__.__file__).parent

# Unique App ID for this file path on this hostname.
# Used to distinguish two separate asfquart apps running on the same hostname
COOKIE_ID = hashlib.sha224(bytes(APP_DIR)).hexdigest()[:16]

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
