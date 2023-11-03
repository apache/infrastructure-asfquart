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
app_dir = pathlib.Path(__main__.__file__).parent

# Unique App ID for this file path on this hostname.
# Used to distinguish two separate asfquart apps running on the same hostname
app_id = hashlib.sha224(bytes(app_dir)).hexdigest()[:16]

# Read, or set and write, the application secret token for session encryption.
# We prefer permanence for the session encryption, but will fall back to a new secret if we
# cannot write a permanent token to disk...with a warning!
app_secret = secrets.token_hex()
token_filename = app_dir / "apptoken.txt"
if os.path.isfile(token_filename):  # Token file exists, try to read it
    app_secret = open(token_filename).read()
else:  # No token file yet, try to write, warn if we cannot
    try:
        with open(token_filename, "w") as f:
            f.write(app_secret)
    except PermissionError:
        sys.stderr.write(
            f"ASFQuart: Could not open {token_filename} for writing. Session permanence cannot be guaranteed!"
        )
