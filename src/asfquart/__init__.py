#!/usr/bin/env python3

# ensure all submodules are loaded
from . import auth, base, config, session, utils

# This will be rewritten once construct() is called.
APP: base.QuartApp = None  # pyright: ignore[reportAssignmentType] - typed as it is once construct() has run


def app_or_none() -> base.QuartApp | None:
    """The app, or None in a process that has not called construct(). For code that also runs
    where there is no app, such as a worker or a script: APP itself is typed as though it were
    always set."""
    return APP


# Lift the construction from base to the package level.
construct = base.construct
