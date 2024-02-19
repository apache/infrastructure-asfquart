#!/usr/bin/env python3

# ensure all submodules are loaded
from . import config, base, session, utils

# This will be rewritten once construct() is called.
APP = None

# Lift the construction from base to the package level.
construct = base.construct
