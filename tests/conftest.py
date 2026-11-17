#!/usr/bin/env python3
"""Fixtures for all tests"""

import pytest
import quart
import quart.globals


@pytest.fixture(autouse=True)
def restore_quart_session():
    """Some tests replace quart.session with a session of their own making, to set one up without
    a request. Put the real thing back afterwards. Left in place, that session would be the
    session of every later test in the run, for every client at once, and no test after it would
    exercise the session cookie at all."""
    yield
    quart.session = quart.globals.session
