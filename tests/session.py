#!/usr/bin/env python3

import sys
sys.path.append(".")

import pytest
import time
import quart
from src import asfquart


@pytest.mark.session
def test_sessions():
    asfquart.init("foobar")
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar"}}
    my_session = asfquart.session.read()
    assert my_session, "Was expecting a session, but got nothing in return"
    assert my_session["foo"] == "bar", f"session value 'foo' should be 'bar', but wasn't"
