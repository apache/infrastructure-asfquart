#!/usr/bin/env python3

import sys
sys.path.extend(('src', '../src',))  # Depending on where unit tests are run from, path may differ

import pytest
import time
import quart
import asfquart


@pytest.mark.asyncio
@pytest.mark.session
async def test_sessions():
    asfquart.construct("foobar")
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "uid": "bar"}}
    my_session = await asfquart.session.read()
    assert my_session, "Was expecting a session, but got nothing in return"
    assert my_session.uid == "bar", f"session value 'uid' should be 'bar', but wasn't"
