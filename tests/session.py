#!/usr/bin/env python3

import time

import pytest
import quart
import asfquart


@pytest.mark.session
async def test_sessions():
    app = asfquart.construct("foobar", token_file=None)
    quart.session = {app.app_id: {"uts": time.time(), "uid": "bar"}}
    my_session = await asfquart.session.read()
    assert my_session, "Was expecting a session, but got nothing in return"
    assert my_session.uid == "bar", f"session value 'uid' should be 'bar', but was '{my_session.uid}'"


@pytest.mark.session
async def test_bearer_token_is_not_logged(caplog, capsys):
    """Without a token handler, a bearer token gives no session, and the token itself is not printed or logged."""
    app = asfquart.construct("bearer_no_handler", token_file=None)
    token = "sekrit-token-value"
    async with app.test_request_context("/", headers={"Authorization": f"Bearer {token}"}):
        assert await asfquart.session.read() is None
    captured = capsys.readouterr()
    assert token not in captured.out
    assert token not in captured.err
    assert token not in caplog.text
    assert "no token handler is registered" in caplog.text
