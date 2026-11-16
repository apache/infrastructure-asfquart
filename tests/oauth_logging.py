#!/usr/bin/env python3
"""Tests for the login logging hook shown in docs/oauth.md.

asfquart does not log authentication decisions itself; that is left to the application.
These tests keep the documented hook working: if the OAuth endpoint changes in a way that
breaks it, the documentation has to change too."""

import itertools
import logging
import urllib.parse

import pytest
import quart

import asfquart
import asfquart.generics

_counter = itertools.count()


def _make_app():
    """An app with the hook from docs/oauth.md installed"""
    app = asfquart.construct(f"test_oauth_logging_{next(_counter)}", token_file=None)
    log = logging.getLogger("myapp.audit")

    # ---- This is the hook from docs/oauth.md ("Logging logins") ----
    @app.after_request
    async def log_logins(response):
        request = quart.request
        # Only the callback from the OAuth provider is a login decision
        if request.path == "/auth" and "code" in request.args and "state" in request.args:
            if response.status_code == 200:
                session = await asfquart.session.read()
                log.info("login succeeded: uid=%s remote=%s", session.uid, request.remote_addr)
            else:
                log.warning("login failed: status=%s remote=%s", response.status_code, request.remote_addr)
        return response
    # ---- End of the hook ----

    return app


class _FakeProvider:
    """Stands in for aiohttp.client.ClientSession"""

    def __init__(self, status=200, data=None):
        self.status = status
        self.data = data

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        return self

    async def json(self):
        return self.data


async def _start_login(client, target=""):
    """Starts a login, and returns the state that the provider would send back"""
    resp = await client.get(f"/auth?login{target}", scheme="https")
    assert resp.status_code == 302
    location = urllib.parse.urlsplit(resp.headers["Location"])
    return urllib.parse.parse_qs(location.query)["state"][0]


@pytest.mark.generics
@pytest.mark.parametrize("target", ["", "=/dashboard"])
async def test_successful_login_is_logged(monkeypatch, caplog, target):
    caplog.set_level(logging.INFO, logger="myapp.audit")
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", _FakeProvider(data={"uid": "testuser"}))
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        state = await _start_login(client, target)
        assert caplog.records == []  # starting a login is not a decision
        resp = await client.get(f"/auth?state={state}&code=sekrit", scheme="https")
        assert resp.status_code == 200
    (record,) = caplog.records
    assert record.levelno == logging.INFO
    assert "login succeeded: uid=testuser" in record.getMessage()
    assert "sekrit" not in caplog.text
    assert state not in caplog.text


@pytest.mark.generics
async def test_refused_login_is_logged(monkeypatch, caplog):
    """The provider does not accept the code"""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", _FakeProvider(status=401))
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        state = await _start_login(client)
        resp = await client.get(f"/auth?state={state}&code=sekrit", scheme="https")
        assert resp.status_code == 403
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    assert "login failed: status=403" in record.getMessage()
    assert "sekrit" not in caplog.text


@pytest.mark.generics
async def test_login_with_bad_state_is_logged(monkeypatch, caplog):
    """A state that was never issued, and a state replayed from another browser"""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", _FakeProvider(data={"uid": "testuser"}))
    app = _make_app()
    async with app.test_app():
        resp = await app.test_client().get("/auth?state=made-up&code=sekrit", scheme="https")
        assert resp.status_code == 403
        state = await _start_login(app.test_client())
        other_browser = app.test_client()
        resp = await other_browser.get(f"/auth?state={state}&code=sekrit", scheme="https")
        assert resp.status_code == 403
    assert [record.levelno for record in caplog.records] == [logging.WARNING, logging.WARNING]
    assert all("login failed: status=403" in record.getMessage() for record in caplog.records)


@pytest.mark.generics
async def test_other_auth_requests_are_not_logged(caplog):
    """Showing the session, logging out, and a rejected redirect target are not login decisions"""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        assert (await client.get("/auth", scheme="https")).status_code == 404
        assert (await client.get("/auth?logout", scheme="https")).status_code == 200
        assert (await client.get("/auth?login=https://example.org", scheme="https")).status_code == 400
    assert caplog.records == []
