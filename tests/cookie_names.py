#!/usr/bin/env python3
"""Tests for the names of asfquart's two cookies, which have the __Host- prefix (docs/sessions.md)"""

import itertools
import urllib.parse

import pytest
import quart.testing.app

import asfquart
import asfquart.generics

GOOD_OAUTH_DATA = {"uid": "testuser", "fullname": "Test User", "email": "testuser@apache.org"}

_counter = itertools.count()


def _make_app():
    return asfquart.construct(f"test_cookie_names_{next(_counter)}", token_file=None)


class _FakeProvider:
    """Stands in for aiohttp.client.ClientSession: answers every code with the same user"""

    def __init__(self, data):
        self.data = data

    def __call__(self, timeout=None, **kwargs):  # ClientSession(timeout=...)
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    status = 200

    async def post(self, url, data=None, **kwargs):
        return self

    async def json(self):
        return self.data


async def _login_and_call_back(app, monkeypatch, provider, scheme="https"):
    """Starts a login, then makes the callback as the same browser. Returns the client, the
    response to the start and the response to the callback."""
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", provider)
    client = app.test_client()
    start = await client.get("/auth?login", scheme=scheme)
    assert start.status_code == 302
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(start.headers["Location"]).query)["state"][0]
    return client, start, await client.get(f"/auth?state={state}&code=abc123", scheme=scheme)


def _cookie(resp, name):
    """The Set-Cookie header for one cookie, split into its name=value and its attributes"""
    (header,) = [value for value in resp.headers.getlist("Set-Cookie") if value.startswith(name + "=")]
    return [part.strip() for part in header.split(";")]


def _fits_host_prefix(parts):
    """What a browser requires of a cookie whose name begins with __Host-"""
    attributes = [part.lower() for part in parts[1:]]
    return "secure" in attributes and "path=/" in attributes and not any(a.startswith("domain") for a in attributes)


@pytest.mark.generics
async def test_login_cookie_has_the_host_prefix_and_what_it_requires():
    assert asfquart.generics.STATE_COOKIE_NAME == "__Host-asfquart-oauth-state"
    app = _make_app()
    resp = await app.test_client().get("/auth?login", scheme="https")
    parts = _cookie(resp, "__Host-asfquart-oauth-state")
    assert _fits_host_prefix(parts)
    assert "HttpOnly" in parts and "SameSite=Lax" in parts


@pytest.mark.generics
async def test_login_cookie_fits_the_prefix_wherever_the_oauth_endpoint_is():
    """The path is / and not that of the endpoint, as it was before, since the prefix requires it"""
    app = asfquart.construct(f"test_cookie_names_{next(_counter)}", token_file=None, oauth="/account/session")
    resp = await app.test_client().get("/account/session?login", scheme="https")
    assert _fits_host_prefix(_cookie(resp, "__Host-asfquart-oauth-state"))


@pytest.mark.generics
async def test_session_cookie_has_the_host_prefix_and_what_it_requires(monkeypatch):
    app = _make_app()
    assert app.config["SESSION_COOKIE_NAME"] == "__Host-session"
    client, _start, resp = await _login_and_call_back(app, monkeypatch, _FakeProvider(dict(GOOD_OAUTH_DATA)))
    assert resp.status_code == 200
    parts = _cookie(resp, "__Host-session")
    assert _fits_host_prefix(parts)
    assert "HttpOnly" in parts and "SameSite=Strict" in parts
    assert not [value for value in resp.headers.getlist("Set-Cookie") if value.startswith("session=")]
    assert (await client.get("/auth", scheme="https")).status_code == 200


@pytest.mark.generics
async def test_session_cookie_under_the_old_name_is_not_read(monkeypatch):
    """A cookie called session is what another host of the site could set, and what 0.1.12 set"""
    app = _make_app()
    _client, _start, resp = await _login_and_call_back(app, monkeypatch, _FakeProvider(dict(GOOD_OAUTH_DATA)))
    value = _cookie(resp, "__Host-session")[0].split("=", 1)[1]
    other = app.test_client()
    other.set_cookie("localhost", "session", value, secure=True)
    assert (await other.get("/auth", scheme="https")).status_code == 404
    other.set_cookie("localhost", "__Host-session", value, secure=True)
    assert (await other.get("/auth", scheme="https")).status_code == 200


@pytest.mark.generics
async def test_login_cookie_under_the_old_name_does_not_complete_a_login(monkeypatch):
    """The browser's part in a login is read from the __Host- cookie only"""
    app = _make_app()
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", _FakeProvider(dict(GOOD_OAUTH_DATA)))
    resp = await app.test_client().get("/auth?login", scheme="https")
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(resp.headers["Location"]).query)["state"][0]
    browser = _cookie(resp, "__Host-asfquart-oauth-state")[0].split("=", 1)[1]
    other = app.test_client()
    other.set_cookie("localhost", "asfquart-oauth-state", browser, secure=True)
    assert (await other.get(f"/auth?state={state}&code=abc123", scheme="https")).status_code == 403
    # ... and the same browser identifier under the right name would have done
    resp = await app.test_client().get("/auth?login", scheme="https")
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(resp.headers["Location"]).query)["state"][0]
    browser = _cookie(resp, "__Host-asfquart-oauth-state")[0].split("=", 1)[1]
    other = app.test_client()
    other.set_cookie("localhost", "__Host-asfquart-oauth-state", browser, secure=True)
    assert (await other.get(f"/auth?state={state}&code=abc123", scheme="https")).status_code == 200


@pytest.mark.generics
async def test_cookie_names_can_be_set_back_for_development_over_http(monkeypatch):
    """The way out that docs/sessions.md gives: the old names, without Secure"""
    monkeypatch.setattr(asfquart.generics, "STATE_COOKIE_NAME", "asfquart-oauth-state")
    monkeypatch.setattr(asfquart.generics, "STATE_COOKIE_SECURE", False)
    app = _make_app()
    app.config["SESSION_COOKIE_NAME"] = "session"
    app.config["SESSION_COOKIE_SECURE"] = False
    provider = _FakeProvider(dict(GOOD_OAUTH_DATA))
    client, start, resp = await _login_and_call_back(app, monkeypatch, provider, scheme="http")
    assert "Secure" not in _cookie(start, "asfquart-oauth-state")
    assert resp.status_code == 200
    assert "Secure" not in _cookie(resp, "session")
    assert (await client.get("/auth", scheme="http")).status_code == 200


def test_the_way_out_in_the_documentation_names_the_real_settings():
    """docs/sessions.md shows how to take the prefix off: the names in its example exist"""
    import pathlib

    text = (pathlib.Path(__file__).parent.parent / "docs" / "sessions.md").read_text(encoding="utf-8")
    example = text[text.index("### Developing without HTTPS") :]
    for line in (
        'STATE_COOKIE_NAME = "asfquart-oauth-state"',
        "STATE_COOKIE_SECURE = False",
        '"SESSION_COOKIE_NAME"',
        '"SESSION_COOKIE_SECURE"',
    ):
        assert line in example
    assert hasattr(asfquart.generics, "STATE_COOKIE_NAME") and hasattr(asfquart.generics, "STATE_COOKIE_SECURE")


# ---- An app whose cookies a browser would refuse does not start ----


async def _starts(app):
    async with app.test_app():
        return True


async def test_app_with_the_cookies_as_asfquart_sets_them_starts():
    assert await _starts(_make_app())
    assert await _starts(asfquart.construct(f"test_cookie_names_{next(_counter)}", token_file=None, oauth=False))


SETTINGS_A_BROWSER_REFUSES = {
    "served from a path": ({"APPLICATION_ROOT": "/myapp"}, "has the path '/myapp', not '/'"),
    "a path for the cookie": ({"SESSION_COOKIE_PATH": "/myapp"}, "has the path '/myapp', not '/'"),
    "a domain": ({"SESSION_COOKIE_DOMAIN": "apache.org"}, "has the domain 'apache.org'"),
    "not Secure": ({"SESSION_COOKIE_SECURE": False}, "is not Secure"),
    "prefix in other letters": (
        {"SESSION_COOKIE_NAME": "__host-session", "SESSION_COOKIE_SECURE": False},
        "is named '__host-session' and is not Secure",
    ),
    "__Secure- and not Secure": (
        {"SESSION_COOKIE_NAME": "__Secure-session", "SESSION_COOKIE_SECURE": False},
        "is named '__Secure-session' and is not Secure",
    ),
}


@pytest.mark.parametrize("which", list(SETTINGS_A_BROWSER_REFUSES))
async def test_app_whose_session_cookie_a_browser_would_refuse_does_not_start(which):
    """A browser drops a __Host- cookie that is not Secure, or has a domain, or a path other than
    "/", and says nothing. Nobody could log in, so the app says why and does not start."""
    settings, problem = SETTINGS_A_BROWSER_REFUSES[which]
    app = _make_app()
    app.config.update(settings)  # after construct(), as an app would
    with pytest.raises(quart.testing.app.LifespanError) as excinfo:
        await _starts(app)
    message = str(excinfo.value)
    assert "The session cookie (SESSION_COOKIE_NAME) is named " in message
    assert problem in message
    assert 'See "Cookie names" in docs/sessions.md.' in message


async def test_every_problem_with_the_session_cookie_is_named_at_once():
    app = _make_app()
    app.config.update(APPLICATION_ROOT="/myapp", SESSION_COOKIE_DOMAIN="apache.org", SESSION_COOKIE_SECURE=False)
    with pytest.raises(quart.testing.app.LifespanError) as excinfo:
        await _starts(app)
    for problem in ("is not Secure", "has the path '/myapp'", "has the domain 'apache.org'"):
        assert problem in str(excinfo.value)


SETTINGS_WITHOUT_THE_PREFIX = {
    "served from a path": {"APPLICATION_ROOT": "/myapp"},
    "a domain": {"SESSION_COOKIE_DOMAIN": "apache.org"},
    "not Secure": {"SESSION_COOKIE_SECURE": False},
    "a path, with __Secure-": {"SESSION_COOKIE_NAME": "__Secure-session", "APPLICATION_ROOT": "/myapp"},
}


@pytest.mark.parametrize("which", list(SETTINGS_WITHOUT_THE_PREFIX))
async def test_app_without_the_prefix_may_have_those_settings(which):
    """The rules are the prefix's: under another name the same settings are the app's business"""
    app = _make_app()
    app.config.update({"SESSION_COOKIE_NAME": "session", **SETTINGS_WITHOUT_THE_PREFIX[which]})
    assert await _starts(app)


async def test_app_whose_login_cookie_a_browser_would_refuse_does_not_start(monkeypatch):
    monkeypatch.setattr(asfquart.generics, "STATE_COOKIE_SECURE", False)
    app = _make_app()
    with pytest.raises(quart.testing.app.LifespanError) as excinfo:
        await _starts(app)
    assert (
        "The cookie for a login (generics.STATE_COOKIE_NAME) is named '__Host-asfquart-oauth-state' and is not Secure."
    ) in str(excinfo.value)


async def test_login_cookie_is_not_checked_in_an_app_without_oauth(monkeypatch):
    monkeypatch.setattr(asfquart.generics, "STATE_COOKIE_SECURE", False)
    assert await _starts(asfquart.construct(f"test_cookie_names_{next(_counter)}", token_file=None, oauth=False))


async def test_the_way_out_for_development_starts(monkeypatch):
    """The settings that docs/sessions.md gives for plain HTTP pass the check"""
    monkeypatch.setattr(asfquart.generics, "STATE_COOKIE_NAME", "asfquart-oauth-state")
    monkeypatch.setattr(asfquart.generics, "STATE_COOKIE_SECURE", False)
    app = _make_app()
    app.config["SESSION_COOKIE_NAME"] = "session"
    app.config["SESSION_COOKIE_SECURE"] = False
    assert await _starts(app)
