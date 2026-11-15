#!/usr/bin/env python3
"""Tests for generics.py — redirect URI validation (CWE-601, CWE-79)"""

import asyncio
import itertools
import urllib.parse

import aiohttp
import pytest

import asfquart


# Counter for unique app names to avoid duplicate route registration
_counter = itertools.count()


def _make_app():
    """Create a minimal Quart app with the OAuth endpoint for testing.
    asfquart.construct() calls setup_oauth() internally when oauth=True (the default),
    so we do NOT call setup_oauth() again here.
    """
    name = f"test_generics_{next(_counter)}"
    app = asfquart.construct(name, token_file=None)
    return app


# ---- Endpoint integration tests ----

@pytest.mark.generics
async def test_login_with_valid_redirect():
    """?login=/dashboard should initiate OAuth flow (302 to oauth.apache.org)."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=/dashboard")
        assert resp.status_code == 302
        location = resp.headers.get("Location", "")
        assert "oauth.apache.org" in location


@pytest.mark.generics
async def test_login_bare():
    """Bare ?login (no redirect value) should initiate OAuth flow normally."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login")
        assert resp.status_code == 302
        location = resp.headers.get("Location", "")
        assert "oauth.apache.org" in location


@pytest.mark.generics
async def test_login_rejects_javascript_uri():
    """?login=javascript:... must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=javascript:alert(1)")
        assert resp.status_code == 400
        body = (await resp.get_data()).decode()
        assert "Invalid redirect" in body


@pytest.mark.generics
async def test_login_rejects_absolute_url():
    """?login=https://evil.com must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=https://evil.com")
        assert resp.status_code == 400


@pytest.mark.generics
async def test_login_rejects_protocol_relative():
    """?login=//evil.com must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=//evil.com")
        assert resp.status_code == 400


@pytest.mark.generics
async def test_login_rejects_data_uri():
    """?login=data:text/html,... must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=data:text/html,<script>alert(1)</script>")
        assert resp.status_code == 400


@pytest.mark.generics
async def test_logout_rejects_javascript_uri():
    """?logout=javascript:... must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?logout=javascript:alert(1)")
        assert resp.status_code == 400
        body = (await resp.get_data()).decode()
        assert "Invalid redirect" in body


@pytest.mark.generics
async def test_logout_rejects_absolute_url():
    """?logout=https://evil.com must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?logout=https://evil.com")
        assert resp.status_code == 400


@pytest.mark.generics
async def test_logout_bare():
    """Bare ?logout (no redirect value) should clear session and return 200."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?logout")
        assert resp.status_code == 200
        body = (await resp.get_data()).decode()
        assert "goodbye" in body.lower()


@pytest.mark.generics
async def test_logout_post():
    """Bare POST ?logout should clear session and return 204 with no body."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.post("/auth?logout")
        assert resp.status_code == 204
        body = (await resp.get_data()).decode()
        assert body == ""


@pytest.mark.generics
async def test_logout_with_valid_redirect():
    """?logout=/goodbye should clear session and redirect."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?logout=/goodbye")
        assert resp.status_code == 302
        location = resp.headers.get("Location", "")
        assert "/goodbye" in location


@pytest.mark.generics
async def test_no_session_returns_404():
    """Bare /auth with no session should return 404."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth")
        assert resp.status_code == 404


# ---- Redirect targets that a browser would take off-site, or that would split a header ----

UNSAFE_REDIRECTS = [
    "/%5Cevil.com",       # /\evil.com: browsers read the backslash as a forward slash
    "/%5C%5Cevil.com",    # /\\evil.com
    "/foo%5Cbar",         # a backslash anywhere in the target
    "/%09/evil.com",      # browsers drop tabs from a URL, leaving //evil.com
    "/foo%0D%0ASet-Cookie:%20a=b",  # CRLF
    "/foo%0Abar",         # bare LF
    "/foo%00bar",         # NUL
    "/foo%7Fbar",         # DEL
]


@pytest.mark.generics
@pytest.mark.parametrize("target", UNSAFE_REDIRECTS)
async def test_login_rejects_unsafe_redirect(target):
    """?login=<unsafe target> must return 400 and must not start a login."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get(f"/auth?login={target}")
        assert resp.status_code == 400
        assert "Invalid redirect" in (await resp.get_data()).decode()
        assert "Location" not in resp.headers


@pytest.mark.generics
@pytest.mark.parametrize("target", UNSAFE_REDIRECTS)
async def test_logout_rejects_unsafe_redirect(target):
    """?logout=<unsafe target> must return 400 and must not redirect."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get(f"/auth?logout={target}")
        assert resp.status_code == 400
        assert "Invalid redirect" in (await resp.get_data()).decode()
        assert "Location" not in resp.headers


@pytest.mark.generics
async def test_login_accepts_path_with_query():
    """A local path with a query string and percent-encoded characters is still accepted."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=/foo/bar%3Fa%3Db%26c%3D%2520d")
        assert resp.status_code == 302


# ---- The callback: exchanging the code with the OAuth provider ----

GOOD_OAUTH_DATA = {"uid": "testuser", "fullname": "Test User", "email": "testuser@apache.org"}


class _FakeProvider:
    """Stands in for aiohttp.client.ClientSession, and records how it was used."""

    def __init__(self, status=200, data=None, error=None):
        self.status = status
        self.data = data
        self.error = error
        self.urls = []
        self.timeouts = []

    def __call__(self, timeout=None, **kwargs):  # ClientSession(timeout=...)
        self.timeouts.append(timeout)
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        self.urls.append(url)
        if self.error is not None:
            raise self.error
        return self

    async def json(self):
        if isinstance(self.data, Exception):
            raise self.data
        return self.data


async def _login_and_call_back(app, monkeypatch, provider, code="abc123", login="/auth?login"):
    """Starts a login, then makes the callback as the same browser. Returns the callback response."""
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", provider)
    client = app.test_client()
    resp = await client.get(login, scheme="https")
    assert resp.status_code == 302
    location = urllib.parse.urlsplit(resp.headers["Location"])
    state = urllib.parse.parse_qs(location.query)["state"][0]
    query = urllib.parse.urlencode({"state": state, "code": code})
    return client, await client.get(f"/auth?{query}", scheme="https")


@pytest.mark.generics
async def test_callback_success(monkeypatch):
    """A good exchange creates the session and greets the user."""
    app = _make_app()
    provider = _FakeProvider(data=dict(GOOD_OAUTH_DATA))
    async with app.test_app():
        client, resp = await _login_and_call_back(app, monkeypatch, provider)
        assert resp.status_code == 200
        assert "Welcome, testuser" in (await resp.get_data()).decode()
        session = await client.get("/auth", scheme="https")
        assert session.status_code == 200
        assert (await session.get_json())["uid"] == "testuser"


@pytest.mark.generics
async def test_callback_redirects_to_recorded_target(monkeypatch):
    """The target given at login ends up in the Refresh header."""
    app = _make_app()
    provider = _FakeProvider(data=dict(GOOD_OAUTH_DATA))
    async with app.test_app():
        _client, resp = await _login_and_call_back(app, monkeypatch, provider, login="/auth?login=/dashboard")
        assert resp.status_code == 200
        assert resp.headers["Refresh"] == "0; url=/dashboard"


@pytest.mark.generics
async def test_callback_quotes_code(monkeypatch):
    """The code is percent-encoded, so it cannot add parameters to the exchange request."""
    app = _make_app()
    provider = _FakeProvider(data=dict(GOOD_OAUTH_DATA))
    async with app.test_app():
        _client, resp = await _login_and_call_back(app, monkeypatch, provider, code="a&client_id=evil#/x y?")
        assert resp.status_code == 200
    assert len(provider.urls) == 1
    query = urllib.parse.urlsplit(provider.urls[0]).query
    assert query == "code=a%26client_id%3Devil%23%2Fx%20y%3F"
    assert urllib.parse.parse_qs(query) == {"code": ["a&client_id=evil#/x y?"]}


@pytest.mark.generics
async def test_callback_exchange_is_time_limited(monkeypatch):
    """The exchange has a limit on connecting, on each read, and on the whole."""
    app = _make_app()
    provider = _FakeProvider(data=dict(GOOD_OAUTH_DATA))
    async with app.test_app():
        await _login_and_call_back(app, monkeypatch, provider)
    (timeout,) = provider.timeouts
    assert timeout.total is not None
    assert timeout.connect is not None
    assert timeout.sock_connect is not None
    assert timeout.sock_read is not None
    assert max(timeout.connect, timeout.sock_connect, timeout.sock_read) <= timeout.total <= 60


@pytest.mark.generics
@pytest.mark.parametrize("error", [
    asyncio.TimeoutError(),
    aiohttp.ClientConnectionError("https://oauth.apache.org/token-oidc?code=sekrit"),
])
async def test_callback_exchange_error(monkeypatch, caplog, error):
    """A provider that cannot be reached, or is too slow, is a failed login and not a 500."""
    app = _make_app()
    provider = _FakeProvider(error=error)
    async with app.test_app():
        client, resp = await _login_and_call_back(app, monkeypatch, provider, code="sekrit")
        assert resp.status_code == 403
        assert "OAuth authentication failed" in (await resp.get_data()).decode()
        assert (await client.get("/auth", scheme="https")).status_code == 404
    assert "OAuth code exchange failed" in caplog.text
    assert "sekrit" not in caplog.text


@pytest.mark.generics
async def test_callback_provider_refuses(monkeypatch):
    """A non-200 answer from the provider is a failed login."""
    app = _make_app()
    provider = _FakeProvider(status=401, data=dict(GOOD_OAUTH_DATA))
    async with app.test_app():
        client, resp = await _login_and_call_back(app, monkeypatch, provider)
        assert resp.status_code == 403
        assert (await client.get("/auth", scheme="https")).status_code == 404


@pytest.mark.generics
@pytest.mark.parametrize("data", [
    None,                         # JSON null
    [],                           # not an object
    "testuser",                   # not an object
    {},                           # no uid
    {"fullname": "Test User"},    # no uid
    {"uid": None},
    {"uid": ""},
    {"uid": 12345},               # not a string
    {"uid": ["testuser"]},
    {"uid": "Test User"},         # not the shape of an ASF uid
    {"uid": "testuser\n"},
    {"uid": "testuser,ou=people"},
    {"uid": "-testuser"},
    {"uid": "_testuser"},
    {"uid": "4user"},             # must start with a letter
    {"uid": "ab"},                # at least three characters
    {"uid": "TestUser"},
    {"uid": "test.user"},
    {"uid": "t\u00e9stuser"},
    ValueError("not JSON"),       # body is not JSON
])
async def test_callback_rejects_response_without_valid_uid(monkeypatch, data):
    """No session is created unless the provider's response identifies a user."""
    app = _make_app()
    provider = _FakeProvider(data=data)
    async with app.test_app():
        client, resp = await _login_and_call_back(app, monkeypatch, provider)
        assert resp.status_code == 403
        assert "OAuth authentication failed" in (await resp.get_data()).decode()
        assert (await client.get("/auth", scheme="https")).status_code == 404


@pytest.mark.generics
@pytest.mark.parametrize("uid", ["testuser", "abc", "test-user", "test_user", "user42", "t-_", "t" * 100])
async def test_callback_accepts_asf_uids(monkeypatch, uid):
    app = _make_app()
    provider = _FakeProvider(data={"uid": uid})
    async with app.test_app():
        _client, resp = await _login_and_call_back(app, monkeypatch, provider)
        assert resp.status_code == 200
