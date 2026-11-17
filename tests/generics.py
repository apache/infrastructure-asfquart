#!/usr/bin/env python3
"""Tests for generics.py — redirect URI validation (CWE-601, CWE-79)"""

import asyncio
import itertools
import ssl
import urllib.parse

import aiohttp
import aiohttp.test_utils
import aiohttp.web
import pytest
import quart

import asfquart
import asfquart.generics


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
    "/foo%C2%85bar",      # U+0085 NEXT LINE, a C1 control
    "/foo%C2%9Fbar",      # U+009F, the last C1 control
    "/foo%E2%80%8Bbar",   # U+200B ZERO WIDTH SPACE, a format character
    "/foo%E2%80%AEbar",   # U+202E RIGHT-TO-LEFT OVERRIDE, a format character
    "/foo%EF%BB%BFbar",   # U+FEFF BYTE ORDER MARK, a format character
    "/foo%EE%80%80bar",   # U+E000, private use
    "/foo%EF%BF%BFbar",   # U+FFFF, unassigned
    "/foo%E2%80%A8bar",   # U+2028 LINE SEPARATOR
    "/foo%E2%80%A9bar",   # U+2029 PARAGRAPH SEPARATOR
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


@pytest.mark.generics
@pytest.mark.parametrize("target", [
    "/caf%C3%A9",                # e with an acute accent
    "/%E6%97%A5%E6%9C%AC",       # CJK
    "/foo%C2%A0bar",             # U+00A0 NO-BREAK SPACE: a separator, but not one that ends a line
    "/foo%20bar",                # a plain space
])
async def test_login_accepts_printable_non_ascii(target):
    """Only the "C" categories and the line separators are refused, not everything outside ASCII."""
    app = _make_app()
    async with app.test_app():
        resp = await app.test_client().get(f"/auth?login={target}")
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
        self.calls = []  # (method, url, form body)
        self.post_kwargs = []
        self.timeouts = []

    def __call__(self, timeout=None, **kwargs):  # ClientSession(timeout=...)
        self.timeouts.append(timeout)
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def _answer(self, method, url, data):
        self.urls.append(url)
        self.calls.append((method, url, data))
        if self.error is not None:
            raise self.error
        return self

    async def get(self, url):
        return self._answer("GET", url, None)

    async def post(self, url, data=None, **kwargs):
        self.post_kwargs.append(kwargs)
        return self._answer("POST", url, data)

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


AWKWARD_CODE = "a&client_id=evil#/x y?"

# The default before #96, which many apps set themselves
OLD_DEFAULT_CALLBACK = "https://oauth.apache.org/token-oidc?code=%s"
# Some other endpoint that takes the code as a %s
LEGACY_CALLBACK = "https://oauth.example.org/token?code=%s"


@pytest.fixture
def callback_url(monkeypatch):
    """Sets OAUTH_URL_CALLBACK for a test, with the warned-once flag reset"""
    def set_url(url):
        monkeypatch.setattr(asfquart.generics, "OAUTH_URL_CALLBACK", url)
    monkeypatch.setattr(asfquart.generics, "_warned_legacy_callback", False)
    return set_url


@pytest.mark.generics
@pytest.mark.parametrize("setting, posted_to", [
    (None, "https://oauth.apache.org/token-oidc"),                  # the default
    ("https://oauth.example.org/token", "https://oauth.example.org/token"),
    (OLD_DEFAULT_CALLBACK, "https://oauth.apache.org/token-oidc"),  # upgraded to the new default
])
async def test_callback_posts_code_in_body(monkeypatch, caplog, callback_url, setting, posted_to):
    """The code goes in a POST body, not the URL (#96)"""
    if setting:
        callback_url(setting)
    app = _make_app()
    provider = _FakeProvider(data=dict(GOOD_OAUTH_DATA))
    async with app.test_app():
        _client, resp = await _login_and_call_back(app, monkeypatch, provider, code=AWKWARD_CODE)
        assert resp.status_code == 200
    assert provider.calls == [("POST", posted_to, {"code": AWKWARD_CODE})]
    assert provider.post_kwargs == [{"allow_redirects": False}]
    assert "OAUTH_URL_CALLBACK" not in caplog.text


@pytest.mark.generics
async def test_exchange_code_over_real_aiohttp(callback_url):
    """Checks what actually goes over the wire - the fake provider only sees the arguments"""
    seen = {}

    async def token(request):
        seen.update(method=request.method, query=request.query_string, form=dict(await request.post()))
        return aiohttp.web.json_response(GOOD_OAUTH_DATA)

    server_app = aiohttp.web.Application()
    server_app.router.add_route("*", "/token", token)
    async with aiohttp.test_utils.TestServer(server_app) as server:
        callback_url(str(server.make_url("/token")))
        async with aiohttp.ClientSession() as session:
            rv = await asfquart.generics._exchange_code(session, AWKWARD_CODE)
            assert rv.status == 200
    assert seen == {"method": "POST", "query": "", "form": {"code": AWKWARD_CODE}}


@pytest.mark.generics
async def test_callback_redirect_is_a_failed_login(monkeypatch, caplog):
    app = _make_app()
    provider = _FakeProvider(status=302, data=None)
    async with app.test_app():
        _client, resp = await _login_and_call_back(app, monkeypatch, provider)
        assert resp.status_code == 403
    assert "OAuth code exchange failed: provider answered with status 302" in caplog.text


@pytest.mark.generics
async def test_callback_legacy_template_uses_get(monkeypatch, caplog, callback_url):
    """Any other endpoint with a %s still gets a GET with the code quoted, and one warning"""
    callback_url(LEGACY_CALLBACK)
    app = _make_app()
    provider = _FakeProvider(data=dict(GOOD_OAUTH_DATA))
    async with app.test_app():
        for _ in range(2):
            _client, resp = await _login_and_call_back(app, monkeypatch, provider, code=AWKWARD_CODE)
            assert resp.status_code == 200
    get = ("GET", "https://oauth.example.org/token?code=a%26client_id%3Devil%23%2Fx%20y%3F", None)
    assert provider.calls == [get, get]
    warnings = [r for r in caplog.records if r.name == "asfquart.generics" and r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert warnings[0].getMessage().startswith("OAUTH_URL_CALLBACK has a %s for the code,")
    assert AWKWARD_CODE not in caplog.text


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
    OSError("could not load the CA store, while exchanging sekrit"),  # not wrapped by aiohttp
    ssl.SSLError("handshake failed for code=sekrit"),
    ConnectionResetError("reset, code=sekrit"),
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
    assert f"OAuth code exchange failed: {type(error).__name__}" in caplog.text
    assert "sekrit" not in caplog.text


@pytest.mark.generics
async def test_callback_ssl_context_error(monkeypatch, caplog):
    """A failure to build the TLS settings is a failed login too, and not a 500."""
    def broken():
        raise OSError("no CA store")
    monkeypatch.setattr(asfquart.generics, "_oauth_ssl_context", broken)
    app = _make_app()
    provider = _FakeProvider(data=dict(GOOD_OAUTH_DATA))
    async with app.test_app():
        client, resp = await _login_and_call_back(app, monkeypatch, provider)
        assert resp.status_code == 403
        assert (await client.get("/auth", scheme="https")).status_code == 404
    assert provider.urls == []  # the provider was never contacted
    assert "OAuth code exchange failed: OSError" in caplog.text


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
@pytest.mark.parametrize("status", [204, 400, 401, 404, 500, 503])
async def test_callback_logs_provider_status(monkeypatch, caplog, status):
    """The status of a provider that does not answer 200 is in the log, to tell what is wrong at its end."""
    app = _make_app()
    provider = _FakeProvider(status=status, data=dict(GOOD_OAUTH_DATA))
    async with app.test_app():
        _client, resp = await _login_and_call_back(app, monkeypatch, provider, code="sekrit")
        assert resp.status_code == 403
    (record,) = [r for r in caplog.records if r.name == "asfquart.generics"]
    assert record.levelname == "WARNING"
    assert record.getMessage() == f"OAuth code exchange failed: provider answered with status {status}"


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
    {"uid": "a"},                 # at least two characters
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
@pytest.mark.parametrize("uid", ["testuser", "abc", "ab", "a1", "test-user", "test_user", "user42", "t-_", "t" * 100])
async def test_callback_accepts_asf_uids(monkeypatch, caplog, uid):
    app = _make_app()
    provider = _FakeProvider(data={"uid": uid})
    async with app.test_app():
        _client, resp = await _login_and_call_back(app, monkeypatch, provider)
        assert resp.status_code == 200
    assert "OAuth code exchange failed" not in caplog.text  # a login that works logs no failure


@pytest.mark.generics
@pytest.mark.parametrize("data, problem", [
    (None, "response is not a JSON object"),
    (["testuser"], "response is not a JSON object"),
    ("testuser", "response is not a JSON object"),
    ({}, "response has no uid"),
    ({"sub": "testuser", "nickname": "testuser"}, "response has no uid"),  # a provider with other field names
    ({"uid": None}, "uid is not a string"),
    ({"uid": 12345}, "uid is not a string"),
    ({"uid": ""}, "uid is not in the form of an ASF user id"),
    ({"uid": "a"}, "uid is not in the form of an ASF user id"),
    ({"uid": "Test User"}, "uid is not in the form of an ASF user id"),
])
async def test_callback_logs_which_check_failed(monkeypatch, caplog, data, problem):
    """The log tells a provider that changed its response from a uid that was turned away."""
    app = _make_app()
    provider = _FakeProvider(data=data)
    async with app.test_app():
        _client, resp = await _login_and_call_back(app, monkeypatch, provider, code="sekrit")
        assert resp.status_code == 403
    (record,) = [r for r in caplog.records if r.name == "asfquart.generics"]
    assert record.levelname == "WARNING"
    assert record.getMessage() == f"OAuth code exchange failed: {problem}"


@pytest.mark.generics
async def test_callback_log_has_no_secrets(monkeypatch, caplog):
    """Neither the code, the state, nor what the provider sent is in the log."""
    app = _make_app()
    provider = _FakeProvider(data={"uid": "Not A Valid Uid", "email": "private@example.org"})
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", provider)
    async with app.test_app():
        client = app.test_client()
        start = await client.get("/auth?login", scheme="https")
        state = urllib.parse.parse_qs(urllib.parse.urlsplit(start.headers["Location"]).query)["state"][0]
        resp = await client.get(f"/auth?state={state}&code=sekrit", scheme="https")
        assert resp.status_code == 403
    assert "OAuth code exchange failed" in caplog.text
    for secret in ("sekrit", state, "Not A Valid Uid", "private@example.org"):
        assert secret not in caplog.text


# ---- The callback: TLS settings for the exchange ----

@pytest.mark.generics
def test_oauth_ssl_context():
    """The provider's certificate and host name are checked, and old TLS versions are refused."""
    ctx = asfquart.generics._oauth_ssl_context()
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


@pytest.mark.generics
async def test_callback_exchange_uses_ssl_context(monkeypatch):
    """The exchange is made over a connection that uses those TLS settings."""
    connectors = []
    sessions = []

    class RecordingConnector:
        def __init__(self, **kwargs):
            connectors.append(kwargs)

    provider = _FakeProvider(data=dict(GOOD_OAUTH_DATA))

    def client_session(**kwargs):
        sessions.append(kwargs)
        return provider(**kwargs)

    app = _make_app()
    monkeypatch.setattr(asfquart.generics.aiohttp, "TCPConnector", RecordingConnector)
    async with app.test_app():
        _client, resp = await _login_and_call_back(app, monkeypatch, client_session)
        assert resp.status_code == 200
    assert connectors == [{"ssl": asfquart.generics._oauth_ssl_context()}]
    assert isinstance(sessions[0]["connector"], RecordingConnector)


# ---- Pending logins: expired ones are removed, and there is a limit to how many are kept ----

def _pending(*ages, now=1000.0):
    """A pending_states dictionary with one login for each age (in seconds), oldest first"""
    return {f"state{index}": [now - age, None, "digest"] for index, age in enumerate(ages)}


class _Clock:
    """Stands in for the time module inside asfquart.generics"""

    def __init__(self, now=1000.0):
        self.now = now

    def time(self):
        return self.now


@pytest.mark.generics
def test_purge_removes_expired_logins(monkeypatch):
    monkeypatch.setattr(asfquart.generics, "time", _Clock())
    pending = _pending(2000, 901, 900, 10, 0)  # with a timeout of 900 seconds, the first two have expired
    evicted = asfquart.generics._purge_pending_states(pending, 900, 100)
    assert list(pending) == ["state2", "state3", "state4"]
    assert evicted == 0


@pytest.mark.generics
def test_purge_keeps_to_the_limit_by_dropping_the_oldest(monkeypatch):
    monkeypatch.setattr(asfquart.generics, "time", _Clock())
    pending = _pending(50, 40, 30, 20, 10)
    evicted = asfquart.generics._purge_pending_states(pending, 900, 3)
    assert list(pending) == ["state2", "state3", "state4"]
    assert evicted == 2


@pytest.mark.generics
def test_purge_counts_only_unexpired_logins_as_evicted(monkeypatch):
    monkeypatch.setattr(asfquart.generics, "time", _Clock())
    pending = _pending(5000, 4000, 30, 20, 10)
    evicted = asfquart.generics._purge_pending_states(pending, 900, 2)
    assert list(pending) == ["state3", "state4"]
    assert evicted == 1


@pytest.mark.generics
@pytest.mark.parametrize("pending", [{}, _pending(10), _pending(30, 20, 10)])
def test_purge_leaves_alone_what_is_within_bounds(monkeypatch, pending):
    monkeypatch.setattr(asfquart.generics, "time", _Clock())
    before = dict(pending)
    assert asfquart.generics._purge_pending_states(pending, 900, 3) == 0
    assert pending == before


@pytest.mark.generics
def test_purge_can_empty_the_dictionary(monkeypatch):
    monkeypatch.setattr(asfquart.generics, "time", _Clock())
    pending = _pending(30, 20, 10)
    assert asfquart.generics._purge_pending_states(pending, 900, 0) == 3
    assert pending == {}


def _make_app_with_limit(max_pending_logins, workflow_timeout=900):
    """An app whose OAuth endpoint is set up by hand, to choose the limits"""
    app = asfquart.construct(f"test_generics_{next(_counter)}", token_file=None, oauth=False)
    asfquart.generics.setup_oauth(app, workflow_timeout=workflow_timeout, max_pending_logins=max_pending_logins)
    return app


def _pending_states_of(app):
    """The pending logins of the app's OAuth endpoint, which it keeps to itself"""
    endpoint = app.view_functions["oauth_endpoint"]
    cells = dict(zip(endpoint.__code__.co_freevars, endpoint.__closure__))
    return cells["pending_states"].cell_contents


async def _start(client):
    """Starts a login, and returns its state"""
    resp = await client.get("/auth?login", scheme="https")
    assert resp.status_code == 302
    return urllib.parse.parse_qs(urllib.parse.urlsplit(resp.headers["Location"]).query)["state"][0]


@pytest.mark.generics
async def test_abandoned_logins_are_removed_once_expired(monkeypatch):
    """Logins that are started and never completed do not stay in memory for ever."""
    clock = _Clock()
    monkeypatch.setattr(asfquart.generics, "time", clock)
    app = _make_app_with_limit(1000)
    async with app.test_app():
        abandoned = [await _start(app.test_client()) for _ in range(5)]
        assert list(_pending_states_of(app)) == abandoned
        clock.now += 899
        fresh = await _start(app.test_client())
        assert len(_pending_states_of(app)) == 6   # none has expired yet
        clock.now += 2
        newest = await _start(app.test_client())
        assert list(_pending_states_of(app)) == [fresh, newest]


@pytest.mark.generics
async def test_callback_removes_expired_logins(monkeypatch):
    """Expired logins also go when a callback arrives, whatever it is for."""
    clock = _Clock()
    monkeypatch.setattr(asfquart.generics, "time", clock)
    app = _make_app_with_limit(1000)
    async with app.test_app():
        for _ in range(5):
            await _start(app.test_client())
        clock.now += 901
        resp = await app.test_client().get("/auth?state=made-up&code=abc", scheme="https")
        assert resp.status_code == 403
        assert _pending_states_of(app) == {}


@pytest.mark.generics
async def test_pending_logins_are_limited(monkeypatch, caplog):
    """With more logins pending than the limit, the oldest is dropped and fails; the others still work."""
    app = _make_app_with_limit(3)
    provider = _FakeProvider(data=dict(GOOD_OAUTH_DATA))
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", provider)
    async with app.test_app():
        clients = [app.test_client() for _ in range(4)]
        states = [await _start(client) for client in clients]
        assert list(_pending_states_of(app)) == states[1:]

        dropped = await clients[0].get(f"/auth?state={states[0]}&code=abc", scheme="https")
        assert dropped.status_code == 403
        assert "Invalid or expired OAuth state" in (await dropped.get_data()).decode()

        for client, state in zip(clients[1:], states[1:]):
            resp = await client.get(f"/auth?state={state}&code=abc", scheme="https")
            assert resp.status_code == 200
        assert _pending_states_of(app) == {}
    warnings = [r for r in caplog.records if r.name == "asfquart.generics" and "pending" in r.getMessage()]
    assert len(warnings) == 1
    assert "More than 3 OAuth logins are pending" in warnings[0].getMessage()
    for state in states:
        assert state not in caplog.text


@pytest.mark.generics
async def test_pending_logins_stay_within_the_limit_under_a_flood(caplog):
    """However many logins are started, no more than the limit are kept, and the log is not flooded too."""
    app = _make_app_with_limit(10)
    async with app.test_app():
        client = app.test_client()
        for _ in range(200):
            await client.get("/auth?login", scheme="https")
            assert len(_pending_states_of(app)) <= 10
    warnings = [r for r in caplog.records if r.name == "asfquart.generics" and "pending" in r.getMessage()]
    assert len(warnings) == 1


@pytest.mark.generics
async def test_no_warning_when_only_expired_logins_are_removed(monkeypatch, caplog):
    clock = _Clock()
    monkeypatch.setattr(asfquart.generics, "time", clock)
    app = _make_app_with_limit(3)
    async with app.test_app():
        for _ in range(3):
            await _start(app.test_client())
            clock.now += 1000   # each has expired by the time the next one starts
    assert len(_pending_states_of(app)) == 1
    assert "pending" not in caplog.text


@pytest.mark.generics
def test_default_limit_on_pending_logins(monkeypatch):
    """The limit is DEFAULT_MAX_PENDING_LOGINS, as it is when the endpoint is set up."""
    assert asfquart.generics.DEFAULT_MAX_PENDING_LOGINS == 10000
    monkeypatch.setattr(asfquart.generics, "DEFAULT_MAX_PENDING_LOGINS", 2)
    app = _make_app()   # set up by asfquart.construct()
    endpoint = app.view_functions["oauth_endpoint"]
    cells = dict(zip(endpoint.__code__.co_freevars, endpoint.__closure__))
    assert cells["max_pending_logins"].cell_contents == 2


@pytest.mark.generics
@pytest.mark.parametrize("limit", [0, -1])
def test_limit_on_pending_logins_must_be_positive(limit):
    app = asfquart.construct(f"test_generics_{next(_counter)}", token_file=None, oauth=False)
    with pytest.raises(ValueError):
        asfquart.generics.setup_oauth(app, max_pending_logins=limit)


# ---- The redirect target of a login is kept in memory, so its length is limited ----

@pytest.mark.generics
@pytest.mark.parametrize("action", ["login", "logout"])
async def test_redirect_target_has_a_maximum_length(action):
    limit = asfquart.generics.MAX_REDIRECT_URI_LENGTH
    assert limit == 2048
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        longest = "/" + "a" * (limit - 1)
        assert (await client.get(f"/auth?{action}={longest}", scheme="https")).status_code == 302
        too_long = await client.get(f"/auth?{action}={longest}a", scheme="https")
        assert too_long.status_code == 400
        assert "Invalid redirect" in (await too_long.get_data()).decode()


@pytest.mark.generics
async def test_too_long_redirect_target_is_not_kept():
    """A login with a target that is refused leaves nothing in memory."""
    app = _make_app_with_limit(10)
    async with app.test_app():
        resp = await app.test_client().get("/auth?login=/" + "a" * 5000, scheme="https")
        assert resp.status_code == 400
    assert _pending_states_of(app) == {}


# ---- The warning says how many logins were dropped ----

def _pending_warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.name == "asfquart.generics" and "pending" in r.getMessage()]


@pytest.mark.generics
async def test_warning_counts_the_logins_that_were_dropped(monkeypatch, caplog):
    """One warning a minute at most, and each says how many logins were dropped since the one before:
    a single burst is one warning with a small number, and lasting pressure is one every minute."""
    clock = _Clock()
    monkeypatch.setattr(asfquart.generics, "time", clock)
    app = _make_app_with_limit(10)
    async with app.test_app():
        client = app.test_client()
        for _ in range(11):                                  # the eleventh drops one
            await client.get("/auth?login", scheme="https")
        assert _pending_warnings(caplog) == [
            "More than 10 OAuth logins are pending; 1 dropped since the last warning, oldest first."
            " A dropped login fails if its user completes it"
        ]
        for _ in range(50):                                  # within the minute: counted, not logged
            await client.get("/auth?login", scheme="https")
        assert len(_pending_warnings(caplog)) == 1
        clock.now += 61
        await client.get("/auth?login", scheme="https")
        assert len(_pending_warnings(caplog)) == 2
        assert "; 51 dropped since the last warning" in _pending_warnings(caplog)[1]
        # A warning goes out with the first drop after a minute; later drops wait for the next one
        clock.now += 61
        for _ in range(3):
            await client.get("/auth?login", scheme="https")
        assert len(_pending_warnings(caplog)) == 3
        assert "; 1 dropped since the last warning" in _pending_warnings(caplog)[2]
        clock.now += 61
        await client.get("/auth?login", scheme="https")
        assert "; 3 dropped since the last warning" in _pending_warnings(caplog)[3]


@pytest.mark.generics
async def test_no_warning_once_nothing_is_being_dropped(monkeypatch, caplog):
    """The count is not carried over into a warning when the drops have stopped and the rest expired."""
    clock = _Clock()
    monkeypatch.setattr(asfquart.generics, "time", clock)
    app = _make_app_with_limit(10)
    async with app.test_app():
        client = app.test_client()
        for _ in range(11):
            await client.get("/auth?login", scheme="https")
        assert len(_pending_warnings(caplog)) == 1
        clock.now += 1000                                    # all of them expire
        for _ in range(5):
            await client.get("/auth?login", scheme="https")  # only expired logins are removed now
        assert len(_pending_warnings(caplog)) == 1


# ---- The callback URL sent to the OAuth provider (#93) ----

async def _callback_url(app, host):
    """Starts a login as a request for the given Host, and returns the callback URL sent to the provider"""
    resp = await app.test_client().get("/auth?login", scheme="https", headers={"Host": host})
    assert resp.status_code == 302
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(resp.headers["Location"]).query)
    return urllib.parse.urlsplit(query["redirect_uri"][0])


@pytest.mark.generics
async def test_callback_url_follows_host_header_by_default():
    app = _make_app()
    async with app.test_app():
        callback = await _callback_url(app, "myapp.apache.org")
    assert (callback.scheme, callback.netloc, callback.path) == ("https", "myapp.apache.org", "/auth")


def _make_app_with_callback_host(callback_host):
    """An app that calls setup_oauth() itself, to pass callback_host"""
    app = asfquart.construct(f"test_generics_{next(_counter)}", token_file=None, oauth=False)
    asfquart.generics.setup_oauth(app, callback_host=callback_host)
    return app


@pytest.mark.generics
@pytest.mark.parametrize("setting, netloc", [
    ("https://myapp.apache.org", "myapp.apache.org"),
    ("https://myapp.apache.org/", "myapp.apache.org"),
    ("https://localhost.apache.org:8080", "localhost.apache.org:8080"),
])
@pytest.mark.parametrize("how", ["parameter", "module default"])
async def test_callback_url_uses_configured_host(monkeypatch, setting, netloc, how):
    """With a callback host set, the Host header has no say in the callback URL"""
    if how == "parameter":
        app = _make_app_with_callback_host(setting)
    else:
        monkeypatch.setattr(asfquart.generics, "OAUTH_CALLBACK_HOST", setting)
        app = _make_app()
    async with app.test_app():
        callback = await _callback_url(app, "evil.example.org")
    assert (callback.scheme, callback.netloc, callback.path) == ("https", netloc, "/auth")
    assert list(urllib.parse.parse_qs(callback.query)) == ["state"]


@pytest.mark.generics
async def test_callback_host_parameter_wins_over_module_default(monkeypatch):
    monkeypatch.setattr(asfquart.generics, "OAUTH_CALLBACK_HOST", "https://default.apache.org")
    app = _make_app_with_callback_host("https://myapp.apache.org")
    async with app.test_app():
        callback = await _callback_url(app, "evil.example.org")
    assert callback.netloc == "myapp.apache.org"


@pytest.mark.generics
@pytest.mark.parametrize("setting", [
    "http://myapp.apache.org",           # not https
    "myapp.apache.org",                  # no scheme
    "https://",                          # no host
    "https://myapp.apache.org/app",      # a path
    "https://myapp.apache.org?x=1",      # a query string
    "https://myapp.apache.org#frag",     # a fragment
    "https://user:pw@myapp.apache.org",  # userinfo
    "https://myapp.apache.org:notaport",
    "https://myapp.apache.org\\@evil.example",
    "https://my app.apache.org",
    "https://myapp.apache.org\n",
    "https://[::1]",                     # IPv6 literals aren't supported
    b"https://myapp.apache.org",         # not a string
])
def test_callback_host_is_validated(monkeypatch, setting):
    """A bad callback host stops the app from starting, however it was set"""
    with pytest.raises(ValueError, match="callback host"):
        _make_app_with_callback_host(setting)
    monkeypatch.setattr(asfquart.generics, "OAUTH_CALLBACK_HOST", setting)
    with pytest.raises(ValueError, match="callback host"):
        _make_app()


@pytest.mark.generics
async def test_callback_host_set_after_setup_still_applies(monkeypatch, caplog):
    """The module default is read at each login, so setting it late isn't silently ignored"""
    app = _make_app()
    async with app.test_app():
        monkeypatch.setattr(asfquart.generics, "OAUTH_CALLBACK_HOST", "https://myapp.apache.org")
        callback = await _callback_url(app, "evil.example.org")
        assert callback.netloc == "myapp.apache.org"

        # A bad value fails the login - it doesn't fall back to the Host header
        monkeypatch.setattr(asfquart.generics, "OAUTH_CALLBACK_HOST", "http://myapp.apache.org")
        resp = await app.test_client().get("/auth?login", scheme="https")
    assert resp.status_code == 500
    assert "Location" not in resp.headers
    assert "callback host must be https://" in caplog.text


# ---- Referrer-Policy on URLs with a code ----

@pytest.mark.generics
@pytest.mark.parametrize("login, provider_args, status", [
    ("/auth?login", {"data": dict(GOOD_OAUTH_DATA)}, 200),               # logged in
    ("/auth?login=/dashboard", {"data": dict(GOOD_OAUTH_DATA)}, 200),    # logged in, with a Refresh
    ("/auth?login", {"status": 404, "data": None}, 403),                 # provider refused the code
])
async def test_callback_sends_no_referrer(monkeypatch, login, provider_args, status):
    app = _make_app()
    provider = _FakeProvider(**provider_args)
    async with app.test_app():
        _client, resp = await _login_and_call_back(app, monkeypatch, provider, login=login)
        assert resp.status_code == status
        assert resp.headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.generics
@pytest.mark.parametrize("method, url, headers, status", [
    ("GET", "/auth?state=notpending&code=abc123", {}, 403),                              # bad state
    ("GET", "/auth?code=abc123", {}, 404),                                               # no state
    ("POST", "/auth?state=notpending&code=abc123", {"Sec-Fetch-Site": "cross-site"}, 403),  # CSRF check
])
async def test_refused_request_with_code_sends_no_referrer(method, url, headers, status):
    app = _make_app()
    async with app.test_app():
        resp = await app.test_client().open(url, method=method, scheme="https", headers=headers)
        assert resp.status_code == status
        assert resp.headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.generics
async def test_callback_error_sends_no_referrer(monkeypatch):
    """Even a 500 has the header"""
    async def broken(_data):
        raise RuntimeError("could not write the session")
    monkeypatch.setattr(asfquart.session, "awrite", broken)
    app = _make_app()
    app.config["PROPAGATE_EXCEPTIONS"] = False
    provider = _FakeProvider(data=dict(GOOD_OAUTH_DATA))
    async with app.test_app():
        _client, resp = await _login_and_call_back(app, monkeypatch, provider)
        assert resp.status_code == 500
        assert resp.headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.generics
@pytest.mark.parametrize("url", ["/auth", "/auth?login", "/auth?logout"])
async def test_no_referrer_policy_without_a_code(url):
    app = _make_app()
    async with app.test_app():
        resp = await app.test_client().get(url, scheme="https")
        assert "Referrer-Policy" not in resp.headers


# ---- Requests that change state: logout by POST (#69) ----

def _make_app_with_logout_by_get(logout_by_get):
    """An app that calls setup_oauth() itself, to pass logout_by_get"""
    app = asfquart.construct(f"test_generics_{next(_counter)}", token_file=None, oauth=False)
    asfquart.generics.setup_oauth(app, logout_by_get=logout_by_get)
    return app


def _make_app_with_logout_same_site(logout_same_site):
    """An app that calls setup_oauth() itself, to pass logout_same_site"""
    app = asfquart.construct(f"test_generics_{next(_counter)}", token_file=None, oauth=False)
    asfquart.generics.setup_oauth(app, logout_same_site=logout_same_site)
    return app


def _add_session_routes(app):
    """Routes to log in without the OAuth provider, and to see whether the browser is still logged in"""
    @app.route("/test-login")
    async def test_login():
        asfquart.session.write({"uid": "testuser"})
        return "ok"

    @app.route("/test-whoami")
    async def test_whoami():
        session = await asfquart.session.read()
        return session.uid if session is not None else "nobody"


async def _whoami(client):
    return (await (await client.get("/test-whoami", scheme="https")).get_data()).decode()


def _navigation(site):
    """The headers a browser sends when the user goes to an address in a window or tab"""
    if site is None:
        return {}
    return {"Sec-Fetch-Site": site, "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}


@pytest.fixture
def real_session(monkeypatch):
    """Other tests replace quart.session; these need the session cookie"""
    monkeypatch.setattr(quart, "session", quart.globals.session)
    monkeypatch.setattr(asfquart.generics, "_warned_get_logout", False)


@pytest.mark.generics
@pytest.mark.parametrize("site", [None, "same-origin", "none"])
@pytest.mark.parametrize("url, status", [("/auth?logout", 200), ("/auth?logout=/goodbye", 302)])
async def test_get_logout_from_the_app_itself_still_works(real_session, site, url, status):
    """A logout link in the app, a typed address, and a client that sends no Sec-Fetch-Site"""
    app = _make_app()
    _add_session_routes(app)
    async with app.test_app():
        client = app.test_client()
        await client.get("/test-login", scheme="https")
        assert await _whoami(client) == "testuser"
        resp = await client.get(url, scheme="https", headers=_navigation(site))
        assert resp.status_code == status
        assert resp.headers["Clear-Site-Data"] == '"cache", "cookies", "storage"'
        assert await _whoami(client) == "nobody"


@pytest.mark.generics
@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("url", ["/auth?logout", "/auth?logout=/goodbye", "/auth?logout=https://evil.example"])
async def test_get_logout_from_another_site_is_refused(real_session, method, url):
    """Another site cannot log a user out, nor have the browser clear the app's data"""
    app = _make_app()
    _add_session_routes(app)
    async with app.test_app():
        client = app.test_client()
        await client.get("/test-login", scheme="https")
        resp = await client.open(url, method=method, scheme="https", headers=_navigation("cross-site"))
        assert resp.status_code == 403
        assert "Clear-Site-Data" not in resp.headers
        assert "Location" not in resp.headers
        assert "Set-Cookie" not in resp.headers
        assert await _whoami(client) == "testuser"


@pytest.mark.generics
@pytest.mark.parametrize("site", ["same-origin", "same-site", "cross-site"])
@pytest.mark.parametrize("mode, dest", [
    ("no-cors", "image"),       # <img src="/auth?logout">
    ("no-cors", "script"),
    ("cors", "empty"),          # fetch()
    ("navigate", "iframe"),     # a frame is a navigation, but not one the user made
    ("navigate", "embed"),
    (None, None),               # Sec-Fetch-Site alone
])
async def test_get_logout_from_within_a_page_is_refused(real_session, site, mode, dest):
    """A page cannot log the user out by fetching the address, not even one on the same site:
    every host under apache.org is the same site as the app."""
    app = _make_app()
    _add_session_routes(app)
    headers = {"Sec-Fetch-Site": site}
    if mode:
        headers.update({"Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": dest})
    async with app.test_app():
        client = app.test_client()
        await client.get("/test-login", scheme="https")
        resp = await client.get("/auth?logout", scheme="https", headers=headers)
        assert resp.status_code == 403
        assert "Clear-Site-Data" not in resp.headers
        assert await _whoami(client) == "testuser"


@pytest.mark.generics
@pytest.mark.parametrize("prefetch", [
    {"Sec-Purpose": "prefetch"},
    {"Sec-Purpose": "prefetch;prerender"},
    {"Sec-Purpose": "prefetch;anonymous-client-ip"},
    {"Purpose": "prefetch"},
    {"X-Moz": "prefetch"},
])
@pytest.mark.parametrize("site", [None, "same-origin"])
async def test_prefetched_get_logout_is_refused(real_session, caplog, prefetch, site):
    """A browser fetching the logout link ahead of time does not log the user out"""
    app = _make_app()
    _add_session_routes(app)
    async with app.test_app():
        client = app.test_client()
        await client.get("/test-login", scheme="https")
        resp = await client.get("/auth?logout", scheme="https", headers={**_navigation(site), **prefetch})
        assert resp.status_code == 403
        assert "Clear-Site-Data" not in resp.headers
        assert await _whoami(client) == "testuser"
    assert "requested with GET" not in caplog.text


@pytest.mark.generics
async def test_post_logout_from_another_site_is_refused(real_session):
    """As before: the check on a POST does not allow "none" either"""
    app = _make_app()
    _add_session_routes(app)
    async with app.test_app():
        client = app.test_client()
        await client.get("/test-login", scheme="https")
        for site in ("cross-site", "none"):
            resp = await client.post("/auth?logout", scheme="https", headers={"Sec-Fetch-Site": site})
            assert resp.status_code == 403
            assert "Clear-Site-Data" not in resp.headers
        assert await _whoami(client) == "testuser"


@pytest.mark.generics
@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("site", [None, "same-origin", "none", "cross-site"])
async def test_get_logout_can_be_turned_off(real_session, method, site):
    """With logout_by_get=False a GET logout is a 405 wherever it comes from, and logs nobody out"""
    app = _make_app_with_logout_by_get(False)
    _add_session_routes(app)
    async with app.test_app():
        client = app.test_client()
        await client.get("/test-login", scheme="https")
        for url in ("/auth?logout", "/auth?logout=/goodbye"):
            resp = await client.open(url, method=method, scheme="https", headers=_navigation(site))
            assert resp.status_code == 405
            assert resp.headers["Allow"] == "POST"
            assert "Clear-Site-Data" not in resp.headers
            assert "Location" not in resp.headers
        assert await _whoami(client) == "testuser"


@pytest.mark.generics
async def test_post_logout_works_when_get_is_turned_off(real_session, caplog):
    app = _make_app_with_logout_by_get(False)
    _add_session_routes(app)
    async with app.test_app():
        client = app.test_client()
        await client.get("/test-login", scheme="https")
        resp = await client.post("/auth?logout", scheme="https", headers={"Sec-Fetch-Site": "same-origin"})
        assert resp.status_code == 204
        assert resp.headers["Clear-Site-Data"] == '"cache", "cookies", "storage"'
        assert await _whoami(client) == "nobody"
        await client.get("/test-login", scheme="https")
        resp = await client.post("/auth?logout=/goodbye", scheme="https")
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/goodbye"
        assert await _whoami(client) == "nobody"
    assert "requested with GET" not in caplog.text


@pytest.mark.generics
async def test_login_and_the_session_display_are_not_affected_by_turning_get_logout_off(real_session):
    """Starting a login has to work with GET: the browser gets there by a redirect"""
    app = _make_app_with_logout_by_get(False)
    _add_session_routes(app)
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=/dashboard", scheme="https", headers={"Sec-Fetch-Site": "cross-site"})
        assert resp.status_code == 302
        assert resp.headers["Location"].startswith("https://oauth.apache.org/")
        await client.get("/test-login", scheme="https")
        assert (await client.get("/auth", scheme="https")).status_code == 200


@pytest.mark.generics
async def test_logout_by_get_module_default(real_session, monkeypatch):
    """OAUTH_LOGOUT_BY_GET is the default for apps made by construct(), and may be set after it"""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        assert (await client.get("/auth?logout", scheme="https")).status_code == 200
        monkeypatch.setattr(asfquart.generics, "OAUTH_LOGOUT_BY_GET", False)
        assert (await client.get("/auth?logout", scheme="https")).status_code == 405
        assert (await client.post("/auth?logout", scheme="https")).status_code == 204


@pytest.mark.generics
async def test_logout_by_get_parameter_wins_over_module_default(real_session, monkeypatch):
    monkeypatch.setattr(asfquart.generics, "OAUTH_LOGOUT_BY_GET", False)
    app = _make_app_with_logout_by_get(True)
    async with app.test_app():
        assert (await app.test_client().get("/auth?logout", scheme="https")).status_code == 200
    monkeypatch.setattr(asfquart.generics, "OAUTH_LOGOUT_BY_GET", True)
    app = _make_app_with_logout_by_get(False)
    async with app.test_app():
        assert (await app.test_client().get("/auth?logout", scheme="https")).status_code == 405


@pytest.mark.generics
async def test_get_logout_is_warned_about_once(real_session, caplog):
    """The log says once that logout should be a POST; refused and POST logouts do not count"""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        await client.post("/auth?logout", scheme="https")
        await client.get("/auth?logout", scheme="https", headers=_navigation("cross-site"))
        await client.get("/auth?logout", scheme="https", headers={"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"})
        assert "requested with GET" not in caplog.text
        for _ in range(3):
            await client.get("/auth?logout", scheme="https")
    warnings = [r for r in caplog.records if r.name == "asfquart.generics" and "requested with GET" in r.getMessage()]
    assert len(warnings) == 1
    assert warnings[0].levelname == "WARNING"
    assert "OAUTH_LOGOUT_BY_GET" in warnings[0].getMessage()


# ---- Logout from another host of the same site (#69) ----

async def _logout(client, method, site):
    """A logout as a browser would send it from a page of the given kind of site: a link for GET, a form for POST"""
    headers = _navigation(site) if method == "GET" else {"Sec-Fetch-Site": site}
    return await client.open("/auth?logout", method=method, scheme="https", headers=headers)


@pytest.mark.generics
@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_logout_from_another_host_of_the_same_site_is_refused(real_session, method):
    """Every apache.org host is the same site as the app. By default only the app's own pages can log a user out."""
    app = _make_app()
    _add_session_routes(app)
    async with app.test_app():
        client = app.test_client()
        await client.get("/test-login", scheme="https")
        resp = await _logout(client, method, "same-site")
        assert resp.status_code == 403
        assert "Clear-Site-Data" not in resp.headers
        assert await _whoami(client) == "testuser"
        resp = await _logout(client, method, "same-origin")
        assert resp.status_code == (200 if method == "GET" else 204)
        assert await _whoami(client) == "nobody"


@pytest.mark.generics
@pytest.mark.parametrize("method, status", [("GET", 200), ("POST", 204)])
async def test_logout_from_the_same_site_can_be_allowed(real_session, method, status):
    app = _make_app_with_logout_same_site(True)
    _add_session_routes(app)
    async with app.test_app():
        client = app.test_client()
        await client.get("/test-login", scheme="https")
        resp = await _logout(client, method, "same-site")
        assert resp.status_code == status
        assert resp.headers["Clear-Site-Data"] == '"cache", "cookies", "storage"'
        assert await _whoami(client) == "nobody"


@pytest.mark.generics
async def test_allowing_the_same_site_allows_nothing_else(real_session):
    """Another site is still refused, and so is a page of the same site that fetches the address"""
    app = _make_app_with_logout_same_site(True)
    _add_session_routes(app)
    refused = [
        ("GET", _navigation("cross-site")),
        ("POST", {"Sec-Fetch-Site": "cross-site"}),
        ("POST", {"Sec-Fetch-Site": "none"}),
        ("GET", {"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"}),
        ("GET", {"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"}),
        ("GET", {**_navigation("same-site"), "Sec-Purpose": "prefetch"}),
    ]
    async with app.test_app():
        client = app.test_client()
        await client.get("/test-login", scheme="https")
        for method, headers in refused:
            resp = await client.open("/auth?logout", method=method, scheme="https", headers=headers)
            assert resp.status_code == 403, (method, headers)
            assert "Clear-Site-Data" not in resp.headers
        assert await _whoami(client) == "testuser"


@pytest.mark.generics
@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_logout_same_site_module_default_and_parameter(real_session, monkeypatch, method):
    """OAUTH_LOGOUT_SAME_SITE is the default, may be set after construct(), and the parameter wins over it"""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        assert (await _logout(client, method, "same-site")).status_code == 403
        monkeypatch.setattr(asfquart.generics, "OAUTH_LOGOUT_SAME_SITE", True)
        assert (await _logout(client, method, "same-site")).status_code != 403
    app = _make_app_with_logout_same_site(False)
    async with app.test_app():
        assert (await _logout(app.test_client(), method, "same-site")).status_code == 403
    monkeypatch.setattr(asfquart.generics, "OAUTH_LOGOUT_SAME_SITE", False)
    app = _make_app_with_logout_same_site(True)
    async with app.test_app():
        assert (await _logout(app.test_client(), method, "same-site")).status_code != 403


@pytest.mark.generics
async def test_other_posts_from_the_same_site_are_not_affected(real_session):
    """The stricter rule is for logout. Starting a login by POST from the same site works as before."""
    app = _make_app()
    async with app.test_app():
        resp = await app.test_client().post("/auth?login", scheme="https", headers={"Sec-Fetch-Site": "same-site"})
        assert resp.status_code == 302
        assert resp.headers["Location"].startswith("https://oauth.apache.org/")


@pytest.mark.generics
async def test_get_logout_turned_off_and_same_site_allowed_together(real_session):
    app = asfquart.construct(f"test_generics_{next(_counter)}", token_file=None, oauth=False)
    asfquart.generics.setup_oauth(app, logout_by_get=False, logout_same_site=True)
    async with app.test_app():
        client = app.test_client()
        assert (await _logout(client, "GET", "same-site")).status_code == 405
        assert (await _logout(client, "POST", "same-site")).status_code == 204
