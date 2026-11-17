#!/usr/bin/env python3
"""Tests for the login logging shown in docs/oauth.md: the session store, and the hook.

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
        args = request.args
        # Only the callback from the OAuth provider is a login decision. The OAuth endpoint treats a
        # request as the callback when it has a code and a state, neither of them empty, and is not
        # a login or logout request. Anything else must not be logged as a login: with an empty code,
        # for instance, the endpoint shows the session of a user who is logged in already.
        is_callback = (
            request.path == "/auth"
            and args.get("code") and args.get("state")
            and not args.get("login") and not args.get("logout")
        )
        if is_callback:
            # The callback answers 200 only when it has created the session. Read it back all the
            # same, and count the login as failed if it is not there.
            session = await asfquart.session.read() if response.status_code == 200 else None
            if session is not None:
                log.info("login succeeded: uid=%s remote=%s", session.uid, request.remote_addr)
            else:
                log.warning("login failed: status=%s remote=%s", response.status_code, request.remote_addr)
        return response
    # ---- End of the hook ----

    return app


def _audit(caplog):
    """The records of the application's audit log. asfquart logs warnings of its own (when the
    exchange with the provider fails), and those are not what these tests are about."""
    return [record for record in caplog.records if record.name == "myapp.audit"]


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

    async def post(self, url, **kwargs):
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
        assert _audit(caplog) == []  # starting a login is not a decision
        resp = await client.get(f"/auth?state={state}&code=sekrit", scheme="https")
        assert resp.status_code == 200
    (record,) = _audit(caplog)
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
    (record,) = _audit(caplog)
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
    assert [record.levelno for record in _audit(caplog)] == [logging.WARNING, logging.WARNING]
    assert all("login failed: status=403" in record.getMessage() for record in _audit(caplog))


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
    assert _audit(caplog) == []


# ---- Requests that look like the callback, but are not a login ----

async def _logged_in_client(app, monkeypatch, caplog):
    """A client that has completed a login; the log is emptied afterwards"""
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", _FakeProvider(data={"uid": "testuser"}))
    client = app.test_client()
    state = await _start_login(client)
    resp = await client.get(f"/auth?state={state}&code=sekrit", scheme="https")
    assert resp.status_code == 200
    caplog.clear()
    return client


@pytest.mark.generics
@pytest.mark.parametrize("query", [
    "code=&state=",             # both present, both empty
    "code=x&state=",
    "code=&state=x",
    "code&state",
])
async def test_session_display_is_not_logged_as_a_login(monkeypatch, caplog, query):
    """With an empty code or state, /auth shows the session of a user who is logged in already.
    That answers 200, and must not be recorded as a login."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_app()
    async with app.test_app():
        client = await _logged_in_client(app, monkeypatch, caplog)
        resp = await client.get(f"/auth?{query}", scheme="https")
        assert resp.status_code == 200
        assert (await resp.get_json())["uid"] == "testuser"
    assert _audit(caplog) == []


@pytest.mark.generics
async def test_session_display_without_a_session_is_not_logged(caplog):
    """The same requests from somebody who is not logged in answer 404, and are not login attempts."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_app()
    async with app.test_app():
        resp = await app.test_client().get("/auth?code=&state=", scheme="https")
        assert resp.status_code == 404
    assert _audit(caplog) == []


@pytest.mark.generics
@pytest.mark.parametrize("query, status", [
    ("login=/dashboard&code=x&state=y", 302),   # starts a login, whatever else is in the query
    ("logout=/goodbye&code=x&state=y", 302),    # logs out
    ("login=https://example.org&code=x&state=y", 400),
])
async def test_login_and_logout_with_a_code_are_not_logged(monkeypatch, caplog, query, status):
    """A login or logout request is not the callback, even with a code and a state added to it."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_app()
    async with app.test_app():
        client = await _logged_in_client(app, monkeypatch, caplog)
        resp = await client.get(f"/auth?{query}", scheme="https")
        assert resp.status_code == status
    assert _audit(caplog) == []


@pytest.mark.generics
async def test_made_up_callback_from_a_logged_in_user_is_a_failed_login(monkeypatch, caplog):
    """A logged in user cannot produce a success record by sending a callback of their own making."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_app()
    async with app.test_app():
        client = await _logged_in_client(app, monkeypatch, caplog)
        resp = await client.get("/auth?code=made-up&state=made-up", scheme="https")
        assert resp.status_code == 403
    (record,) = _audit(caplog)
    assert record.levelno == logging.WARNING
    assert "login failed: status=403" in record.getMessage()


@pytest.mark.generics
async def test_hook_does_not_fail_when_the_session_cannot_be_read(monkeypatch, caplog):
    """If the session is not there after a callback that answered 200, the hook records a failed
    login. It does not raise, which would turn the response into a 500."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", _FakeProvider(data={"uid": "testuser"}))
    app = _make_app()

    async def no_session(*args, **kwargs):
        return None

    async with app.test_app():
        client = app.test_client()
        state = await _start_login(client)
        monkeypatch.setattr(asfquart.session, "read", no_session)
        resp = await client.get(f"/auth?state={state}&code=sekrit", scheme="https")
        assert resp.status_code == 200
    (record,) = _audit(caplog)
    assert record.levelno == logging.WARNING
    assert "login failed: status=200" in record.getMessage()


# ---- Logging in the session store ----

log = logging.getLogger("myapp.audit")


class Store:
    """A small store, kept in memory, with the two log lines from docs/oauth.md ("Logging logins")
    in its create() and destroy(). It has no replace() or register(): see the stores below."""

    def __init__(self):
        self._sessions = {}

    async def create(self, hsid, session_data):
        self._sessions[hsid] = asfquart.session.ClientSession(session_data)
        log.info("login succeeded: uid=%s remote=%s", session_data.get("uid"), quart.request.remote_addr)

    async def validate(self, hsid):
        return self._sessions.get(hsid)

    async def destroy(self, hsid):
        session = self._sessions.pop(hsid, None)
        if session is not None:
            log.info("logout: uid=%s", session.uid)


class StoreWithRegister(Store):
    """A store that areplace() can use, by destroying the old session and registering the new one"""

    async def register(self, hsid, session_object):
        self._sessions[hsid] = session_object


class StoreWithReplace(Store):
    """A store that areplace() can use in one step"""

    async def replace(self, old_hsid, new_hsid, session_object):
        self._sessions.pop(old_hsid, None)
        self._sessions[new_hsid] = session_object


def _make_store_app(store_class=Store):
    """An app with a store that logs as docs/oauth.md shows, and no hook"""
    app = asfquart.construct(f"test_oauth_logging_store_{next(_counter)}", token_file=None)
    app.sessions = store_class()

    @app.route("/change")
    async def change():
        session = await asfquart.session.read()
        changed = asfquart.session.ClientSession({"uid": session.uid, "fullname": "Changed"})
        await asfquart.session.areplace(changed)
        return "ok"

    return app


async def _login(client, uid_provider, monkeypatch, code="sekrit"):
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", uid_provider)
    state = await _start_login(client)
    return state, await client.get(f"/auth?state={state}&code={code}", scheme="https")


@pytest.mark.generics
async def test_store_logs_login_and_logout(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_store_app()
    async with app.test_app():
        client = app.test_client()
        state, resp = await _login(client, _FakeProvider(data={"uid": "testuser"}), monkeypatch)
        assert resp.status_code == 200
        (login,) = _audit(caplog)
        assert "login succeeded: uid=testuser" in login.getMessage()

        # The session works, and reading it logs nothing more
        session = await client.get("/auth", scheme="https")
        assert (await session.get_json())["uid"] == "testuser"
        assert len(_audit(caplog)) == 1

        assert (await client.get("/auth?logout", scheme="https")).status_code == 200
        assert [record.getMessage() for record in _audit(caplog)][1:] == ["logout: uid=testuser"]

        # Logging out again, with no session left, is not another logout
        await client.get("/auth?logout", scheme="https")
        assert len(_audit(caplog)) == 2

    # Neither the code nor the state is in the log
    for secret in ("sekrit", state):
        assert secret not in caplog.text


@pytest.mark.generics
@pytest.mark.parametrize("query", ["code=&state=", "code=x&state=", "code&state", "", "code=made-up&state=made-up"])
async def test_store_cannot_be_made_to_log_a_login(monkeypatch, caplog, query):
    """No request from a logged in user produces a login record: only a completed login does."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_store_app()
    async with app.test_app():
        client = app.test_client()
        await _login(client, _FakeProvider(data={"uid": "testuser"}), monkeypatch)
        caplog.clear()
        await client.get(f"/auth?{query}", scheme="https")
    assert _audit(caplog) == []


@pytest.mark.generics
async def test_store_does_not_see_failed_logins(monkeypatch, caplog):
    """A refused code and an unknown state never reach the store, which is why the hook exists."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_store_app()
    async with app.test_app():
        client = app.test_client()
        _state, resp = await _login(client, _FakeProvider(status=401), monkeypatch)
        assert resp.status_code == 403
        assert (await client.get("/auth?state=made-up&code=sekrit", scheme="https")).status_code == 403
    assert _audit(caplog) == []


@pytest.mark.generics
async def test_store_logs_logout_when_a_user_logs_in_again(monkeypatch, caplog):
    """Logging in again without logging out destroys the previous session first."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_store_app()
    async with app.test_app():
        client = app.test_client()
        await _login(client, _FakeProvider(data={"uid": "testuser"}), monkeypatch)
        await _login(client, _FakeProvider(data={"uid": "testuser"}), monkeypatch)
    messages = [record.getMessage().split(" remote=")[0] for record in _audit(caplog)]
    assert messages == ["login succeeded: uid=testuser", "logout: uid=testuser", "login succeeded: uid=testuser"]
    assert len(app.sessions._sessions) == 1


@pytest.mark.generics
async def test_store_login_without_a_uid_does_not_leave_a_session_behind(caplog):
    """The log line cannot fail, so create() cannot raise after it has saved the session. If it
    did, the session would be in the store with no cookie leading to it."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_store_app()
    async with app.test_request_context("/"):
        await asfquart.session.awrite({"fullname": "No uid"})
        assert isinstance(quart.session[app.app_id].get("sid"), str)   # the cookie leads to the session
    assert len(app.sessions._sessions) == 1
    (record,) = _audit(caplog)
    assert "login succeeded: uid=None" in record.getMessage()


@pytest.mark.generics
async def test_areplace_with_replace_logs_nothing(monkeypatch, caplog):
    """With a store that has replace(), changing a session with areplace() is neither a login nor a logout."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_store_app(StoreWithReplace)
    async with app.test_app():
        client = app.test_client()
        await _login(client, _FakeProvider(data={"uid": "testuser"}), monkeypatch)
        caplog.clear()
        assert (await client.get("/change", scheme="https")).status_code == 200
        session = await client.get("/auth", scheme="https")
        assert (await session.get_json())["fullname"] == "Changed"
    assert _audit(caplog) == []
    assert len(app.sessions._sessions) == 1


@pytest.mark.generics
async def test_areplace_with_register_logs_a_logout(monkeypatch, caplog):
    """With a store that has only register(), areplace() destroys the old session first, and the
    log line in destroy() records a logout, as docs/oauth.md warns."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_store_app(StoreWithRegister)
    async with app.test_app():
        client = app.test_client()
        await _login(client, _FakeProvider(data={"uid": "testuser"}), monkeypatch)
        caplog.clear()
        assert (await client.get("/change", scheme="https")).status_code == 200
        session = await client.get("/auth", scheme="https")
        assert (await session.get_json())["fullname"] == "Changed"
    assert [record.getMessage() for record in _audit(caplog)] == ["logout: uid=testuser"]


@pytest.mark.generics
async def test_areplace_needs_replace_or_register(monkeypatch):
    """A store with neither cannot be used with areplace()."""
    app = _make_store_app(Store)
    async with app.test_app():
        client = app.test_client()
        await _login(client, _FakeProvider(data={"uid": "testuser"}), monkeypatch)
        assert (await client.get("/change", scheme="https")).status_code == 500


# ---- The method of the callback, and more than one app ----

@pytest.mark.generics
async def test_callback_by_post_is_a_login_and_is_logged(monkeypatch, caplog):
    """The OAuth endpoint takes the callback by POST as well as by GET. A login that is completed
    by POST is a login, so the hook must record it: a hook that looked at GET only would miss it."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", _FakeProvider(data={"uid": "testuser"}))
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        state = await _start_login(client)
        resp = await client.post(f"/auth?state={state}&code=sekrit", scheme="https")
        assert resp.status_code == 200
        session = await client.get("/auth", scheme="https")
        assert (await session.get_json())["uid"] == "testuser"       # the POST did log the user in
    (record,) = _audit(caplog)
    assert "login succeeded: uid=testuser" in record.getMessage()


@pytest.mark.generics
async def test_refused_post_callback_is_logged_as_a_failure(caplog):
    """A callback posted from another site is refused before anything else, and is a failed login."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    app = _make_app()
    async with app.test_app():
        resp = await app.test_client().post(
            "/auth?state=made-up&code=sekrit", scheme="https", headers={"Sec-Fetch-Site": "cross-site"})
        assert resp.status_code == 403
    (record,) = _audit(caplog)
    assert "login failed: status=403" in record.getMessage()


@pytest.mark.generics
async def test_hook_finds_the_session_where_the_endpoint_put_it(monkeypatch, caplog):
    """The OAuth endpoint writes the session for asfquart.APP, the app that was constructed last,
    and session.read() with no app reads it from there. The hook must read it the same way. If it
    passed its own app, and another app had been constructed since, it would look in the wrong
    place and record a login that worked as one that failed."""
    caplog.set_level(logging.INFO, logger="myapp.audit")
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", _FakeProvider(data={"uid": "testuser"}))
    app = _make_app()
    other = asfquart.construct(f"test_oauth_logging_other_{next(_counter)}", token_file=None)
    assert asfquart.APP is other and other is not app      # the endpoint and the hook both look here
    async with app.test_app():
        client = app.test_client()
        state = await _start_login(client)
        resp = await client.get(f"/auth?state={state}&code=sekrit", scheme="https")
        assert resp.status_code == 200
    (record,) = _audit(caplog)
    assert "login succeeded: uid=testuser" in record.getMessage()
