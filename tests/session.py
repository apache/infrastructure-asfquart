#!/usr/bin/env python3

import time

import pytest
import quart
import asfquart


@pytest.mark.session
async def test_sessions():
    app = asfquart.construct("foobar", token_file=None)
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "uid": "bar"}})
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


# ---- Time limits for a session that is kept in the cookie ----

DAY = 86400


class _Clock:
    """Stands in for the time module inside asfquart.session"""

    def __init__(self, now=1_000_000.0):
        self.now = now

    def time(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    fake = _Clock()
    monkeypatch.setattr(asfquart.session, "time", fake)
    return fake


_app_counter = iter(range(1_000_000))


def _session_app(**cfg):
    """An app with endpoints to log in, to use the session, and to change it"""
    app = asfquart.construct(f"test_session_limits_{next(_app_counter)}", token_file=None, oauth=False)
    app.cfg.update(cfg)

    @app.route("/login")
    async def login():
        uid = quart.request.args.get("uid", "testuser")
        asfquart.session.write({"uid": uid}, new_session=bool(quart.request.args.get("new")))
        return "ok"

    @app.route("/use")
    async def use():
        idle = quart.request.args.get("idle")
        session = await asfquart.session.read(expiry_time=int(idle)) if idle else await asfquart.session.read()
        if session is None:
            return {"uid": None}
        stored = quart.session[app.app_id]
        return {"uid": session.uid, "cts": stored["cts"], "uts": stored["uts"], "fullname": session.fullname}

    @app.route("/change")
    async def change():
        session = await asfquart.session.read()
        session["fullname"] = "Changed"
        asfquart.session.write(session)   # as docs/sessions.md shows
        return "ok"

    return app


async def _get(client, path):
    resp = await client.get(path, scheme="https")
    assert resp.status_code == 200
    if resp.content_type == "application/json":
        return await resp.get_json()
    return resp


@pytest.mark.session
def test_default_session_limits():
    assert asfquart.session.DEFAULT_MAX_SESSION_AGE == 7 * DAY
    assert asfquart.session.DEFAULT_MAX_SESSION_IDLE == 7 * DAY


@pytest.mark.session
async def test_session_in_use_does_not_go_idle(clock):
    """Using a session counts: the idle limit runs from when it was last used, not from the login."""
    app = _session_app(MAX_SESSION_IDLE=100, MAX_SESSION_AGE=0)
    client = app.test_client()
    await _get(client, "/login")
    for _ in range(10):
        clock.now += 60          # never 100 seconds without a request
        assert (await _get(client, "/use"))["uid"] == "testuser"
    clock.now += 101             # and then nothing for longer than the limit
    assert (await _get(client, "/use"))["uid"] is None


@pytest.mark.session
async def test_session_ends_at_its_maximum_age_however_much_it_is_used(clock):
    app = _session_app(MAX_SESSION_IDLE=100, MAX_SESSION_AGE=1000)
    client = app.test_client()
    await _get(client, "/login")
    for _ in range(19):
        clock.now += 50
        assert (await _get(client, "/use"))["uid"] == "testuser"    # up to 950 seconds old
    clock.now += 51
    assert (await _get(client, "/use"))["uid"] is None              # 1001 seconds old


@pytest.mark.session
async def test_default_limits_apply_when_nothing_is_configured(clock):
    """A session lasts 7 days from the login, whether it is used every day or left alone."""
    app = _session_app()
    client = app.test_client()
    await _get(client, "/login")
    for _ in range(6):
        clock.now += DAY
        assert (await _get(client, "/use"))["uid"] == "testuser"
    clock.now += DAY + 1
    assert (await _get(client, "/use"))["uid"] is None

    client = app.test_client()
    await _get(client, "/login")
    clock.now += 7 * DAY - 1
    assert (await _get(client, "/use"))["uid"] == "testuser"
    clock.now += 2
    assert (await _get(client, "/use"))["uid"] is None


@pytest.mark.session
async def test_lower_idle_limit_takes_effect_with_the_default_maximum_age(clock):
    """With MAX_SESSION_IDLE below the default MAX_SESSION_AGE, a user who stays away is logged out sooner."""
    app = _session_app(MAX_SESSION_IDLE=DAY)
    client = app.test_client()
    await _get(client, "/login")
    for _ in range(5):
        clock.now += DAY - 60
        assert (await _get(client, "/use"))["uid"] == "testuser"
    clock.now += DAY + 1
    assert (await _get(client, "/use"))["uid"] is None


@pytest.mark.session
async def test_limits_of_zero_mean_no_limit(clock):
    app = _session_app(MAX_SESSION_IDLE=0, MAX_SESSION_AGE=0)
    client = app.test_client()
    await _get(client, "/login")
    clock.now += 20 * DAY        # quart itself does not accept a cookie that it signed more than 31 days ago
    assert (await _get(client, "/use"))["uid"] == "testuser"


@pytest.mark.session
async def test_expiry_time_argument_is_the_idle_limit_for_that_call(clock):
    app = _session_app(MAX_SESSION_IDLE=1000, MAX_SESSION_AGE=0)
    client = app.test_client()
    await _get(client, "/login")
    clock.now += 500
    assert (await _get(client, "/use?idle=600"))["uid"] == "testuser"   # within 600 seconds
    clock.now += 500
    assert (await _get(client, "/use?idle=5000"))["uid"] == "testuser"  # 500 since last use
    clock.now += 1500
    assert (await _get(client, "/use?idle=5000"))["uid"] == "testuser"  # over MAX_SESSION_IDLE, but the argument wins
    clock.now += 100
    assert (await _get(client, "/use?idle=50"))["uid"] is None


@pytest.mark.session
async def test_changing_a_session_does_not_extend_its_life(clock):
    """Writing the session of the user who is logged in keeps its creation time."""
    app = _session_app(MAX_SESSION_IDLE=0, MAX_SESSION_AGE=1000)
    client = app.test_client()
    await _get(client, "/login")
    created = (await _get(client, "/use"))["cts"]
    clock.now += 900
    await _get(client, "/change")
    used = await _get(client, "/use")
    assert used["fullname"] == "Changed"
    assert used["cts"] == created
    clock.now += 101             # 1001 seconds after the login, 101 after the change
    assert (await _get(client, "/use"))["uid"] is None


@pytest.mark.session
async def test_logging_in_starts_a_new_session(clock):
    """A new login has the full lifetime: as another user, when asked for, or after the old session ended."""
    app = _session_app(MAX_SESSION_IDLE=0, MAX_SESSION_AGE=1000)
    client = app.test_client()
    await _get(client, "/login")
    created = (await _get(client, "/use"))["cts"]

    clock.now += 500
    await _get(client, "/login?uid=otheruser")                 # another user
    assert (await _get(client, "/use"))["cts"] == created + 500

    clock.now += 500
    await _get(client, "/login?uid=otheruser&new=1")           # the same user, having authenticated again
    assert (await _get(client, "/use"))["cts"] == created + 1000

    clock.now += 1001
    await _get(client, "/login?uid=otheruser")                 # the same user, whose session had ended
    assert (await _get(client, "/use"))["cts"] == created + 2001


class _Provider:
    """Stands in for aiohttp.client.ClientSession: the OAuth provider says who the user is"""

    status = 200

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        return self

    async def json(self):
        return {"uid": "testuser"}


@pytest.mark.session
async def test_oauth_login_starts_a_new_session(clock, monkeypatch):
    """Logging in again through OAuth, while still logged in, gives a new session with the full lifetime."""
    import urllib.parse
    import asfquart.generics
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", _Provider())
    app = asfquart.construct(f"test_session_limits_{next(_app_counter)}", token_file=None)
    app.cfg.update(MAX_SESSION_AGE=1000, MAX_SESSION_IDLE=0)
    created = []

    @app.after_request
    async def note_creation_time(response):
        stored = quart.session.get(app.app_id)
        if isinstance(stored, dict) and "cts" in stored:
            created.append(stored["cts"])
        return response

    client = app.test_client()
    for _ in range(2):
        start = await client.get("/auth?login", scheme="https")
        state = urllib.parse.parse_qs(urllib.parse.urlsplit(start.headers["Location"]).query)["state"][0]
        resp = await client.get(f"/auth?state={state}&code=abc", scheme="https")
        assert resp.status_code == 200
        clock.now += 900
    assert created[-1] == created[0] + 900
    clock.now += 50              # 950 seconds after the second login, 1850 after the first
    session = await client.get("/auth", scheme="https")
    assert session.status_code == 200


@pytest.mark.session
async def test_session_without_a_creation_time_gets_one(clock):
    """A session written by a version that did not record when it was created is not ended at
    once; its clock starts when it is next read, and it ends MAX_SESSION_AGE after that."""
    app = _session_app(MAX_SESSION_IDLE=0, MAX_SESSION_AGE=1000)
    client = app.test_client()
    async with client.session_transaction(scheme="https") as stored:
        stored[app.app_id] = {"uid": "testuser", "uts": clock.now}
    first = await _get(client, "/use")
    assert first["uid"] == "testuser"
    assert first["cts"] == clock.now
    clock.now += 900
    assert (await _get(client, "/use"))["cts"] == first["cts"]     # saved, not started again
    clock.now += 101
    assert (await _get(client, "/use"))["uid"] is None


@pytest.mark.session
async def test_cookie_is_not_sent_again_for_every_request(clock):
    """The time a session was last used is saved at most once a minute for a limit of days."""
    app = _session_app()
    client = app.test_client()
    await _get(client, "/login")
    clock.now += 30
    assert "Set-Cookie" not in (await client.get("/use", scheme="https")).headers
    clock.now += 31
    assert "Set-Cookie" in (await client.get("/use", scheme="https")).headers
    clock.now += 30
    assert "Set-Cookie" not in (await client.get("/use", scheme="https")).headers


@pytest.mark.session
async def test_session_store_applies_its_own_limits(clock):
    """With a session store, asfquart leaves the limits to the store: what validate() returns is the session."""
    app = _session_app(MAX_SESSION_IDLE=10, MAX_SESSION_AGE=10)

    class Store:
        async def validate(self, hsid):
            return asfquart.session.ClientSession({"uid": "stored"})

    app.sessions = Store()
    client = app.test_client()
    async with client.session_transaction(scheme="https") as stored:
        stored[app.app_id] = {"sid": "some-session-id"}
    clock.now += 5000
    async with app.test_request_context("/"):
        quart.session[app.app_id] = {"sid": "some-session-id"}
        session = await asfquart.session.read(expiry_time=1)
    assert session.uid == "stored"


# ---- Saving a change to the session must not fail silently ----

@pytest.mark.session
async def test_reading_marks_a_real_session_as_changed():
    """When read() updates the session, it tells quart, so that the cookie is sent again."""
    app = asfquart.construct("foobar", token_file=None)
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time() - 3600, "uid": "bar"}})
    assert quart.session.modified is False
    session = await asfquart.session.read()
    assert session.uid == "bar"
    assert quart.session.modified is True


@pytest.mark.session
async def test_session_that_cannot_be_marked_as_changed_is_an_error():
    """If quart.session is not a session, a plain dict for instance, the update cannot be saved.
    read() says so with an error, and does not carry on as if it had been."""
    app = asfquart.construct("foobar", token_file=None)
    quart.session = {app.app_id: {"uts": time.time() - 3600, "uid": "bar"}}
    with pytest.raises(AttributeError, match="modified"):
        await asfquart.session.read()
