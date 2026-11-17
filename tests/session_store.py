#!/usr/bin/env python3
"""Tests for server-side session stores (app.sessions), as described in docs/session-stores.md.

The store under test is the one printed on that page: the code is read from the page and run,
so the page cannot say one thing and the tests another."""

import hashlib
import pathlib
import re
import time
import urllib.parse

import pytest
import quart
import quart.globals

import asfquart
import asfquart.auth
import asfquart.generics
import asfquart.session

DOC = pathlib.Path(__file__).parent.parent / "docs" / "session-stores.md"
DAY = 86400


def _store_class_from_the_docs():
    blocks = re.findall(r"```python\n(.*?)```", DOC.read_text(encoding="utf-8"), flags=re.DOTALL)
    (source,) = [block for block in blocks if "class MemoryStore" in block]
    namespace = {}
    exec(compile(source, str(DOC), "exec"), namespace)
    return namespace["MemoryStore"]


MemoryStore = _store_class_from_the_docs()

_counter = iter(range(1_000_000))


@pytest.fixture(autouse=True)
def real_session(monkeypatch):
    """Other tests replace quart.session with a plain dict; these need the session cookie."""
    monkeypatch.setattr(quart, "session", quart.globals.session)


@pytest.fixture
def clock(monkeypatch):
    """Lets a test move time on, for the store and for asfquart alike"""
    class Clock:
        now = time.time()

    monkeypatch.setattr(time, "time", lambda: Clock.now)
    return Clock


class _Provider:
    """Stands in for aiohttp.client.ClientSession: the OAuth provider says who the user is"""

    status = 200
    data = {"uid": "testuser", "fullname": "Test User", "pmcs": ["httpd"], "projects": ["httpd", "tomcat"], "isMember": True}

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        return self

    async def json(self):
        return dict(self.data)


def _app(store=None, **kwargs):
    app = asfquart.construct(f"test_session_store_{next(_counter)}", token_file=None, **kwargs)
    app.sessions = store if store is not None else MemoryStore()

    @app.route("/write")
    async def write():
        await asfquart.session.awrite({"uid": quart.request.args.get("uid", "testuser")})
        return "ok"

    @app.route("/whoami")
    async def whoami():
        session = await asfquart.session.read()
        return {"uid": session.uid if session else None, "cookie": quart.session.get(app.app_id)}

    @app.route("/clear")
    async def clear():
        await asfquart.session.aclear()
        return "ok"

    @app.route("/replace")
    async def replace():
        session = await asfquart.session.read()
        changed = asfquart.session.ClientSession({"uid": session.uid, "fullname": "Changed"})
        await asfquart.session.areplace(changed)
        return "ok"

    @app.route("/login-as")
    async def login_as():
        """Gives the browser a session made by the application, without reading the one it has"""
        await asfquart.session.areplace(asfquart.session.ClientSession({"uid": quart.request.args["uid"]}))
        return "ok"

    @app.route("/members")
    @asfquart.auth.require(asfquart.auth.Requirements.member)
    async def members():
        return "members only"

    return app


async def _json(client, path):
    resp = await client.get(path, scheme="https")
    assert resp.status_code == 200
    return await resp.get_json()


async def _oauth_login(client, monkeypatch):
    monkeypatch.setattr(asfquart.generics.aiohttp.client, "ClientSession", _Provider())
    start = await client.get("/auth?login", scheme="https")
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(start.headers["Location"]).query)["state"][0]
    resp = await client.get(f"/auth?state={state}&code=abc", scheme="https")
    assert resp.status_code == 200


def _hash(sid):
    return hashlib.sha3_256(sid.encode("utf-8")).hexdigest()


# ---- What is in the cookie, and what the store is given ----

@pytest.mark.session
async def test_cookie_holds_only_a_session_id(monkeypatch):
    """With a store, nothing about the user is in the cookie, and the store never has the session id."""
    app = _app()
    client = app.test_client()
    await _oauth_login(client, monkeypatch)
    cookie = (await _json(client, "/whoami"))["cookie"]
    assert list(cookie) == ["sid"]
    (hsid,) = app.sessions._sessions
    assert hsid == _hash(cookie["sid"])
    assert re.fullmatch(r"[0-9a-f]{64}", hsid)
    assert cookie["sid"] not in app.sessions._sessions


@pytest.mark.session
async def test_oauth_login_reads_back_through_the_store(monkeypatch):
    """A login creates the session in the store, and reading, the /auth display and @require all use it."""
    app = _app()
    client = app.test_client()
    await _oauth_login(client, monkeypatch)
    assert (await _json(client, "/whoami"))["uid"] == "testuser"
    shown = await _json(client, "/auth")
    assert shown["uid"] == "testuser"
    assert shown["committees"] == ["httpd"]        # the provider's "pmcs"
    assert (await client.get("/members", scheme="https")).status_code == 200


@pytest.mark.session
async def test_logout_removes_the_session_from_the_store(monkeypatch):
    app = _app()
    client = app.test_client()
    await _oauth_login(client, monkeypatch)
    assert len(app.sessions._sessions) == 1
    assert (await client.get("/auth?logout", scheme="https")).status_code == 200
    assert app.sessions._sessions == {}
    assert (await _json(client, "/whoami")) == {"uid": None, "cookie": None}


@pytest.mark.session
async def test_logging_in_again_gives_a_new_session_id(monkeypatch):
    """The old session is destroyed, and the new one has another id."""
    app = _app()
    client = app.test_client()
    await _oauth_login(client, monkeypatch)
    first = (await _json(client, "/whoami"))["cookie"]["sid"]
    await _oauth_login(client, monkeypatch)
    second = (await _json(client, "/whoami"))["cookie"]["sid"]
    assert second != first
    assert list(app.sessions._sessions) == [_hash(second)]


# ---- The functions to use with a store ----

@pytest.mark.session
async def test_awrite_and_aclear():
    app = _app(oauth=False)
    client = app.test_client()
    await client.get("/write?uid=alice", scheme="https")
    assert (await _json(client, "/whoami"))["uid"] == "alice"
    await client.get("/clear", scheme="https")
    assert (await _json(client, "/whoami"))["uid"] is None
    assert app.sessions._sessions == {}
    await client.get("/clear", scheme="https")     # with no session: not an error


@pytest.mark.session
async def test_write_and_clear_are_refused_with_a_store():
    app = _app(oauth=False)
    async with app.test_request_context("/"):
        with pytest.raises(RuntimeError, match="awrite"):
            asfquart.session.write({"uid": "testuser"})
        with pytest.raises(RuntimeError, match="aclear"):
            asfquart.session.clear()


@pytest.mark.session
async def test_areplace_uses_replace(clock):
    """areplace() puts a new session, under a new id, in place of the old one, and keeps its age."""
    app = _app(oauth=False)
    client = app.test_client()
    await client.get("/write", scheme="https")
    before = (await _json(client, "/whoami"))["cookie"]["sid"]
    created = app.sessions._sessions[_hash(before)][0]
    clock.now += 3600
    await client.get("/replace", scheme="https")
    after = (await _json(client, "/whoami"))["cookie"]["sid"]
    assert after != before
    assert list(app.sessions._sessions) == [_hash(after)]
    assert app.sessions._sessions[_hash(after)][0] == created
    assert app.sessions._sessions[_hash(after)][3].fullname == "Changed"
    assert (await _json(client, "/whoami"))["uid"] == "testuser"


@pytest.mark.session
async def test_areplace_falls_back_to_destroy_and_register():
    """A store without replace() has its destroy() and register() called instead."""
    calls = []

    class RegisterStore:
        """The three methods that every store has, and register(), but no replace()"""

        def __init__(self):
            self._store = MemoryStore()
            self._sessions = self._store._sessions

        async def create(self, hsid, session_data):
            await self._store.create(hsid, session_data)

        async def validate(self, hsid):
            return await self._store.validate(hsid)

        async def destroy(self, hsid):
            calls.append("destroy")
            await self._store.destroy(hsid)

        async def register(self, hsid, session):
            calls.append("register")
            self._sessions[hsid] = [time.time(), time.time(), None, session]

    store = RegisterStore()
    app = _app(store=store, oauth=False)
    client = app.test_client()
    await client.get("/write", scheme="https")
    calls.clear()
    resp = await client.get("/replace", scheme="https")
    assert resp.status_code == 200
    assert calls == ["destroy", "register"]
    assert len(store._sessions) == 1
    assert (await _json(client, "/whoami"))["uid"] == "testuser"


@pytest.mark.session
async def test_areplace_must_not_be_used_without_replace_or_register():
    """With neither method areplace() fails, and only after it has removed the user's session."""
    class PlainStore:
        def __init__(self):
            self._store = MemoryStore()
            self._sessions = self._store._sessions
            self.create, self.validate, self.destroy = self._store.create, self._store.validate, self._store.destroy

    store = PlainStore()
    app = _app(store=store, oauth=False)
    client = app.test_client()
    await client.get("/write", scheme="https")
    assert (await _json(client, "/whoami"))["uid"] == "testuser"
    assert len(store._sessions) == 1
    assert (await client.get("/replace", scheme="https")).status_code == 500
    assert store._sessions == {}                                    # destroy() had already been called
    assert (await _json(client, "/whoami")) == {"uid": None, "cookie": None}
    await client.get("/write", scheme="https")                      # the other functions work without them
    assert (await _json(client, "/whoami"))["uid"] == "testuser"
    await client.get("/clear", scheme="https")
    assert (await _json(client, "/whoami"))["uid"] is None


@pytest.mark.session
async def test_areplace_without_a_session_makes_one():
    """old_hsid is None when the browser had no session: there is nothing to replace, and no reason to refuse."""
    app = _app(oauth=False)
    client = app.test_client()
    await client.get("/login-as?uid=alice", scheme="https")
    assert (await _json(client, "/whoami"))["uid"] == "alice"
    assert len(app.sessions._sessions) == 1


@pytest.mark.session
async def test_replace_does_not_bring_back_a_revoked_session():
    """A session that is revoked after the application read it is not replaced by a new one."""
    store = MemoryStore()
    app = _app(store=store, oauth=False)

    @app.route("/replace-after-revoke")
    async def replace_after_revoke():
        session = await asfquart.session.read()
        store.revoke(session.uid)                                   # as another request might, in between
        await asfquart.session.areplace(asfquart.session.ClientSession({"uid": session.uid}))
        return "ok"

    client = app.test_client()
    await client.get("/write", scheme="https")
    assert (await client.get("/replace-after-revoke", scheme="https")).status_code == 200
    assert store._sessions == {}
    assert (await _json(client, "/whoami")) == {"uid": None, "cookie": None}


@pytest.mark.session
async def test_replace_does_not_bring_back_a_session_that_has_timed_out(clock):
    """A session that has ended, and has not been purged yet, is not replaced either."""
    store = MemoryStore(max_idle=3600, max_age=DAY)
    app = _app(store=store, oauth=False)
    client = app.test_client()
    await client.get("/write", scheme="https")
    clock.now += 3601
    assert len(store._sessions) == 1                                # ended, and still in the store
    assert (await client.get("/login-as?uid=testuser", scheme="https")).status_code == 200
    assert store._sessions == {}
    assert (await _json(client, "/whoami")) == {"uid": None, "cookie": None}
    await client.get("/login-as?uid=testuser", scheme="https")      # the cookie is clear now: a new session
    assert (await _json(client, "/whoami"))["uid"] == "testuser"


@pytest.mark.session
async def test_areplace_refuses_a_session_without_a_uid():
    """A plain dictionary has no uid attribute, so it's refused - and the session the user had is kept"""
    store = MemoryStore()
    app = _app(store=store, oauth=False)

    @app.route("/replace-with-dict")
    async def replace_with_dict():
        try:
            await asfquart.session.areplace({"uid": "alice", "note": "a plain dictionary"})
        except TypeError as e:
            return str(e)
        return "replaced"

    alice = app.test_client()
    await alice.get("/write?uid=alice", scheme="https")
    before = (await _json(alice, "/whoami"))["cookie"]
    resp = await alice.get("/replace-with-dict", scheme="https")
    assert "SessionProtocol" in (await resp.get_data()).decode()
    assert (await _json(alice, "/whoami")) == {"uid": "alice", "cookie": before}
    assert store.revoke("alice") == 1


@pytest.mark.session
async def test_store_that_is_false_is_taken_for_no_store():
    """asfquart tests the store's truth value, so an empty store with a length is not used at all."""
    class CountedStore(MemoryStore):
        def __len__(self):
            return len(self._sessions)

    store = CountedStore()
    app = _app(store=store, oauth=False)
    client = app.test_client()
    await client.get("/write", scheme="https")
    whoami = await _json(client, "/whoami")
    assert whoami["uid"] == "testuser"
    assert store._sessions == {}                                    # the store was never called
    assert "sid" not in whoami["cookie"]
    assert whoami["cookie"]["uid"] == "testuser"                    # the session is in the cookie
    assert bool(MemoryStore()) is True                              # no __len__, no __bool__: always true


# ---- What the store looks after: time limits, and ending sessions ----

@pytest.mark.session
async def test_store_applies_the_idle_timeout(clock):
    app = _app(store=MemoryStore(max_idle=3600, max_age=DAY), oauth=False)
    client = app.test_client()
    await client.get("/write", scheme="https")
    for _ in range(5):
        clock.now += 3000                                   # used within the hour, each time
        assert (await _json(client, "/whoami"))["uid"] == "testuser"
    clock.now += 3601
    gone = await _json(client, "/whoami")
    assert gone == {"uid": None, "cookie": None}            # and asfquart has taken the id out of the cookie
    assert app.sessions._sessions == {}


@pytest.mark.session
async def test_store_applies_the_maximum_lifetime(clock):
    app = _app(store=MemoryStore(max_idle=3600, max_age=DAY), oauth=False)
    client = app.test_client()
    await client.get("/write", scheme="https")
    for _ in range(28):
        clock.now += 3000                                   # in use all day
        assert (await _json(client, "/whoami"))["uid"] == "testuser"
    clock.now += 3000                                       # 87000 seconds after the login
    assert (await _json(client, "/whoami"))["uid"] is None


@pytest.mark.session
async def test_asfquart_limits_are_not_applied_with_a_store(clock):
    """MAX_SESSION_AGE and the expiry_time argument are for cookie sessions: the store decides."""
    app = _app(store=MemoryStore(max_idle=30 * DAY, max_age=30 * DAY), oauth=False)
    app.cfg["MAX_SESSION_AGE"] = 10

    @app.route("/recent")
    async def recent():
        session = await asfquart.session.read(expiry_time=10)
        return {"uid": session.uid if session else None}

    client = app.test_client()
    await client.get("/write", scheme="https")
    clock.now += DAY
    assert (await _json(client, "/recent"))["uid"] == "testuser"


@pytest.mark.session
async def test_abandoned_sessions_are_purged(clock):
    """Sessions that are never asked for again do not stay in the store for ever."""
    store = MemoryStore(max_idle=3600, max_age=DAY)
    app = _app(store=store, oauth=False)
    for _ in range(5):
        await app.test_client().get("/write", scheme="https")   # five browsers, never seen again
    assert len(store._sessions) == 5
    clock.now += 3601
    assert store.purge() == 5
    assert store._sessions == {}
    for _ in range(3):
        await app.test_client().get("/write", scheme="https")
    clock.now += 3601
    await app.test_client().get("/write", scheme="https")       # create() purges as well
    assert len(store._sessions) == 1


@pytest.mark.session
async def test_revoked_session_stops_working_at_the_next_request():
    store = MemoryStore()
    app = _app(store=store, oauth=False)
    alice, bob = app.test_client(), app.test_client()
    await alice.get("/write?uid=alice", scheme="https")
    await bob.get("/write?uid=bob", scheme="https")
    assert store.revoke("alice") == 1
    assert (await _json(alice, "/whoami")) == {"uid": None, "cookie": None}
    assert (await _json(bob, "/whoami"))["uid"] == "bob"


@pytest.mark.session
async def test_made_up_session_id_is_not_a_session():
    """A cookie with an id that the store does not know is not logged in, and the id is dropped."""
    app = _app(oauth=False)
    client = app.test_client()
    async with client.session_transaction(scheme="https") as stored:
        stored[app.app_id] = {"sid": "made-up"}
    assert (await _json(client, "/whoami")) == {"uid": None, "cookie": None}


@pytest.mark.session
async def test_error_in_the_store_is_a_500():
    """asfquart does not catch what the store raises."""
    class BrokenStore(MemoryStore):
        async def validate(self, hsid):
            raise ConnectionError("database unavailable")

    app = _app(store=BrokenStore(), oauth=False)
    client = app.test_client()
    await client.get("/write", scheme="https")
    assert (await client.get("/whoami", scheme="https")).status_code == 500


@pytest.mark.session
async def test_create_that_fails_leaves_no_cookie():
    """The session id goes into the cookie only once create() has returned."""
    class FullStore(MemoryStore):
        async def create(self, hsid, session_data):
            raise ConnectionError("database unavailable")

    app = _app(store=FullStore(), oauth=False)
    client = app.test_client()
    assert (await client.get("/write", scheme="https")).status_code == 500
    assert (await _json(client, "/whoami")) == {"uid": None, "cookie": None}


# ---- The session object ----

@pytest.mark.session
async def test_store_keeps_the_data_and_makes_the_session_from_it(monkeypatch):
    """The documented store does what the page advises: it keeps the dictionary create() was given."""
    store = MemoryStore()
    app = _app(store=store)

    @app.route("/scribble")
    async def scribble():
        session = await asfquart.session.read()
        session.committees.append("not-a-real-committee")
        session["uid"] = session.uid = "somebody-else"
        return "ok"

    client = app.test_client()
    await _oauth_login(client, monkeypatch)
    (entry,) = store._sessions.values()
    assert type(entry[2]) is dict and entry[3] is None
    assert entry[2]["pmcs"] == ["httpd"]                            # the provider's name for it
    hsid = next(iter(store._sessions))
    first, second = await store.validate(hsid), await store.validate(hsid)
    assert isinstance(first, asfquart.session.ClientSession)
    assert first == second and first is not second                  # made anew each time
    assert first.committees == ["httpd"]
    await client.get("/scribble", scheme="https")                   # a request changes its own copy only
    assert (await _json(client, "/whoami"))["uid"] == "testuser"
    assert (await store.validate(hsid)).committees == ["httpd"]
    assert store.revoke("testuser") == 1


@pytest.mark.session
def test_client_session_does_not_turn_back_into_its_data():
    """Keep the dictionary that create() was given: a ClientSession made from a ClientSession loses things."""
    data = {"uid": "testuser", "pmcs": ["httpd"], "roleaccount": True}
    session = asfquart.session.ClientSession(data)
    assert session.committees == ["httpd"]
    assert session.isRole is True
    again = asfquart.session.ClientSession(session)
    assert again.committees == []
    assert again.isRole is False
