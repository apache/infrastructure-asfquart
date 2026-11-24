#!/usr/bin/env python3
"""Tests for ldap.py: the username is validated before it is placed in a DN"""

import base64
import types

import pytest

import asfquart
import asfquart.ldap

INVALID_USERNAMES = [
    "",
    "a",  # too short
    "4user",  # must start with a letter
    "-user",
    "_user",
    "TestUser",  # upper case
    "test user",
    "test.user",
    "testuser,ou=people,dc=apache,dc=org",  # would add components to the DN
    "testuser,ou=project",
    "uid=testuser",
    "testuser+cn=admin",  # multi-valued RDN
    "*",  # LDAP filter characters
    "test*",
    "test)(uid=*",
    "test\\2Cuser",  # DN escape
    "testuser\n",
    "testuser\x00",
    "testéuser",
    "ｔｅｓｔ",  # full width letters
]

VALID_USERNAMES = ["testuser", "abc", "ab", "a1", "test-user", "test_user", "user42", "t" * 100]


@pytest.fixture
def ldap_clients(monkeypatch):
    """Replaces asfpy.aioldap, and records the LDAP clients that asfquart creates"""
    created = []

    def fake_ldap_client(uri, dn, password):
        created.append((uri, dn, password))
        return object()

    fake_asfpy = types.SimpleNamespace(aioldap=types.SimpleNamespace(LDAPClient=fake_ldap_client))
    monkeypatch.setattr(asfquart.ldap, "asfpy", fake_asfpy, raising=False)
    return created


@pytest.mark.auth
@pytest.mark.parametrize("username", INVALID_USERNAMES)
def test_invalid_username_is_rejected(ldap_clients, username):
    """A username that is not a plain user id never reaches a DN, or LDAP"""
    with pytest.raises(asfquart.base.ASFQuartException) as excinfo:
        asfquart.ldap.LDAPClient(username, "password")
    assert excinfo.value.errorcode == 403
    assert excinfo.value.message == "Invalid credentials provided"
    assert ldap_clients == []


@pytest.mark.auth
@pytest.mark.parametrize("username", [None, 12345, b"testuser", ["testuser"]])
def test_username_must_be_a_string(ldap_clients, username):
    with pytest.raises(asfquart.base.ASFQuartException) as excinfo:
        asfquart.ldap.LDAPClient(username, "password")
    assert excinfo.value.errorcode == 403
    assert ldap_clients == []


@pytest.mark.auth
@pytest.mark.parametrize("password", ["", None, b"password", 12345])
def test_empty_password_is_rejected(ldap_clients, password):
    """An empty password is refused before LDAP is contacted: a bind without a password is an
    unauthenticated bind, which a server may accept."""
    with pytest.raises(asfquart.base.ASFQuartException) as excinfo:
        asfquart.ldap.LDAPClient("testuser", password)
    assert excinfo.value.errorcode == 403
    assert excinfo.value.message == "Invalid credentials provided"
    assert ldap_clients == []


@pytest.mark.auth
@pytest.mark.parametrize("password", [" ", "0", "p", "pass word", "p\u00e4ss"])
def test_non_empty_password_is_passed_on(ldap_clients, password):
    """Any password that is not empty goes to LDAP as it is, for LDAP to judge"""
    asfquart.ldap.LDAPClient("testuser", password)
    assert [created[2] for created in ldap_clients] == [password]


@pytest.mark.auth
@pytest.mark.parametrize("username", VALID_USERNAMES)
def test_valid_username_is_accepted(ldap_clients, username):
    client = asfquart.ldap.LDAPClient(username, "password")
    assert client.userid == username
    assert client.dn == f"uid={username},ou=people,dc=apache,dc=org"
    assert ldap_clients == [(asfquart.ldap.DEFAULT_LDAP_URI, client.dn, "password")]


@pytest.mark.auth
@pytest.mark.parametrize("username", ["testuser,ou=project", "uid=testuser", "test*", "a"])
async def test_basic_auth_with_invalid_username(monkeypatch, ldap_clients, username):
    """Through the Authorization header: a 403, as for a wrong password, and no LDAP connection"""
    monkeypatch.setattr(asfquart.ldap, "LDAP_SUPPORTED", True)
    app = asfquart.construct("ldap_username", token_file=None, basic_auth=True)
    credentials = base64.b64encode(f"{username}:password".encode()).decode()
    async with app.test_request_context("/", headers={"Authorization": f"Basic {credentials}"}):
        with pytest.raises(asfquart.base.ASFQuartException) as excinfo:
            await asfquart.session.read()
    assert excinfo.value.errorcode == 403
    assert excinfo.value.message == "Invalid credentials provided"
    assert ldap_clients == []


@pytest.mark.auth
async def test_basic_auth_with_empty_password(monkeypatch, ldap_clients):
    """Through the Authorization header: "testuser:" is a 403, and no LDAP connection"""
    monkeypatch.setattr(asfquart.ldap, "LDAP_SUPPORTED", True)
    app = asfquart.construct("ldap_empty_password", token_file=None, basic_auth=True)
    credentials = base64.b64encode(b"testuser:").decode()
    async with app.test_request_context("/", headers={"Authorization": f"Basic {credentials}"}):
        with pytest.raises(asfquart.base.ASFQuartException) as excinfo:
            await asfquart.session.read()
    assert excinfo.value.errorcode == 403
    assert excinfo.value.message == "Invalid credentials provided"
    assert ldap_clients == []


# ---- The cache of LDAP lookups: expired ones are removed, and there is a limit to how many are kept ----


class _Clock:
    """Stands in for the time module inside asfquart.ldap"""

    def __init__(self, now=100000.0):
        self.now = now

    def time(self):
        return self.now


class _FakeDirectory:
    """Stands in for asfpy.aioldap: every user is a member of one project, and searches are counted"""

    def __init__(self):
        self.binds = []
        self.searches = []

    def LDAPClient(self, uri, dn, password):  # noqa: N802 - stands in for bonsai.LDAPClient
        directory = self

        class Connection:
            async def __aenter__(self):
                directory.binds.append(dn)
                return self

            async def __aexit__(self, *exc):
                return False

            async def search(self, base, attrs):
                directory.searches.append(dn)
                return [{"dn": "cn=testproject,ou=project,ou=groups,dc=apache,dc=org", "member": [dn], "owner": []}]

        return types.SimpleNamespace(connect=Connection)


@pytest.fixture
def directory(monkeypatch):
    """A fake LDAP directory, a clock that the test can move, and an empty cache"""
    fake = _FakeDirectory()
    clock = _Clock()
    monkeypatch.setattr(asfquart.ldap, "asfpy", types.SimpleNamespace(aioldap=fake), raising=False)
    monkeypatch.setattr(
        asfquart.ldap,
        "bonsai",
        types.SimpleNamespace(errors=types.SimpleNamespace(AuthenticationError=PermissionError)),
        raising=False,
    )
    monkeypatch.setattr(asfquart.ldap, "time", clock)
    monkeypatch.setattr(asfquart.ldap, "LDAP_CACHE", {})
    fake.clock = clock
    return fake


async def _lookup(username):
    return await asfquart.ldap.LDAPClient(username, "password").get_affiliations()


@pytest.mark.auth
async def test_ldap_lookup_is_cached(directory):
    """The memberships are looked up once an hour per user; the password is checked every time."""
    assert await _lookup("alice") == {"member": ["testproject"], "owner": []}
    assert await _lookup("alice") == {"member": ["testproject"], "owner": []}
    assert len(directory.searches) == 1
    assert len(directory.binds) == 2
    directory.clock.now += asfquart.ldap.DEFAULT_LDAP_CACHE_TTL + 1
    await _lookup("alice")
    assert len(directory.searches) == 2
    assert list(asfquart.ldap.LDAP_CACHE) == ["alice"]


@pytest.mark.auth
async def test_expired_ldap_lookups_are_removed(directory):
    """A lookup that has expired goes when anybody next authenticates, not only when its own user returns."""
    for username in ("alice", "bob", "carol"):
        await _lookup(username)
        directory.clock.now += 60
    assert list(asfquart.ldap.LDAP_CACHE) == ["alice", "bob", "carol"]
    directory.clock.now += asfquart.ldap.DEFAULT_LDAP_CACHE_TTL - 100  # alice and bob have expired, carol has not
    await _lookup("dave")
    assert list(asfquart.ldap.LDAP_CACHE) == ["carol", "dave"]
    directory.clock.now += asfquart.ldap.DEFAULT_LDAP_CACHE_TTL + 1
    await _lookup("dave")
    assert list(asfquart.ldap.LDAP_CACHE) == ["dave"]


@pytest.mark.auth
async def test_ldap_cache_is_limited(directory, monkeypatch):
    """With more users than the limit, the oldest lookups are dropped. They are looked up again when needed."""
    monkeypatch.setattr(asfquart.ldap, "DEFAULT_LDAP_CACHE_MAX_ENTRIES", 3)
    users = [f"user{index}" for index in range(10)]
    for username in users:
        await _lookup(username)
        directory.clock.now += 1
        assert len(asfquart.ldap.LDAP_CACHE) <= 3
    assert list(asfquart.ldap.LDAP_CACHE) == users[-3:]
    # A user who was dropped is not refused: the lookup is made again, and cached again
    searches = len(directory.searches)
    assert await _lookup("user0") == {"member": ["testproject"], "owner": []}
    assert len(directory.searches) == searches + 1
    assert list(asfquart.ldap.LDAP_CACHE) == ["user8", "user9", "user0"]


@pytest.mark.auth
async def test_renewed_ldap_lookup_counts_as_the_newest(directory, monkeypatch):
    """A lookup that is renewed after it expired goes to the back of the queue."""
    monkeypatch.setattr(asfquart.ldap, "DEFAULT_LDAP_CACHE_MAX_ENTRIES", 3)
    await _lookup("alice")
    directory.clock.now += asfquart.ldap.DEFAULT_LDAP_CACHE_TTL - 10
    await _lookup("bob")
    await _lookup("carol")
    directory.clock.now += 20  # alice has expired; she comes back, and is looked up again
    await _lookup("alice")
    assert list(asfquart.ldap.LDAP_CACHE) == ["bob", "carol", "alice"]
    await _lookup("dave")  # the cache is full: bob is now the oldest, not alice
    assert list(asfquart.ldap.LDAP_CACHE) == ["carol", "alice", "dave"]


@pytest.mark.auth
async def test_failed_ldap_lookup_is_not_cached(directory, monkeypatch):
    """Only a lookup that succeeded is cached, so the cache cannot be filled by guessing usernames."""

    def refuse(uri, dn, password):
        class Connection:
            async def __aenter__(self):
                raise PermissionError("invalid credentials")

            async def __aexit__(self, *exc):
                return False

        return types.SimpleNamespace(connect=Connection)

    monkeypatch.setattr(directory, "LDAPClient", refuse)
    for index in range(20):
        with pytest.raises(asfquart.base.ASFQuartException) as excinfo:
            await _lookup(f"guess{index}")
        assert excinfo.value.errorcode == 403
    assert asfquart.ldap.LDAP_CACHE == {}


@pytest.mark.auth
async def test_cached_user_is_not_failed_by_an_eviction_during_the_password_check(directory, monkeypatch):
    """While a cached user's password is being checked, another request can push their lookup out of
    the cache. The first request already has the lookup, and must answer with it, not with a 500."""
    import asyncio

    monkeypatch.setattr(asfquart.ldap, "DEFAULT_LDAP_CACHE_MAX_ENTRIES", 1)
    await _lookup("alice")  # alice is cached
    hold = asyncio.Event()
    waiting = asyncio.Event()
    plain_client = directory.LDAPClient

    def slow_for_alice(uri, dn, password):
        client = plain_client(uri, dn, password)
        if not dn.startswith("uid=alice,"):
            return client
        connection = client.connect

        class HeldOpen(connection):
            async def __aenter__(self):
                waiting.set()
                await hold.wait()  # the bind does not come back yet
                return await super().__aenter__()

        return types.SimpleNamespace(connect=HeldOpen)

    monkeypatch.setattr(directory, "LDAPClient", slow_for_alice)
    alice = asyncio.ensure_future(_lookup("alice"))  # cache hit; now checking the password
    await waiting.wait()
    await _lookup("bob")  # the cache holds one: alice goes
    assert "alice" not in asfquart.ldap.LDAP_CACHE
    hold.set()
    assert await alice == {"member": ["testproject"], "owner": []}


@pytest.mark.auth
async def test_ldap_cache_drops_the_least_recently_used(directory, monkeypatch):
    """When the cache is full, the lookup to go is the one that has gone longest without being used,
    and not the one that was made first: a user who keeps coming back keeps their place."""
    monkeypatch.setattr(asfquart.ldap, "DEFAULT_LDAP_CACHE_MAX_ENTRIES", 3)
    for username in ("alice", "bob", "carol"):
        await _lookup(username)
        directory.clock.now += 1
    await _lookup("alice")  # alice is back: a cache hit, and a use
    assert list(asfquart.ldap.LDAP_CACHE) == ["bob", "carol", "alice"]
    searches = len(directory.searches)
    await _lookup("dave")  # the cache is full: bob goes, not alice
    assert list(asfquart.ldap.LDAP_CACHE) == ["carol", "alice", "dave"]
    await _lookup("alice")
    assert len(directory.searches) == searches + 1  # only dave was looked up; alice was still cached


@pytest.mark.auth
async def test_using_a_lookup_does_not_make_it_last_longer(directory):
    """Being used keeps a lookup from being dropped for want of room. It does not keep it past its hour."""
    await _lookup("alice")
    for _ in range(5):
        directory.clock.now += asfquart.ldap.DEFAULT_LDAP_CACHE_TTL / 6
        await _lookup("alice")  # used every ten minutes
    assert len(directory.searches) == 1
    directory.clock.now += asfquart.ldap.DEFAULT_LDAP_CACHE_TTL / 6 + 1
    await _lookup("alice")  # an hour after the lookup: made again
    assert len(directory.searches) == 2


@pytest.mark.auth
async def test_expired_lookup_is_removed_wherever_it_is_in_the_order(directory):
    """An expired lookup is found even when a recently used one is in front of it."""
    await _lookup("alice")
    directory.clock.now += 1800
    await _lookup("bob")
    directory.clock.now += 1000
    await _lookup("alice")  # used: alice is now behind bob in the order
    assert list(asfquart.ldap.LDAP_CACHE) == ["bob", "alice"]
    directory.clock.now += 900  # alice's lookup is 3700 seconds old, bob's 1900
    await _lookup("carol")
    assert list(asfquart.ldap.LDAP_CACHE) == ["bob", "carol"]


@pytest.mark.auth
async def test_wrong_password_for_a_cached_user_is_not_a_use(directory, monkeypatch):
    """A failed password check answers 403, and does not move the cached lookup up the order."""
    monkeypatch.setattr(asfquart.ldap, "DEFAULT_LDAP_CACHE_MAX_ENTRIES", 2)
    await _lookup("alice")
    await _lookup("bob")
    plain_client = directory.LDAPClient

    def refuse_alice(uri, dn, password):
        if not dn.startswith("uid=alice,"):
            return plain_client(uri, dn, password)

        class Refused:
            async def __aenter__(self):
                raise PermissionError("invalid credentials")

            async def __aexit__(self, *exc):
                return False

        return types.SimpleNamespace(connect=Refused)

    monkeypatch.setattr(directory, "LDAPClient", refuse_alice)
    with pytest.raises(asfquart.base.ASFQuartException) as excinfo:
        await _lookup("alice")
    assert excinfo.value.errorcode == 403
    assert list(asfquart.ldap.LDAP_CACHE) == ["alice", "bob"]


# ---- HTTP Basic authentication is off unless the app asks for it ----

BASIC_CREDENTIALS = "Basic " + base64.b64encode(b"testuser:password").decode()


@pytest.mark.auth
@pytest.mark.parametrize("kwargs", [{}, {"basic_auth": False}])
@pytest.mark.parametrize("ldap_supported", [True, False])
async def test_basic_auth_is_off_by_default(monkeypatch, ldap_clients, kwargs, ldap_supported):
    """Without basic_auth=True a Basic header is a 401, with or without the LDAP libraries, and LDAP is not contacted"""
    monkeypatch.setattr(asfquart.ldap, "LDAP_SUPPORTED", ldap_supported)
    app = asfquart.construct("ldap_basic_off", token_file=None, **kwargs)
    assert app.basic_auth is False
    async with app.test_request_context("/", headers={"Authorization": BASIC_CREDENTIALS}):
        with pytest.raises(asfquart.base.ASFQuartException) as excinfo:
            await asfquart.session.read()
    assert excinfo.value.errorcode == 401
    assert excinfo.value.message == "Basic authentication is not enabled"
    assert ldap_clients == []


@pytest.mark.auth
async def test_basic_auth_off_is_a_401_response(monkeypatch, ldap_clients):
    """Through a protected endpoint: a 401 in plain text, and no redirect to the OAuth login"""
    monkeypatch.setattr(asfquart.ldap, "LDAP_SUPPORTED", True)
    app = asfquart.construct("ldap_basic_off_response", token_file=None)

    @app.route("/protected")
    @asfquart.auth.require
    async def protected():
        return "in"

    resp = await app.test_client().get("/protected", headers={"Authorization": BASIC_CREDENTIALS})
    assert resp.status_code == 401
    assert (await resp.get_data()).decode() == "Basic authentication is not enabled"
    assert "Location" not in resp.headers
    assert ldap_clients == []


@pytest.mark.auth
async def test_basic_auth_when_asked_for(monkeypatch):
    """With basic_auth=True a Basic header is checked against LDAP, and makes a session"""
    seen = []

    class FakeLDAPClient:
        def __init__(self, username, password):
            seen.append((username, password))

        async def get_affiliations(self):
            return {asfquart.ldap.DEFAULT_OWNER_ATTR: ["httpd"], asfquart.ldap.DEFAULT_MEMBER_ATTR: ["httpd", "tomcat"]}

    monkeypatch.setattr(asfquart.ldap, "LDAP_SUPPORTED", True)
    monkeypatch.setattr(asfquart.ldap, "LDAPClient", FakeLDAPClient)
    app = asfquart.construct("ldap_basic_on", token_file=None, basic_auth=True)
    assert app.basic_auth is True
    async with app.test_request_context("/", headers={"Authorization": BASIC_CREDENTIALS}):
        session = await asfquart.session.read()
    assert seen == [("testuser", "password")]
    assert session.uid == "testuser"
    assert session.committees == ["httpd"]
    assert session.projects == ["httpd", "tomcat"]
    assert session.mfa is False  # a password alone: Requirements.mfa_protected is not met


@pytest.mark.auth
def test_basic_auth_without_the_ldap_libraries_fails_at_startup(monkeypatch):
    """Asking for Basic authentication where it cannot work is an error when the app is constructed"""
    monkeypatch.setattr(asfquart.ldap, "LDAP_SUPPORTED", False)
    with pytest.raises(RuntimeError, match=r"basic_auth=True needs the LDAP libraries.*asfquart\[aioldap\]"):
        asfquart.construct("ldap_basic_on_no_libraries", token_file=None, basic_auth=True)


@pytest.mark.auth
@pytest.mark.parametrize("kwargs", [{}, {"basic_auth": False}])
def test_no_ldap_libraries_are_needed_with_basic_auth_off(monkeypatch, kwargs):
    monkeypatch.setattr(asfquart.ldap, "LDAP_SUPPORTED", False)
    assert asfquart.construct("ldap_basic_off_no_libraries", token_file=None, **kwargs).basic_auth is False


@pytest.mark.auth
async def test_basic_auth_turned_on_later_without_the_ldap_libraries(monkeypatch, ldap_clients, caplog):
    """An app that sets app.basic_auth itself is not checked at startup. A Basic header is then a 500
    that is explained in the log, and not a request with no session."""
    monkeypatch.setattr(asfquart.ldap, "LDAP_SUPPORTED", False)
    app = asfquart.construct("ldap_basic_on_later", token_file=None)
    app.basic_auth = True

    @app.route("/protected")
    @asfquart.auth.require
    async def protected():
        return "in"

    client = app.test_client()
    resp = await client.get("/protected", headers={"Authorization": BASIC_CREDENTIALS})
    assert resp.status_code == 500
    assert (await resp.get_data()).decode() == "Basic authentication is not available"
    assert "LDAP libraries (asfquart[aioldap]) are not installed" in caplog.text
    assert "password" not in caplog.text and "dGVzdHVzZXI6cGFzc3dvcmQ=" not in caplog.text
    assert ldap_clients == []
    # A request without a Basic header is not affected
    assert (await client.get("/protected", headers={"x-no-redirect": "1"})).status_code != 500


@pytest.mark.auth
async def test_other_credentials_do_not_depend_on_basic_auth():
    """A bearer token works as before with Basic authentication off"""
    app = asfquart.construct("ldap_basic_off_bearer", token_file=None)
    app.token_handler = lambda token: {"uid": "roleaccount"} if token == "good" else None
    async with app.test_request_context("/", headers={"Authorization": "Bearer good"}):
        assert (await asfquart.session.read()).uid == "roleaccount"


def test_quartapp_has_basic_auth_off():
    """An app made with QuartApp directly, and not construct(), has it off too"""
    assert asfquart.base.QuartApp("ldap_quartapp", token_file=None).basic_auth is False


# ---- Failed logins are logged ----


class _RefusingDirectory:
    """Stands in for asfpy.aioldap: refuses the password of every user, and counts the attempts"""

    def __init__(self, error):
        self.error = error
        self.binds = []

    def LDAPClient(self, uri, dn, password):  # noqa: N802 - stands in for bonsai.LDAPClient
        directory = self

        class Connection:
            async def __aenter__(self):
                directory.binds.append(dn)
                raise directory.error

            async def __aexit__(self, *exc):
                return False

        return types.SimpleNamespace(connect=Connection)


@pytest.fixture
def refusing(monkeypatch, directory):
    """An LDAP directory that refuses every password, with the clock of the directory fixture"""
    fake = _RefusingDirectory(PermissionError("Invalid credentials. (0x0031 [49])"))
    fake.clock = directory.clock
    monkeypatch.setattr(asfquart.ldap, "asfpy", types.SimpleNamespace(aioldap=fake), raising=False)
    monkeypatch.setattr(asfquart.ldap, "_FAILED_LOGINS", {})
    monkeypatch.setattr(asfquart.ldap, "_FAILED_LOGIN_LINES", [0.0, 0, 0])
    return fake


async def _refused(username):
    with pytest.raises(asfquart.base.ASFQuartException) as excinfo:
        await asfquart.ldap.LDAPClient(username, "hunter2-wrong-password").get_affiliations()
    return excinfo.value


def _failure_lines(caplog):
    return [r.getMessage() for r in caplog.records if r.name == "asfquart.ldap" and r.levelname == "WARNING"]


@pytest.mark.auth
async def test_failed_basic_login_is_logged(refusing, caplog):
    error = await _refused("alice")
    assert error.errorcode == 403
    assert _failure_lines(caplog) == [
        "HTTP Basic authentication failed for user alice: Invalid credentials. (0x0031 [49])"
    ]
    assert "hunter2" not in caplog.text


@pytest.mark.auth
async def test_failed_basic_login_response_does_not_say_what_ldap_said(refusing):
    """The response is the same as for a username that is refused without asking LDAP"""
    error = await _refused("alice")
    assert error.message == "Invalid credentials provided"
    assert isinstance(error.__cause__, PermissionError)


@pytest.mark.auth
async def test_failed_basic_logins_for_one_user_are_logged_once_a_minute(refusing, caplog):
    """A flood of guesses is a line a minute with a count, and every guess still reaches LDAP"""
    for _ in range(251):
        await _refused("alice")
    assert len(_failure_lines(caplog)) == 1
    refusing.clock.now += asfquart.ldap.FAILED_LOGIN_LOG_INTERVAL - 1
    await _refused("alice")
    assert len(_failure_lines(caplog)) == 1
    refusing.clock.now += 1
    await _refused("alice")
    lines = _failure_lines(caplog)
    assert len(lines) == 2
    assert lines[1].endswith("(and 251 more times since this was last logged)")
    assert len(refusing.binds) == 253
    # The count starts again
    refusing.clock.now += asfquart.ldap.FAILED_LOGIN_LOG_INTERVAL
    await _refused("alice")
    assert "more times" not in _failure_lines(caplog)[2]


@pytest.mark.auth
async def test_failed_basic_logins_are_counted_for_each_user(refusing, caplog):
    """One user being guessed at does not hide another"""
    for _ in range(5):
        await _refused("alice")
    await _refused("bob")
    lines = _failure_lines(caplog)
    assert len(lines) == 2
    assert "for user alice:" in lines[0]
    assert "for user bob:" in lines[1]


@pytest.mark.auth
async def test_failed_basic_login_records_are_bounded(refusing, monkeypatch, caplog):
    """Guessing at many user ids does not grow the record of failures without limit"""
    monkeypatch.setattr(asfquart.ldap, "MAX_FAILED_LOGIN_USERS", 3)
    for user in ("aa", "bb", "cc", "dd", "ee"):
        await _refused(user)
    assert list(asfquart.ldap._FAILED_LOGINS) == ["cc", "dd", "ee"]
    await _refused("dd")  # counted, not logged, and now the latest to fail
    assert list(asfquart.ldap._FAILED_LOGINS) == ["cc", "ee", "dd"]
    assert len(_failure_lines(caplog)) == 5
    await _refused("aa")  # was dropped, so it is logged again
    assert len(_failure_lines(caplog)) == 6
    assert list(asfquart.ldap._FAILED_LOGINS) == ["ee", "dd", "aa"]


@pytest.mark.auth
async def test_failures_of_a_user_who_is_dropped_are_logged_first(refusing, monkeypatch, caplog):
    """The failures that were counted for a user are not thrown away with the record"""
    monkeypatch.setattr(asfquart.ldap, "MAX_FAILED_LOGIN_USERS", 2)
    for _ in range(3):
        await _refused("aa")  # one line, and two that are counted
    await _refused("bb")
    await _refused("cc")  # no room: aa is dropped
    assert _failure_lines(caplog) == [
        "HTTP Basic authentication failed for user aa: Invalid credentials. (0x0031 [49])",
        "HTTP Basic authentication failed for user bb: Invalid credentials. (0x0031 [49])",
        "HTTP Basic authentication failed for user aa 2 more times since it was last logged",
        "HTTP Basic authentication failed for user cc: Invalid credentials. (0x0031 [49])",
    ]
    assert list(asfquart.ldap._FAILED_LOGINS) == ["bb", "cc"]
    # bb has nothing counted, so nothing is written when it is dropped
    await _refused("dd")
    assert len(_failure_lines(caplog)) == 5


def _users(count, start=0):
    return [f"user{number}" for number in range(start, start + count)]


@pytest.mark.auth
async def test_failed_basic_logins_for_many_users_do_not_flood_the_log(refusing, caplog):
    """Guessing at one user id after another is a limited number of lines, and a count"""
    limit = asfquart.ldap.FAILED_LOGIN_LOG_LIMIT
    for user in _users(limit + 140):
        await _refused(user)
    lines = _failure_lines(caplog)
    assert len(lines) == limit
    assert lines[-1].startswith(f"HTTP Basic authentication failed for user user{limit - 1}:")
    assert len(refusing.binds) == limit + 140  # every one was still checked by LDAP
    # Nothing more in this interval, whoever it is
    refusing.clock.now += asfquart.ldap.FAILED_LOGIN_LOG_INTERVAL - 1
    await _refused("alice")
    assert len(_failure_lines(caplog)) == limit
    # In the next interval the count is logged, and lines are written again
    refusing.clock.now += 1
    await _refused("bob")
    assert _failure_lines(caplog)[limit:] == [
        "HTTP Basic authentication failed 141 more times, which were not logged one by one:"
        " the limit of 60 lines in 60 seconds had been reached",
        "HTTP Basic authentication failed for user bob: Invalid credentials. (0x0031 [49])",
    ]
    # The count was logged once, and starts again
    refusing.clock.now += asfquart.ldap.FAILED_LOGIN_LOG_INTERVAL
    await _refused("carol")
    assert len(_failure_lines(caplog)) == limit + 3


@pytest.mark.auth
async def test_limit_on_lines_is_for_each_interval(refusing, caplog):
    limit = asfquart.ldap.FAILED_LOGIN_LOG_LIMIT
    for user in _users(limit):
        await _refused(user)
    refusing.clock.now += asfquart.ldap.FAILED_LOGIN_LOG_INTERVAL
    for user in _users(limit, start=1000):
        await _refused(user)
    lines = _failure_lines(caplog)
    assert len(lines) == 2 * limit  # the limit was reached twice, and never passed
    assert not any("one by one" in line for line in lines)


@pytest.mark.auth
async def test_count_of_a_user_goes_into_the_count_for_all_when_the_limit_is_reached(refusing, monkeypatch, caplog):
    """A failure is counted in one place or another, and in one place only"""
    monkeypatch.setattr(asfquart.ldap, "FAILED_LOGIN_LOG_LIMIT", 2)
    for _ in range(4):
        await _refused("alice")  # one line, and three that are counted for alice
    await _refused("bob")  # the second line of this interval
    refusing.clock.now += asfquart.ldap.FAILED_LOGIN_LOG_INTERVAL
    await _refused("carol")
    await _refused("dave")  # the second line of the next
    await _refused("alice")  # alice's line is due, with her count, and there is no room for it
    assert len(_failure_lines(caplog)) == 4
    assert asfquart.ldap._FAILED_LOGINS["alice"] == (refusing.clock.now, 0)
    refusing.clock.now += asfquart.ldap.FAILED_LOGIN_LOG_INTERVAL
    await _refused("alice")
    assert _failure_lines(caplog)[4:] == [
        "HTTP Basic authentication failed 4 more times, which were not logged one by one:"
        " the limit of 2 lines in 60 seconds had been reached",
        "HTTP Basic authentication failed for user alice: Invalid credentials. (0x0031 [49])",
    ]


@pytest.mark.auth
async def test_count_of_a_dropped_user_goes_into_the_count_for_all_when_the_limit_is_reached(
    refusing, monkeypatch, caplog
):
    monkeypatch.setattr(asfquart.ldap, "FAILED_LOGIN_LOG_LIMIT", 2)
    monkeypatch.setattr(asfquart.ldap, "MAX_FAILED_LOGIN_USERS", 2)
    for _ in range(3):
        await _refused("aa")  # one line, and two that are counted
    await _refused("bb")  # the second line
    await _refused("cc")  # aa is dropped: neither aa's count nor cc gets a line
    assert len(_failure_lines(caplog)) == 2
    refusing.clock.now += asfquart.ldap.FAILED_LOGIN_LOG_INTERVAL
    await _refused("dd")
    assert _failure_lines(caplog)[2].startswith("HTTP Basic authentication failed 3 more times,")


@pytest.mark.auth
@pytest.mark.parametrize(
    "username, password", [("Not A User", "password"), ("uid=x,ou=people", "password"), ("alice", "")]
)
async def test_request_refused_before_ldap_is_not_logged(refusing, caplog, username, password):
    """These are not guesses at a password, and a username that was not checked does not go in the log"""
    with pytest.raises(asfquart.base.ASFQuartException):
        asfquart.ldap.LDAPClient(username, password)
    assert _failure_lines(caplog) == []
    assert refusing.binds == []
    assert asfquart.ldap._FAILED_LOGINS == {}


@pytest.mark.auth
async def test_successful_basic_login_is_not_logged(directory, monkeypatch, caplog):
    monkeypatch.setattr(asfquart.ldap, "_FAILED_LOGINS", {})
    await _lookup("alice")
    assert [r for r in caplog.records if r.name == "asfquart.ldap"] == []


@pytest.mark.auth
async def test_ldap_error_is_logged_and_not_printed(refusing, caplog, capsys):
    refusing.error = ConnectionError("Can't contact LDAP server")
    error = await _refused("alice")
    assert error.errorcode == 500
    assert error.message == "Could not perform LDAP authorization check, please try again later."
    errors = [r.getMessage() for r in caplog.records if r.name == "asfquart.ldap" and r.levelname == "ERROR"]
    assert errors == ["LDAP lookup for user alice failed: ConnectionError: Can't contact LDAP server"]
    assert _failure_lines(caplog) == []  # not a wrong password
    assert "hunter2" not in caplog.text
    captured = capsys.readouterr()
    assert captured.out == "" and "LDAP" not in captured.err


@pytest.mark.auth
async def test_failed_basic_login_through_an_endpoint(refusing, monkeypatch, caplog):
    """The whole way: a 403 in plain text without LDAP's words, and the warning in the log"""
    monkeypatch.setattr(asfquart.ldap, "LDAP_SUPPORTED", True)
    app = asfquart.construct("ldap_failed_login", token_file=None, basic_auth=True)

    @app.route("/protected")
    @asfquart.auth.require
    async def protected():
        return "in"

    credentials = "Basic " + base64.b64encode(b"alice:hunter2-wrong-password").decode()
    resp = await app.test_client().get("/protected", headers={"Authorization": credentials})
    assert resp.status_code == 403
    assert (await resp.get_data()).decode() == "Invalid credentials provided"
    assert len(_failure_lines(caplog)) == 1
    assert "hunter2" not in caplog.text and credentials not in caplog.text
