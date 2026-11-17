#!/usr/bin/env python3
"""Tests for ldap.py: the username is validated before it is placed in a DN"""

import base64
import types

import pytest

import asfquart
import asfquart.ldap


INVALID_USERNAMES = [
    "",
    "a",                                    # too short
    "4user",                                # must start with a letter
    "-user",
    "_user",
    "TestUser",                             # upper case
    "test user",
    "test.user",
    "testuser,ou=people,dc=apache,dc=org",  # would add components to the DN
    "testuser,ou=project",
    "uid=testuser",
    "testuser+cn=admin",                    # multi-valued RDN
    "*",                                    # LDAP filter characters
    "test*",
    "test)(uid=*",
    "test\\2Cuser",                         # DN escape
    "testuser\n",
    "testuser\x00",
    "testéuser",
    "ｔｅｓｔ",             # full width letters
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
    app = asfquart.construct("ldap_username", token_file=None)
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
    app = asfquart.construct("ldap_empty_password", token_file=None)
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

    def LDAPClient(self, uri, dn, password):
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
        asfquart.ldap, "bonsai",
        types.SimpleNamespace(errors=types.SimpleNamespace(AuthenticationError=PermissionError)), raising=False,
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
    directory.clock.now += asfquart.ldap.DEFAULT_LDAP_CACHE_TTL - 100   # alice and bob have expired, carol has not
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
    directory.clock.now += 20            # alice has expired; she comes back, and is looked up again
    await _lookup("alice")
    assert list(asfquart.ldap.LDAP_CACHE) == ["bob", "carol", "alice"]
    await _lookup("dave")                # the cache is full: bob is now the oldest, not alice
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
    await _lookup("alice")                                   # alice is cached
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
                await hold.wait()                            # the bind does not come back yet
                return await super().__aenter__()

        return types.SimpleNamespace(connect=HeldOpen)

    monkeypatch.setattr(directory, "LDAPClient", slow_for_alice)
    alice = asyncio.ensure_future(_lookup("alice"))          # cache hit; now checking the password
    await waiting.wait()
    await _lookup("bob")                                     # the cache holds one: alice goes
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
    await _lookup("alice")                                   # alice is back: a cache hit, and a use
    assert list(asfquart.ldap.LDAP_CACHE) == ["bob", "carol", "alice"]
    searches = len(directory.searches)
    await _lookup("dave")                                    # the cache is full: bob goes, not alice
    assert list(asfquart.ldap.LDAP_CACHE) == ["carol", "alice", "dave"]
    await _lookup("alice")
    assert len(directory.searches) == searches + 1           # only dave was looked up; alice was still cached


@pytest.mark.auth
async def test_using_a_lookup_does_not_make_it_last_longer(directory):
    """Being used keeps a lookup from being dropped for want of room. It does not keep it past its hour."""
    await _lookup("alice")
    for _ in range(5):
        directory.clock.now += asfquart.ldap.DEFAULT_LDAP_CACHE_TTL / 6
        await _lookup("alice")                               # used every ten minutes
    assert len(directory.searches) == 1
    directory.clock.now += asfquart.ldap.DEFAULT_LDAP_CACHE_TTL / 6 + 1
    await _lookup("alice")                                   # an hour after the lookup: made again
    assert len(directory.searches) == 2


@pytest.mark.auth
async def test_expired_lookup_is_removed_wherever_it_is_in_the_order(directory):
    """An expired lookup is found even when a recently used one is in front of it."""
    await _lookup("alice")
    directory.clock.now += 1800
    await _lookup("bob")
    directory.clock.now += 1000
    await _lookup("alice")                                   # used: alice is now behind bob in the order
    assert list(asfquart.ldap.LDAP_CACHE) == ["bob", "alice"]
    directory.clock.now += 900                               # alice's lookup is 3700 seconds old, bob's 1900
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
