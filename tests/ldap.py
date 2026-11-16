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
