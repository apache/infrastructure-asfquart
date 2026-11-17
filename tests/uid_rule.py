#!/usr/bin/env python3
"""The rule for the form of an ASF user id is written once, and applied wherever a user id
comes into asfquart from outside: the OAuth provider's response, and the Basic auth username."""

import re
import types

import pytest

import asfquart
import asfquart.base
import asfquart.generics
import asfquart.ldap

VALID = ["testuser", "abc", "ab", "a1", "test-user", "test_user", "user42", "t-_", "t" * 100]
INVALID = [
    "", "a", "4user", "-user", "_user", "TestUser", "test user", "test.user", "testuser\n",
    "testuser,ou=people", "uid=testuser", "test*", "téstuser", "ｔｅｓｔ",
]


@pytest.fixture
def no_ldap_server(monkeypatch):
    """LDAPClient is given a stand-in for asfpy.aioldap, so that nothing is contacted"""
    fake = types.SimpleNamespace(aioldap=types.SimpleNamespace(LDAPClient=lambda uri, dn, password: object()))
    monkeypatch.setattr(asfquart.ldap, "asfpy", fake, raising=False)


def _oauth_accepts(uid):
    return asfquart.generics._oauth_data_problem({"uid": uid}) is None


def _ldap_accepts(uid):
    try:
        asfquart.ldap.LDAPClient(uid, "password")
    except asfquart.base.ASFQuartException:
        return False
    return True


@pytest.mark.auth
def test_one_rule_under_three_names():
    """There is one pattern, not three that happen to be alike."""
    assert asfquart.generics.OAUTH_UID_RE is asfquart.base.ASF_UID_RE
    assert asfquart.ldap.VALID_UID_RE is asfquart.base.ASF_UID_RE


@pytest.mark.auth
@pytest.mark.parametrize("uid", VALID)
def test_valid_uid_is_accepted_everywhere(no_ldap_server, uid):
    assert asfquart.base.ASF_UID_RE.fullmatch(uid)
    assert _oauth_accepts(uid)
    assert _ldap_accepts(uid)


@pytest.mark.auth
@pytest.mark.parametrize("uid", INVALID)
def test_invalid_uid_is_refused_everywhere(no_ldap_server, uid):
    assert not asfquart.base.ASF_UID_RE.fullmatch(uid)
    assert not _oauth_accepts(uid)
    assert not _ldap_accepts(uid)


@pytest.mark.auth
def test_app_can_change_the_rule_for_one_of_the_two(no_ldap_server, monkeypatch):
    """Assigning a pattern to one of the names changes that check, and leaves the other as it was."""
    digits_first = re.compile(r"[a-z0-9][a-z0-9_-]{1,}")

    monkeypatch.setattr(asfquart.generics, "OAUTH_UID_RE", digits_first)
    assert _oauth_accepts("4user")
    assert not _ldap_accepts("4user")
    monkeypatch.undo()

    monkeypatch.setattr(asfquart.ldap, "asfpy", types.SimpleNamespace(
        aioldap=types.SimpleNamespace(LDAPClient=lambda uri, dn, password: object())), raising=False)
    monkeypatch.setattr(asfquart.ldap, "VALID_UID_RE", digits_first)
    assert _ldap_accepts("4user")
    assert not _oauth_accepts("4user")
