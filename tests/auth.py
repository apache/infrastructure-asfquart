#!/usr/bin/env python3

import time
import re

import pytest
import quart

import asfquart.auth
from asfquart.auth import Requirements as R

class MyR(R):
    """Test auth methods in a Requirements subclass"""

    E_ALWAYS_FALSE = "Always False"

    @classmethod
    def true(cls, _session):
        return True, ""

    @classmethod
    def false(cls, _session):
        return False, cls.E_ALWAYS_FALSE

class LoneR():
    """Test auth methods in an independent class"""

    E_ALWAYS_FALSE = "Always False"

    @classmethod
    def true(cls, _session):
        return True, ""

    @classmethod
    def false(cls, _session):
        return False, cls.E_ALWAYS_FALSE

def _string_to_re(s):
    """convert arbitrary string to fullmatch regex"""
    return re.escape(s) + '$'

def _string_to_re(s):
    """convert arbitrary string to fullmatch regex"""
    return re.escape(s) + '$'

@pytest.mark.auth
async def test_auth_basics():
    app = asfquart.construct("foobar", token_file=None)

    # Generic auth test, just requires a valid session
    @asfquart.auth.require
    async def requires_session():
        pass

    # Test with no session, should fail
    quart.session = {}
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_LOGGED_IN)):
        await requires_session()

    # Test with session, should work.
    quart.session = {app.app_id: {"uts": time.time(), "foo": "bar"}}
    await requires_session()

    # Test with a bad requirement, should fail with a TypeError.
    with pytest.raises(TypeError):
        @asfquart.auth.require({R.member, print})
        async def requires_bad_thing():
            pass
    # Same bad one, but with explicit any_of
    with pytest.raises(TypeError):
        @asfquart.auth.require(any_of={R.member, print})
        async def requires_bad_thingy():
            pass


@pytest.mark.auth
async def test_mfa_auth():
    """MFA tests"""

    app = asfquart.construct("foobar", token_file=None)

    @asfquart.auth.require(R.mfa_enabled)
    async def requires_mfa():
        pass

    # Test MFA with no session, should fail exactly like auth_required
    quart.session = {}
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_LOGGED_IN)):
        await requires_mfa()

    # Test with session without MFA, should fail.
    quart.session = {app.app_id: {"uts": time.time(), "foo": "bar"}}
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NO_MFA)):
        await requires_mfa()

    # Test with session with MFA, should work.
    quart.session = {app.app_id: {"uts": time.time(), "foo": "bar", "mfa": True}}
    await requires_mfa()


@pytest.mark.auth
async def test_role_auth():
    """Role tests"""

    app = asfquart.construct("foobar", token_file=None)

    # Set up some role tests
    @asfquart.auth.require  # no args implies any valid account
    async def test_committer_auth():
        pass

    @asfquart.auth.require(R.member)
    async def test_member_auth():
        pass

    @asfquart.auth.require({R.member, R.chair})
    async def test_member_and_chair_auth():
        pass

    @asfquart.auth.require(any_of={R.member, R.chair})
    async def test_member_or_chair_auth():
        pass

    # Test role with no session, should fail exactly like auth_required
    quart.session = {}
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_LOGGED_IN)):
        await test_committer_auth()

    # Test with session , should work
    quart.session = {app.app_id: {"uts": time.time(), "foo": "bar"}}
    await test_committer_auth()

    # Test with a role we don't have, should fail
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_MEMBER)):
        await test_member_auth()

    # Test with for both member and chair, while only being member. should pass on member check, fail on chair
    quart.session = {app.app_id: {"uts": time.time(), "foo": "bar", "isMember": True}}
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_CHAIR)):
        await test_member_and_chair_auth()

    # Test for either member of chair, should work as we have chair (but not member)
    quart.session = {app.app_id: {"uts": time.time(), "foo": "bar", "isChair": True}}
    await test_member_or_chair_auth()

    # Test for both member and chair, when we are both. should work.
    quart.session = {app.app_id: {"uts": time.time(), "foo": "bar", "isMember": True, "isChair": True}}
    await test_member_and_chair_auth()

@pytest.mark.auth
async def test_extended_auth():
    """Extended auth tests"""

    @asfquart.auth.require(MyR.true)
    async def test_true():
        pass

    @asfquart.auth.require(MyR.false)
    async def test_false():
        pass

    # Should always work
    await test_true()

    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(MyR.E_ALWAYS_FALSE)):
        await test_false()

@pytest.mark.auth
async def test_lone_auth():
    """Extended auth tests using independent class"""

    # cannot use independent class as a decorator
    with pytest.raises(TypeError):
        @asfquart.auth.require(LoneR.true)
        async def test_true():
            pass

    with pytest.raises(TypeError):
        @asfquart.auth.require(LoneR.false)
        async def test_false():
            pass
