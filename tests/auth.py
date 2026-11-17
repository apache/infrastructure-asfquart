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


def plain_function(_session):
    """A requirement that belongs to no class at all"""
    return True, ""

@pytest.mark.auth
async def test_auth_basics():
    app = asfquart.construct("foobar", token_file=None)

    # Generic auth test, just requires a valid session
    @asfquart.auth.require
    async def requires_session():
        pass

    # Test with no session, should fail
    quart.session = quart.sessions.SecureCookieSession({})
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_LOGGED_IN)):
        await requires_session()

    # Test with session, should work.
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "foo": "bar"}})
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
    # A plain function has no owning class at all; still a TypeError, not an AttributeError
    with pytest.raises(TypeError):
        @asfquart.auth.require(plain_function)
        async def requires_plain_function():
            pass


@pytest.mark.auth
async def test_mfa_auth():
    """MFA tests"""

    app = asfquart.construct("foobar", token_file=None)

    @asfquart.auth.require(R.mfa_enabled)
    async def requires_mfa():
        pass

    # Test MFA with no session, should fail exactly like auth_required
    quart.session = quart.sessions.SecureCookieSession({})
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_LOGGED_IN)):
        await requires_mfa()

    # Test with session without MFA, should fail.
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "foo": "bar"}})
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NO_MFA)):
        await requires_mfa()

    # Test with session with MFA, should work.
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "foo": "bar", "mfa": True}})
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
    quart.session = quart.sessions.SecureCookieSession({})
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_LOGGED_IN)):
        await test_committer_auth()

    # Test with session , should work
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "foo": "bar"}})
    await test_committer_auth()

    # Test with a role we don't have, should fail
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_MEMBER)):
        await test_member_auth()

    # Test with for both member and chair, while only being member. should pass on member check, fail on chair
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "foo": "bar", "isMember": True}})
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_CHAIR)):
        await test_member_and_chair_auth()

    # Test for either member of chair, should work as we have chair (but not member)
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "foo": "bar", "isChair": True}})
    await test_member_or_chair_auth()

    # Test for both member and chair, when we are both. should work.
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "foo": "bar", "isMember": True, "isChair": True}})
    await test_member_and_chair_auth()

@pytest.mark.auth
async def test_extended_auth():
    """Extended auth tests"""
    app = asfquart.construct("foobar", token_file=None)
    # These requirements need a session, as every requirement does
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "uid": "bar"}})

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


def _session(app, **fields):
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "uid": "bar", **fields}})


@pytest.mark.auth
async def test_require_without_requirements():
    """@require() is the same as a bare @require: any session will do"""
    app = asfquart.construct("foobar", token_file=None)

    @asfquart.auth.require()
    async def requires_session():
        return "ok"

    quart.session = quart.sessions.SecureCookieSession({})
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_LOGGED_IN)):
        await requires_session()

    _session(app)
    assert await requires_session() == "ok"


@pytest.mark.auth
async def test_require_positional_with_all_of():
    """A requirement given as the first argument is not dropped when all_of is given as well"""
    app = asfquart.construct("foobar", token_file=None)

    @asfquart.auth.require(R.member, all_of=R.chair)
    async def member_and_chair():
        return "ok"

    @asfquart.auth.require({R.member, R.root}, all_of={R.chair})
    async def member_root_and_chair():
        return "ok"

    # Meeting only the all_of requirement is not enough
    _session(app, isChair=True)
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_MEMBER)):
        await member_and_chair()

    # Nor is meeting only the first argument
    _session(app, isMember=True)
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_CHAIR)):
        await member_and_chair()

    _session(app, isMember=True, isChair=True)
    assert await member_and_chair() == "ok"
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_ROOT)):
        await member_root_and_chair()

    _session(app, isMember=True, isChair=True, isRoot=True)
    assert await member_root_and_chair() == "ok"


@pytest.mark.auth
async def test_require_positional_with_any_of():
    """The first argument must be met, next to at least one of any_of"""
    app = asfquart.construct("foobar", token_file=None)

    @asfquart.auth.require(R.member, any_of={R.chair, R.root})
    async def member_and_chair_or_root():
        return "ok"

    _session(app, isChair=True)
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_MEMBER)):
        await member_and_chair_or_root()

    _session(app, isMember=True)
    with pytest.raises(asfquart.auth.AuthenticationFailed):
        await member_and_chair_or_root()

    _session(app, isMember=True, isRoot=True)
    assert await member_and_chair_or_root() == "ok"


@pytest.mark.auth
async def test_require_passes_arguments_through():
    """Arguments reach the endpoint, whatever they are called"""
    app = asfquart.construct("foobar", token_file=None)

    @asfquart.auth.require
    async def bare(*args, **kwargs):
        return args, kwargs

    @asfquart.auth.require(R.member)
    async def with_requirement(*args, **kwargs):
        return args, kwargs

    _session(app, isMember=True)
    for endpoint in (bare, with_requirement):
        assert await endpoint() == ((), {})
        assert await endpoint(1, 2, project="foo") == ((1, 2), {"project": "foo"})
        # Names that the decorator uses itself are not special to the endpoint
        assert await endpoint(all_of="a", any_of="b") == ((), {"all_of": "a", "any_of": "b"})
    assert bare.__name__ == "bare"
    assert with_requirement.__name__ == "with_requirement"


@pytest.mark.auth
async def test_require_rejects_misuse():
    """Mistakes are errors when the endpoint is defined, not when it is requested"""

    # An endpoint that is not async, with a bare decorator
    with pytest.raises(TypeError):
        @asfquart.auth.require
        def not_async():
            pass

    # Requirements passed alongside the endpoint, where they would be ignored
    async def endpoint():
        pass
    with pytest.raises(TypeError):
        asfquart.auth.require(endpoint, all_of=R.member)
    with pytest.raises(TypeError):
        asfquart.auth.require(endpoint, any_of=R.member)

    # A bad requirement is found by require() itself, before there is an endpoint
    with pytest.raises(TypeError):
        asfquart.auth.require(R.member, all_of=print)
    with pytest.raises(TypeError):
        asfquart.auth.require(all_of="member")


@pytest.mark.auth
async def test_require_accepts_any_iterable():
    """Requirements can be a list, tuple, set or generator; each is checked on every request"""
    app = asfquart.construct("foobar", token_file=None)

    @asfquart.auth.require(req for req in (R.member, R.chair))
    async def from_generator():
        return "ok"

    @asfquart.auth.require([R.member], all_of=(R.chair,))
    async def from_list_and_tuple():
        return "ok"

    for endpoint in (from_generator, from_list_and_tuple):
        for _ in range(2):  # a generator must not be used up by the first request
            _session(app, isMember=True)
            with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_CHAIR)):
                await endpoint()
        _session(app, isMember=True, isChair=True)
        assert await endpoint() == "ok"


@pytest.mark.auth
def test_requirements_to_iter_is_deprecated():
    """The old public name still works, with a warning"""
    with pytest.warns(DeprecationWarning):
        assert asfquart.auth.requirements_to_iter(R.member) == [R.member]
    with pytest.warns(DeprecationWarning):
        assert asfquart.auth.requirements_to_iter(None) == []
