#!/usr/bin/env python3

import pathlib
import re
import time
import warnings

import pytest
import quart

import asfquart.auth
from asfquart.auth import Requirements as R  # noqa: N817


class MyR(R):
    """Test auth methods in a Requirements subclass"""

    E_ALWAYS_FALSE = "Always False"

    @classmethod
    def true(cls, _session):
        return True, ""

    @classmethod
    def false(cls, _session):
        return False, cls.E_ALWAYS_FALSE


class LoneR:
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
    return re.escape(s) + "$"


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

    @asfquart.auth.require(R.mfa_protected)
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

    # Test with MFA explicitly False, should fail.
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "foo": "bar", "mfa": False}})
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NO_MFA)):
        await requires_mfa()

    # Test with a truthy value that isn't True, should fail.
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "foo": "bar", "mfa": "true"}})
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NO_MFA)):
        await requires_mfa()

    # Test with session with MFA, should work.
    quart.session = quart.sessions.SecureCookieSession({app.app_id: {"uts": time.time(), "foo": "bar", "mfa": True}})
    await requires_mfa()


@pytest.mark.auth
def test_mfa_enabled_is_the_old_name():
    """mfa_enabled still works as the old name for mfa_protected (#44)"""
    assert R.mfa_enabled == R.mfa_protected


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
    quart.session = quart.sessions.SecureCookieSession(
        {app.app_id: {"uts": time.time(), "foo": "bar", "isMember": True}}
    )
    with pytest.raises(asfquart.auth.AuthenticationFailed, match=_string_to_re(R.E_NOT_CHAIR)):
        await test_member_and_chair_auth()

    # Test for either member of chair, should work as we have chair (but not member)
    quart.session = quart.sessions.SecureCookieSession(
        {app.app_id: {"uts": time.time(), "foo": "bar", "isChair": True}}
    )
    await test_member_or_chair_auth()

    # Test for both member and chair, when we are both. should work.
    quart.session = quart.sessions.SecureCookieSession(
        {app.app_id: {"uts": time.time(), "foo": "bar", "isMember": True, "isChair": True}}
    )
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


# ---- Sessions that aren't a ClientSession (#44) ----


class _FullSession:
    """An app's own session class, with every attribute the requirements read"""

    def __init__(self, **values):
        self.uid = "testuser"
        self.is_member = self.is_chair = self.is_root = self.is_role = self.mfa = False
        self.committees = []
        self.__dict__.update(values)


class _OwnNamesSession:
    """An app's own session class with its own field names - only mfa matches"""

    def __init__(self):
        self.uid = "testuser"
        self.mfa = True
        self.member = True
        self.member_committees = ["httpd"]


MISSING_ATTRIBUTES = [
    (R.member, "is_member"),
    (R.chair, "is_chair"),
    (R.root, "is_root"),
    (R.roleacct, "is_role"),
    (R.pmc_member, "committees"),
]


@pytest.mark.auth
def test_session_protocol():
    assert isinstance(asfquart.session.ClientSession({"uid": "testuser"}), asfquart.session.SessionProtocol)
    assert isinstance(_FullSession(), asfquart.session.SessionProtocol)
    assert not isinstance(_OwnNamesSession(), asfquart.session.SessionProtocol)
    assert not isinstance({"uid": "testuser"}, asfquart.session.SessionProtocol)  # a dict has no uid attribute


@pytest.mark.auth
@pytest.mark.parametrize(
    "requirement, values",
    [
        (R.mfa_protected, {"mfa": True}),
        (R.member, {"is_member": True}),
        (R.chair, {"is_chair": True}),
        (R.root, {"is_root": True}),
        (R.roleacct, {"is_role": True}),
        (R.pmc_member, {"committees": ["httpd"]}),
    ],
)
def test_requirements_work_with_other_session_classes(requirement, values):
    assert requirement(_FullSession(**values))[0] is True
    assert requirement(_FullSession())[0] is False


OLD_NAMES = [
    (R.member, "is_member", "isMember"),
    (R.chair, "is_chair", "isChair"),
    (R.root, "is_root", "isRoot"),
    (R.roleacct, "is_role", "isRole"),
]


@pytest.mark.auth
@pytest.mark.parametrize("requirement, new, old", OLD_NAMES)
def test_client_session_old_names_still_work(requirement, new, old):
    """The camelCase names read and set the new attribute, with a DeprecationWarning"""
    session = asfquart.session.ClientSession({"uid": "testuser"})
    with pytest.warns(DeprecationWarning, match=f"{old} is deprecated, use {new}"):
        assert getattr(session, old) is False
    with pytest.warns(DeprecationWarning, match=old):
        setattr(session, old, True)
    assert getattr(session, new) is True
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # the new name, and the requirement that reads it, don't warn
        assert requirement(session)[0] is True


@pytest.mark.auth
def test_client_session_dictionary_keeps_the_old_keys():
    """What /auth sends is unchanged"""
    session = asfquart.session.ClientSession({"uid": "testuser", "isMember": True, "roleaccount": True})
    assert session["isMember"] is True and session["isRole"] is True
    assert {"isMember", "isChair", "isRoot", "isRole"} <= set(session)
    assert not {"is_member", "is_chair", "is_root", "is_role"} & set(session)


@pytest.mark.auth
@pytest.mark.parametrize("requirement, new, old", OLD_NAMES)
def test_requirements_read_the_old_name_from_other_session_classes(requirement, new, old):
    """A store's session class that still has the camelCase name works, with a DeprecationWarning"""

    class OldNamesSession:
        uid = "testuser"

    session = OldNamesSession()
    setattr(session, old, True)
    with pytest.warns(DeprecationWarning, match=f"OldNamesSession has '{old}'.*rename it to '{new}'"):
        assert requirement(session)[0] is True
    setattr(session, new, False)  # the new name wins once it is there
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert requirement(session)[0] is False


@pytest.mark.auth
def test_requirements_only_need_the_attribute_they_read():
    own = _OwnNamesSession()
    assert R.committer(own)[0] is True
    assert R.mfa_protected(own)[0] is True


@pytest.mark.auth
@pytest.mark.parametrize("requirement, attribute", MISSING_ATTRIBUTES)
async def test_require_names_the_missing_attribute(monkeypatch, requirement, attribute):
    """A session missing the attribute is a clear TypeError, not a pass"""
    asfquart.construct("foobar", token_file=None)
    own = _OwnNamesSession()

    async def read():
        return own

    monkeypatch.setattr(asfquart.session, "read", read)
    ran = []

    @asfquart.auth.require(requirement)
    async def endpoint():
        ran.append(True)

    with pytest.raises(TypeError) as excinfo:
        await endpoint()
    message = str(excinfo.value)
    assert "_OwnNamesSession" in message
    assert repr(attribute) in message
    assert "SessionProtocol" in message

    # Same in any_of - it mustn't be skipped in favour of the next requirement, which would pass.
    # A list, so the order is fixed.
    @asfquart.auth.require(any_of=[requirement, R.mfa_protected])
    async def either():
        ran.append(True)

    with pytest.raises(TypeError, match=attribute):
        await either()
    assert ran == []


@pytest.mark.auth
@pytest.mark.parametrize("requirement, attribute", MISSING_ATTRIBUTES)
def test_requirement_called_directly_raises_attribute_error(requirement, attribute):
    """Outside @require there's no translation, just Python's AttributeError"""
    with pytest.raises(AttributeError, match=attribute):
        requirement(_OwnNamesSession())


@pytest.mark.auth
async def test_require_leaves_other_attribute_errors_alone(monkeypatch):
    """An AttributeError that isn't about the session is a bug in the requirement, so it's not translated"""
    asfquart.construct("foobar", token_file=None)

    async def read():
        return _FullSession()

    monkeypatch.setattr(asfquart.session, "read", read)

    class Own(R):
        @classmethod
        def broken(cls, client_session):
            return None.nothing, "never"

    @asfquart.auth.require(Own.broken)
    async def endpoint():
        pass

    with pytest.raises(AttributeError, match="nothing"):
        await endpoint()


# ---- What Requirements.committer means (docs/auth.md) ----

_AUTH_DOC = pathlib.Path(__file__).parent.parent / "docs" / "auth.md"


def _documented_requirements():
    """Runs the example of requirements of one's own from docs/auth.md against a new app, and
    returns the app and the class that the example defines"""
    text = _AUTH_DOC.read_text(encoding="utf-8")
    section = text[text.index("## What `committer` means") :]
    code = section[section.index("```python\n") + len("```python\n") :]
    code = code[: code.index("```")]
    app = asfquart.construct("documented_requirements", token_file=None)
    namespace = {}
    exec(code, namespace)  # noqa: S102 - the example from our own documentation
    return app, namespace["MyRequirements"]


@pytest.mark.auth
@pytest.mark.parametrize(
    "session_data",
    [
        {"uid": "testuser"},  # in no project, and nothing else known about them
        {"uid": "testuser", "projects": ["httpd"], "pmcs": ["httpd"], "isMember": True},
        {"uid": "rolebot", "roleaccount": True},  # a role account
        {},  # a session that the application wrote, with nothing in it
    ],
)
def test_committer_passes_for_any_session(session_data):
    """As documented: it is a test for a session, and reads nothing from it"""
    assert R.committer(asfquart.session.ClientSession(session_data)) == (True, R.E_NOT_LOGGED_IN)
    assert R.committer(object())[0] is True  # a session store's own class, with no attributes at all
    assert R.committer(None)[0] is False


@pytest.mark.auth
def test_committer_is_documented_as_any_session():
    """The docstring and the page say what the code does, so that neither promises a check of projects"""
    assert "any session passes" in R.committer.__doc__
    text = _AUTH_DOC.read_text(encoding="utf-8")
    assert "User must be a committer of any project" not in text
    assert "`Requirements.committer` passes for any session" in text


@pytest.mark.auth
async def test_documented_requirements_of_ones_own():
    """The example in docs/auth.md for an app that needs more than committer works as it says"""
    app, mine = _documented_requirements()
    person = asfquart.session.ClientSession({"uid": "testuser"})
    project_committer = asfquart.session.ClientSession({"uid": "testuser", "projects": ["httpd"]})
    role = asfquart.session.ClientSession({"uid": "rolebot", "roleaccount": True, "projects": ["httpd"]})
    assert mine.person(person)[0] is True
    assert mine.person(role) == (False, "This endpoint is not open to role accounts.")
    assert mine.project_committer(person) == (False, "This endpoint is only accessible to committers of a project.")
    assert mine.project_committer(project_committer)[0] is True
    assert R.committer(role)[0] is True  # which is why the example exists

    app.token_handler = lambda token: {"uid": "rolebot", "roleaccount": True, "projects": ["httpd"]}
    client = app.test_client()
    for path in ("/people-only", "/project-committers"):
        resp = await client.get(path, headers={"Authorization": "Bearer a-token"})
        assert resp.status_code == 403
        assert (await resp.get_data()).decode() == "This endpoint is not open to role accounts."
