#!/usr/bin/env python3
"""ASFQuart - Authentication methods and decorators"""

import collections.abc
import functools
import inspect
import typing
import warnings

from . import base, session

_P = typing.ParamSpec("_P")
_R = typing.TypeVar("_R")

# A requirement takes the session and returns whether it passes, and the error message if not.
# The session is Any, as a subclass of Requirements may test for a session class of its own.
Requirement = typing.Callable[[typing.Any], tuple[bool, str]]


def _read(client_session: typing.Any, name: str) -> typing.Any:
    """Reads an attribute of the session that was camelCase until 0.2.0. A session class that
    still has the old name works, with a warning."""
    try:
        return getattr(client_session, name)
    except AttributeError as e:
        old = session.OLD_NAMES[name]
        # Raise the original, naming the new attribute, unless it's the old name that is there
        if e.obj is not client_session or not hasattr(client_session, old):
            raise
        warnings.warn(
            f"Session type {type(client_session).__name__} has {old!r}, which is deprecated: rename it to {name!r}",
            DeprecationWarning,
            stacklevel=3,
        )
        return getattr(client_session, old)


class Requirements:
    """Various pre-defined access requirements.

    These don't check the session's class, as it isn't always a ClientSession - see
    session.SessionProtocol for the attributes they read."""

    # Error messages related to tests
    E_NOT_LOGGED_IN = "You need to be logged in to access this endpoint."
    E_NOT_MEMBER = "This endpoint is only accessible to foundation members."
    E_NOT_CHAIR = "This endpoint is only accessible to project chairs."
    E_NO_MFA = "This endpoint requires you to log on using multi-factor authentication."
    E_NOT_ROOT = "This endpoint is only accessible to foundation staff."
    E_NOT_PMC = "This endpoint is only accessible to members of the foundation committees."
    E_NOT_ROLEACCOUNT = "This endpoint is only accessible to role accounts."

    @classmethod
    def mfa_protected(cls, client_session: session.SessionProtocol) -> tuple[bool, str]:
        """Tests for whether the user logged in with multi-factor authentication"""
        # The OAuth provider only sends mfa for OIDC logins, so it defaults to False for anything else.
        # Anything but True will cause a failure.
        return client_session.mfa is True, cls.E_NO_MFA

    # Old name for mfa_protected, kept so existing apps don't break (#44)
    mfa_enabled = mfa_protected

    @classmethod
    def committer(cls, client_session: typing.Any) -> tuple[bool, str]:
        """Tests for whether there is a session: any session passes, and nothing in it is read.

        That is what "committer" means here. A session comes from the ASF OAuth provider (or from
        LDAP, for HTTP Basic authentication), which only knows ASF accounts, and an ASF account
        belongs to a committer. It is not a test of membership of a project: a committer who is in
        no project group passes. So does a role account, and so does any session that the
        application writes itself. It is the same test as a bare @require. See docs/auth.md."""
        return client_session is not None, cls.E_NOT_LOGGED_IN

    @classmethod
    def member(cls, client_session: session.SessionProtocol) -> tuple[bool, str]:
        """Tests for whether the user is a foundation member"""
        # Anything but True will cause a failure.
        return _read(client_session, "is_member") is True, cls.E_NOT_MEMBER

    @classmethod
    def chair(cls, client_session: session.SessionProtocol) -> tuple[bool, str]:
        """tests for whether the user is a chair of any top-level project"""
        # Anything but True will cause a failure.
        return _read(client_session, "is_chair") is True, cls.E_NOT_CHAIR

    @classmethod
    def root(cls, client_session: session.SessionProtocol) -> tuple[bool, str]:
        """tests for whether the user is a member of infra-root"""
        # Anything but True will cause a failure.
        return _read(client_session, "is_root") is True, cls.E_NOT_ROOT

    @classmethod
    def pmc_member(cls, client_session: session.SessionProtocol) -> tuple[bool, str]:
        """tests for whether the user is a PMC member of any top-level project"""
        # Anything but True will cause a failure.
        return bool(client_session.committees), cls.E_NOT_PMC

    @classmethod
    def roleacct(cls, client_session: session.SessionProtocol) -> tuple[bool, str]:
        """tests for whether the user is a service account"""
        # Anything but True will cause a failure.
        return _read(client_session, "is_role") is True, cls.E_NOT_ROLEACCOUNT


class AuthenticationFailed(base.ASFQuartException):
    def __init__(self, message: str = "Authentication failed", errorcode: int = 403) -> None:
        self.message = message
        self.errorcode = errorcode
        super().__init__(self.message, self.errorcode)


def _requirements_to_list(args: typing.Any) -> list[Requirement]:
    """Converts any auth req args (single arg, list, tuple, set) to a list of requirements"""
    # No args? return empty list
    if args is None:
        return []
    # Single arg? Convert to list first
    if not isinstance(args, collections.abc.Iterable):
        args = [args]
    args = list(args)
    # Test that each requirement is an allowed one (a classmethod of Requirements or a subclass)
    for req in args:
        owner = getattr(req, "__self__", None)
        if not (callable(req) and isinstance(owner, type) and issubclass(owner, Requirements)):
            raise TypeError(
                f"Authentication requirement {req} is not valid. Must belong to the asfquart.auth.Requirements class."
                " (If this is the endpoint itself: @require can only decorate an async function.)"
            )
    return args


def requirements_to_iter(args: typing.Any) -> list[Requirement]:
    """Deprecated: this is an internal helper of require(), and will be removed from the public API."""
    warnings.warn(
        "asfquart.auth.requirements_to_iter is internal to asfquart and will be removed",
        DeprecationWarning,
        stacklevel=2,
    )
    return _requirements_to_list(args)


def _check(requirement: Requirement, client_session: typing.Any) -> tuple[bool, str]:
    """Runs a requirement against the session, with a clearer error if the session is missing
    the attribute the requirement reads"""
    try:
        return requirement(client_session)
    except AttributeError as e:
        # Only translate if it's the session that's missing the attribute - anything else is a real bug
        if e.obj is not client_session:
            raise
        raise TypeError(
            f"Session type {type(client_session).__name__} has no {e.name!r} attribute, which this "
            "requirement needs - see asfquart.session.SessionProtocol"
        ) from None


async def _require_wrapper(
    original_func: typing.Callable[_P, typing.Coroutine[typing.Any, typing.Any, _R]],
    all_of: list[Requirement],
    any_of: list[Requirement],
    /,
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> _R:
    """Runs the endpoint original_func, provided there is a session and it meets the requirements"""
    client_session = await session.read()
    errors_list = []
    # First off, test if we have a session at all.
    if client_session is None:
        raise AuthenticationFailed(Requirements.E_NOT_LOGGED_IN)

    # Test all_of
    for requirement in all_of:
        passes, desc = _check(requirement, client_session)
        if not passes:
            errors_list.append(desc)
    # If we encountered an error, bail early
    if errors_list:
        raise AuthenticationFailed("\n".join(errors_list))

    # So far, so good? Run the any_of if present, break if any single test succeeds.
    for requirement in any_of:
        passes, desc = _check(requirement, client_session)
        if not passes:
            errors_list.append(desc)
        else:
            # If a test passed, we can clear the failures and pass
            errors_list.clear()
            break
    # If no tests passed, errors_list should have at least one entry.
    if errors_list:
        raise AuthenticationFailed("\n".join(errors_list))
    return await original_func(*args, **kwargs)


# Bare @require: the endpoint keeps its signature
@typing.overload
def require(
    func_or_requirements: typing.Callable[_P, typing.Coroutine[typing.Any, typing.Any, _R]],
) -> typing.Callable[_P, typing.Coroutine[typing.Any, typing.Any, _R]]: ...


# @require(...): a decorator, which does the same
@typing.overload
def require(
    func_or_requirements: Requirement | typing.Iterable[Requirement] | None = None,
    all_of: Requirement | typing.Iterable[Requirement] | None = None,
    any_of: Requirement | typing.Iterable[Requirement] | None = None,
) -> typing.Callable[
    [typing.Callable[_P, typing.Coroutine[typing.Any, typing.Any, _R]]],
    typing.Callable[_P, typing.Coroutine[typing.Any, typing.Any, _R]],
]: ...


def require(
    func_or_requirements: typing.Callable[..., typing.Any] | typing.Iterable[Requirement] | None = None,
    all_of: Requirement | typing.Iterable[Requirement] | None = None,
    any_of: Requirement | typing.Iterable[Requirement] | None = None,
) -> typing.Callable[..., typing.Any]:
    """Adds authentication/authorization requirements to an endpoint. Can be a single requirement or a list
    of requirements. By default, all requirements must be satisfied, though this can be made optional by
    explicitly using the `all_of` or `any_of` keywords to specify optionality. Requirements must be part
    of the asfquart.auth.Requirements class, which consists of the following test:

    - mfa_protected: The client must have logged in with MFA
    - committer: The client must be logged in. Any session passes; see Requirements.committer
    - member: The client must be a foundation member
    - chair: The client must be a chair of a project

    In addition, any endpoint decorated with @require will implicitly require ANY form of
    authenticated session. This is mandatory and also works as a bare decorator.

    The first argument is optional, and is one of two things:

    - the endpoint itself (an async function), when @require is used as a bare decorator
    - a requirement, or a collection of requirements, when it is used as @require(...). These are
      `all_of` requirements, and are added to any that are given with the `all_of` keyword.

    Examples:
        @require(Requirements.member)  # Require session, require ASF member
        @require  # Require any authed session
        @require()  # The same: require any authed session
        @require({Requirements.mfa_protected, Requirements.chair})  # Any project chair with an MFA-protected session
        @require(all_of=Requirements.mfa_protected, any_of={Requirements.member, Requirements.chair})
          # Require either ASF member OR project chair, but also require an MFA-protected session in any case.
        @require(Requirements.mfa_protected, any_of={Requirements.member, Requirements.chair})
          # The same again, with the requirement that must always be met given as the first argument.
    """

    # If the decorator is used without arguments, the first argument is the endpoint (an async function).
    # In this case, we return a simple wrapper that only requires a session.
    if inspect.iscoroutinefunction(func_or_requirements):
        if all_of is not None or any_of is not None:
            raise TypeError("Requirements must be given as @require(...), placed above the endpoint.")
        return functools.wraps(func_or_requirements)(functools.partial(_require_wrapper, func_or_requirements, [], []))

    # Otherwise the first argument, if there is one, holds requirements. They must all be met, as must
    # those given with all_of: neither replaces the other. The requirements are checked here, so that
    # a bad one is an error when the endpoint is defined, and not when it is first requested.
    all_of_list = _requirements_to_list(func_or_requirements) + _requirements_to_list(all_of)
    any_of_list = _requirements_to_list(any_of)

    def require_with_args(
        original_func: typing.Callable[_P, typing.Coroutine[typing.Any, typing.Any, _R]],
    ) -> typing.Callable[_P, typing.Coroutine[typing.Any, typing.Any, _R]]:
        return functools.wraps(original_func)(
            functools.partial(_require_wrapper, original_func, all_of_list, any_of_list)
        )

    return require_with_args
