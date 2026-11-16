#!/usr/bin/env python3
"""ASFQuart - Authentication methods and decorators"""
from . import base, session
import functools
import typing
import collections.abc
import inspect
import warnings

class Requirements:
    """Various pre-defined access requirements"""

    # Error messages related to tests
    E_NOT_LOGGED_IN = "You need to be logged in to access this endpoint."
    E_NOT_MEMBER = "This endpoint is only accessible to foundation members."
    E_NOT_CHAIR = "This endpoint is only accessible to project chairs."
    E_NO_MFA = "This endpoint requires you to log on using multi-factor authentication."
    E_NOT_ROOT = "This endpoint is only accessible to foundation staff."
    E_NOT_PMC = "This endpoint is only accessible to members of the foundation committees."
    E_NOT_ROLEACCOUNT = "This endpoint is only accessible to role accounts."


    @classmethod
    def mfa_enabled(cls, client_session: session.ClientSession):
        """Tests for MFA enabled in the client session"""
        return client_session.mfa is True, cls.E_NO_MFA

    @classmethod
    def committer(cls, client_session: session.ClientSession):
        """Tests for whether the user is a committer on any project"""
        return client_session is not None, cls.E_NOT_LOGGED_IN

    @classmethod
    def member(cls, client_session: session.ClientSession):
        """Tests for whether the user is a foundation member"""
        # Anything but True will cause a failure.
        return client_session.isMember is True, cls.E_NOT_MEMBER

    @classmethod
    def chair(cls, client_session: session.ClientSession):
        """tests for whether the user is a chair of any top-level project"""
        # Anything but True will cause a failure.
        return client_session.isChair is True, cls.E_NOT_CHAIR

    @classmethod
    def root(cls, client_session: session.ClientSession):
        """tests for whether the user is a member of infra-root"""
        # Anything but True will cause a failure.
        return client_session.isRoot is True, cls.E_NOT_ROOT

    @classmethod
    def pmc_member(cls, client_session: session.ClientSession):
        """tests for whether the user is a PMC member of any top-level project"""
        # Anything but True will cause a failure.
        return bool(client_session.committees), cls.E_NOT_PMC

    @classmethod
    def roleacct(cls, client_session: session.ClientSession):
        """tests for whether the user is a service account"""
        # Anything but True will cause a failure.
        return client_session.isRole is True, cls.E_NOT_ROLEACCOUNT

class AuthenticationFailed(base.ASFQuartException):
    def __init__(self, message: str = "Authentication failed", errorcode: int = 403):
        self.message = message
        self.errorcode = errorcode
        super().__init__(self.message, self.errorcode)


def _requirements_to_iter(args: typing.Any) -> list:
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
        if not callable(req) or not isinstance(owner, type) or not issubclass(owner, Requirements):
            raise TypeError(
                f"Authentication requirement {req} is not valid. Must belong to the asfquart.auth.Requirements class."
                " (If this is the endpoint itself: @require can only decorate an async function.)"
            )
    return args


def requirements_to_iter(args: typing.Any):
    """Deprecated: this is an internal helper of require(), and will be removed from the public API."""
    warnings.warn(
        "asfquart.auth.requirements_to_iter is internal to asfquart and will be removed",
        DeprecationWarning,
        stacklevel=2,
    )
    return _requirements_to_iter(args)


async def _require_wrapper(original_func: typing.Callable, all_of: list, any_of: list, /, *args, **kwargs):
    """Runs the endpoint original_func, provided there is a session and it meets the requirements"""
    client_session = await session.read()
    errors_list = []
    # First off, test if we have a session at all.
    if client_session is None:
        raise AuthenticationFailed(Requirements.E_NOT_LOGGED_IN)

    # Test all_of
    for requirement in all_of:
        passes, desc = requirement(client_session)
        if not passes:
            errors_list.append(desc)
    # If we encountered an error, bail early
    if errors_list:
        raise AuthenticationFailed("\n".join(errors_list))

    # So far, so good? Run the any_of if present, break if any single test succeeds.
    for requirement in any_of:
        passes, desc = requirement(client_session)
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


def require(
    func_or_requirements: typing.Union[typing.Callable, typing.Iterable[typing.Callable], None] = None,
    all_of: typing.Union[typing.Callable, typing.Iterable[typing.Callable], None] = None,
    any_of: typing.Union[typing.Callable, typing.Iterable[typing.Callable], None] = None,
):
    """Adds authentication/authorization requirements to an endpoint. Can be a single requirement or a list
    of requirements. By default, all requirements must be satisfied, though this can be made optional by
    explicitly using the `all_of` or `any_of` keywords to specify optionality. Requirements must be part
    of the asfquart.auth.Requirements class, which consists of the following test:

    - mfa_enabled: The client must authenticate with a method that has MFA enabled
    - committer: The client must be a committer
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
        @require({Requirements.mfa_enabled, Requirements.chair})  # Require any project chair with MFA-enabled session
        @require(all_of=Requirements.mfa_enabled, any_of={Requirements.member, Requirements.chair})
          # Require either ASF member OR project chair, but also require MFA enabled in any case.
        @require(Requirements.mfa_enabled, any_of={Requirements.member, Requirements.chair})
          # The same again, with the requirement that must always be met given as the first argument.
    """

    # If the decorator is used without arguments, the first argument is the endpoint (an async function).
    # In this case, we return a simple wrapper that only requires a session.
    if inspect.iscoroutinefunction(func_or_requirements):
        if all_of is not None or any_of is not None:
            raise TypeError("Requirements must be given as @require(...), placed above the endpoint.")
        return functools.wraps(func_or_requirements)(
            functools.partial(_require_wrapper, func_or_requirements, [], [])
        )

    # Otherwise the first argument, if there is one, holds requirements. They must all be met, as must
    # those given with all_of: neither replaces the other. The requirements are checked here, so that
    # a bad one is an error when the endpoint is defined, and not when it is first requested.
    all_of_list = _requirements_to_iter(func_or_requirements) + _requirements_to_iter(all_of)
    any_of_list = _requirements_to_iter(any_of)

    def require_with_args(original_func: typing.Callable):
        return functools.wraps(original_func)(
            functools.partial(_require_wrapper, original_func, all_of_list, any_of_list)
        )

    return require_with_args
