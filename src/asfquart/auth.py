#!/usr/bin/env python3
"""ASFQuart - Authentication methods and decorators"""
from . import base, session
import functools
import enum
import typing


class roles(enum.Enum):
    """ "various pre-defined access roles"""

    committer = 1
    member = 2
    chair = 3
    director = 4
    secretary = 5
    infrastructure = 6
    root = 7
    security = 8


class AuthenticationFailed(base.ASFQuartException):
    def __init__(self, message: str = "Authentication failed", errorcode: int = 403):
        self.message = message
        self.errorcode = errorcode
        super().__init__(self.message, self.errorcode)


def auth_required(func):
    """Denotes that authentication is required for this resource. Authentication may be OAuth, token, or LDAP
    based credentials unless further limited in scope by other asfquart.auth decorators."""

    @functools.wraps(func)
    async def auth_wrapper(*args, **kwargs):
        # We need a session dict of any kind
        client_session = session.read()
        if not client_session or not isinstance(client_session, dict):
            raise AuthenticationFailed("You must authenticate yourself before you can access this endpoint.")
        if args or kwargs:
            if args:
                await func(*args, **kwargs)
            else:
                await func(**kwargs)
        else:
            await func()

    return auth_wrapper


def mfa_required(func):
    """Denotes that multi-factor authentication is required. This implies only OIDC sessions are allowed."""

    @functools.wraps(func)
    @auth_required
    async def auth_wrapper():
        # We need a session dict from an oauth session. @auth_required already tests for a dict, so skip that.
        client_session = session.read()
        if client_session.get("mfa") is not True:
            raise AuthenticationFailed(
                "This endpoint can only be accessed through a multi-factor authenticated session."
            )
        await func()

    return auth_wrapper


def check_role(client_session: dict, role: int):
    """Match a role with a session"""
    # TODO: Check for other roles, secretary, director, infra, security
    if role == roles.committer and client_session:
        return True
    elif role == roles.member and client_session.get("isMember") is True:
        return True
    elif role == roles.chair and client_session.get("isChair") is True:
        return True
    elif role == roles.root and client_session.get("isRoot") is True:
        return True
    return False


def role_required(all_of: typing.Optional[typing.Union[int, typing.List, typing.Tuple]] = roles.committer,
        any_of: typing.Optional[typing.Union[int, typing.List, typing.Tuple]] = None
):
    """Denotes that a specific organizational role is required to access this endpoint.
    Advanced requirements may be constructed using the all_of and any_of arguments, listing one or more roles that
    will need to be required for access.

    Current roles are as follows, and should be accessed via the asfquart.auth.roles enum:
     - committer
     - member
     - chair
     - director
     - secretary
     - infrastructure
     - root
     - security """
    def role_required_inner(func):
        @auth_required
        @functools.wraps(func)
        async def role_wrapper(all_of, any_of):
            # Convert to lists if needed, so we can iterate
            if isinstance(all_of, enum.Enum):
                all_of = [all_of]
            if isinstance(any_of, enum.Enum):
                any_of = [any_of]

            client_session = session.read()
            if all_of and not all(check_role(client_session, role) for role in all_of):
                raise AuthenticationFailed("This endpoint requires an organizational role your account does not have.")
            if any_of and not any(check_role(client_session, role) for role in any_of):
                raise AuthenticationFailed("This endpoint requires an organizational role your account does not have.")
            await func()
        return functools.partial(role_wrapper, all_of=all_of, any_of=any_of)
    return role_required_inner
