#!/usr/bin/env python3
"""ASFQuart - User session methods and decorators"""

import binascii
import hashlib
import inspect
import logging
import secrets
import time
import typing
import warnings

import quart

import asfquart

from . import base, ldap

LOGGER = logging.getLogger(__name__)

# The time limits for a session that is kept in the cookie, in seconds. An app sets its own with
# the MAX_SESSION_AGE and MAX_SESSION_IDLE options in its config.yaml; 0 means no limit.
DEFAULT_MAX_SESSION_AGE = 86400 * 7  # A session ends 7 days after the user logged in, however much it is used
# ... and earlier, once it has not been used for this long. An idle limit only has an effect when
# it is less than the maximum age, so with these defaults it has none until an app lowers it.
DEFAULT_MAX_SESSION_IDLE = 86400 * 7
# How often, at most, the time a session was last used is saved back to the cookie. With an idle
# limit of less than ten times this, it is saved every tenth of that limit instead.
SESSION_REFRESH_INTERVAL = 60


def _session_limit(app, name: str, default: int):
    """A session time limit from the app's config, in seconds. 0 means that there is no limit."""
    value = app.cfg.get(name)
    return default if value is None else value


def _timestamp(session_dict: dict, name: str):
    """A timestamp from a stored session, or None if it does not have a usable one."""
    value = session_dict.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _idle_limit(app, expiry_time=None):
    """The idle limit in effect, in seconds: expiry_time if given, and otherwise MAX_SESSION_IDLE,
    where 0 means that there is none."""
    if expiry_time is not None:
        return expiry_time
    return _session_limit(app, "MAX_SESSION_IDLE", DEFAULT_MAX_SESSION_IDLE)


def _mark_session_changed() -> None:
    """Tells quart to send the session cookie again. It notices a new value being set in the
    session, but not a change inside a value that is already there.

    Every quart session has this attribute. If quart.session is something that has not, such as a
    plain dict, this raises: the change could not be saved, and that must not pass unnoticed."""
    quart.session.modified = True


def _session_expired(app, session_dict: dict, now: float, expiry_time=None) -> bool:
    """Tests a stored session against the time limits. expiry_time, if given, is the idle limit
    for this one test, and is used in place of MAX_SESSION_IDLE."""
    updated = _timestamp(session_dict, "uts") or 0
    idle_limit = _idle_limit(app, expiry_time)
    # An idle limit of 0 in the config means no limit; an expiry_time of 0 is taken at its word
    if (expiry_time is not None or idle_limit > 0) and updated < now - idle_limit:
        return True
    max_session_age = _session_limit(app, "MAX_SESSION_AGE", DEFAULT_MAX_SESSION_AGE)
    created = _timestamp(session_dict, "cts")
    # A session with no creation time was written by a version that did not record one. Its age
    # is not known, so it is not ended here; read() starts its clock instead.
    if max_session_age > 0 and created is not None and created < now - max_session_age:
        return True
    return False


def _created_at(app, session_data: dict, now: float, new_session: bool) -> float:
    """The creation time for a session that is about to be written to the cookie.

    Writing to the session of the user who is logged in changes that session, and does not start
    a new one: it keeps its creation time, or MAX_SESSION_AGE would start again with every write.
    A session for another user, or one that replaces a session that has ended, starts now."""
    if new_session:
        return now
    current = quart.session.get(app.app_id)
    if not isinstance(current, dict) or current.get("uid") != session_data.get("uid"):
        return now
    created = _timestamp(current, "cts")
    if created is None or _session_expired(app, current, now):
        return now
    return created


def _generate_sid() -> str:
    return secrets.token_urlsafe(20)


def _hash_sid(sid: str) -> str:
    return hashlib.sha3_256(sid.encode("utf-8")).hexdigest()


@typing.runtime_checkable
class SessionProtocol(typing.Protocol):
    """What asfquart expects of a session.

    Without a session store the session is a ClientSession, which has all of these. With a store
    (app.sessions) it's whatever the store returns, so that object needs a uid, and the attribute
    for each requirement the app uses. Type checkers can check a session class against this.
    """

    # Properties, as these are only ever read - a class can then use a narrower type, e.g. list[str].
    @property
    def uid(self) -> str | None: ...  # None only if the session was built from data with no uid

    @property
    def is_member(self) -> bool: ...  # Requirements.member

    @property
    def is_chair(self) -> bool: ...  # Requirements.chair

    @property
    def is_root(self) -> bool: ...  # Requirements.root

    @property
    def is_role(self) -> bool: ...  # Requirements.roleacct

    @property
    def mfa(self) -> bool: ...  # Requirements.mfa_protected

    @property
    def committees(self) -> typing.Collection[str]: ...  # Requirements.pmc_member


# These four were camelCase until 0.1.13: new name -> old name. The old names still work, see
# ClientSession and auth.Requirements.
OLD_NAMES = {"is_member": "isMember", "is_chair": "isChair", "is_root": "isRoot", "is_role": "isRole"}


def _old_name(new: str) -> property:
    """A ClientSession attribute under its old name, which warns and then reads or sets the new one"""
    message = f"ClientSession.{OLD_NAMES[new]} is deprecated, use {new}"

    def get(self):
        warnings.warn(message, DeprecationWarning, stacklevel=2)
        return getattr(self, new)

    def set_(self, value):
        warnings.warn(message, DeprecationWarning, stacklevel=2)
        setattr(self, new, value)

    return property(get, set_)


class ClientSession(dict):
    isMember = _old_name("is_member")  # noqa: N815
    isChair = _old_name("is_chair")  # noqa: N815
    isRoot = _old_name("is_root")  # noqa: N815
    isRole = _old_name("is_role")  # noqa: N815

    def __init__(self, raw_data: dict):
        """Initializes a client session from a raw dict. ClientSession is a subclassed dict, so that
        we can send it to quart in a format it can render."""
        super().__init__()
        self.uid = raw_data.get("uid")
        self.dn = raw_data.get("dn")
        self.fullname = raw_data.get("fullname")
        self.email = raw_data.get("email", f"{self.uid}@apache.org")
        self.is_member = raw_data.get("isMember", False)
        self.is_chair = raw_data.get("isChair", False)
        self.is_root = raw_data.get("isRoot", False)
        self.committees = raw_data.get("pmcs", [])
        self.projects = raw_data.get("projects", [])
        self.mfa = raw_data.get("mfa", False)
        self.is_role = raw_data.get("roleaccount", False)
        self.metadata = raw_data.get("metadata", {})  # This can contain whatever specific metadata the app needs
        # Update the external dict representation with internal values. Its keys keep the old
        # names: they are what /auth sends, and what the OAuth provider calls them.
        self.update({OLD_NAMES.get(name, name): value for name, value in self.__dict__.items()})


async def read(expiry_time=None, app=None):  # noqa: C901
    """Fetches a cookie-based session if found (and valid), and updates the last access timestamp
    for the session.

    A session in the cookie ends when it has not been used for MAX_SESSION_IDLE seconds (7 days
    unless the app's config says otherwise), or MAX_SESSION_AGE seconds after it was created (7
    days too). expiry_time, if given, is the idle limit for this call. With a session store
    (app.sessions) these limits are the store's to apply, and expiry_time is not used."""

    if app is None:
        app = asfquart.APP

    # We store the session cookie using the app.app_id identifier, to distinguish between
    # two asfquart apps running on the same hostname.
    cookie_id = app.app_id
    if cookie_id in quart.session:
        if app.sessions:
            entry = quart.session[cookie_id]
            sid = entry.get("sid") if isinstance(entry, dict) else None
            if not isinstance(sid, str) or not sid:
                del quart.session[cookie_id]
                return None
            stored = await app.sessions.validate(_hash_sid(sid))
            if stored is None:
                del quart.session[cookie_id]
                return None
            return stored
        now = time.time()
        session_dict = quart.session[cookie_id]
        if isinstance(session_dict, dict):
            # If a session cookie has expired (not used for too long, or created too long ago),
            # we delete it instead of returning it
            if _session_expired(app, session_dict, now, expiry_time):
                del quart.session[cookie_id]
            # If it's still valid, use it
            else:
                if _timestamp(session_dict, "cts") is None:
                    # Written before sessions recorded when they were created: start the clock now
                    session_dict["cts"] = now
                    _mark_session_changed()
                # Update the timestamp, since the session has been requested (and thus used). The
                # cookie is not sent again for every request: once a minute is often enough to keep
                # an idle limit of days, and a shorter limit is kept to within a tenth of itself.
                idle_limit = _idle_limit(app, expiry_time)
                refresh_interval = SESSION_REFRESH_INTERVAL
                if idle_limit > 0:
                    refresh_interval = min(SESSION_REFRESH_INTERVAL, idle_limit / 10)
                if (_timestamp(session_dict, "uts") or 0) <= now - refresh_interval:
                    session_dict["uts"] = now
                    _mark_session_changed()
                return ClientSession(session_dict)
    # Check for session providers in Auth header. These sessions are created ad-hoc, and do not linger in the
    # quart session DB. Since quart.request is not defined inside testing frameworks, the bool(request) test
    # asks the werkzeug LocalProxy wrapper whether a request exists or not, and bails if not.
    elif bool(quart.request) and "Authorization" in quart.request.headers and quart.request.authorization:
        match quart.request.authorization.type:
            case "bearer":  # Role accounts, PATs - TBD
                if app.token_handler:
                    if not callable(app.token_handler):
                        raise TypeError("app.token_handler is not a callable function.")
                    session_dict = None  # Blank, in case we don't have a working callback.
                    # Async token handler?
                    if inspect.iscoroutinefunction(app.token_handler):
                        session_dict = await app.token_handler(quart.request.authorization.token)
                    # Sync handler?
                    elif callable(app.token_handler):
                        session_dict = app.token_handler(quart.request.authorization.token)
                    # If token handler returns a dict, we have a session and should set it up
                    if session_dict:
                        return ClientSession(session_dict)
                else:
                    # The token is a credential, and must not end up in the log
                    LOGGER.warning("Bearer token presented, but no token handler is registered")
            case "basic":  # Basic LDAP auth - will need to grab info from LDAP
                if not app.basic_auth:
                    raise base.ASFQuartException("Basic authentication is not enabled", errorcode=401)
                if not ldap.LDAP_SUPPORTED:
                    # construct() refuses basic_auth=True without the LDAP libraries, so this is an
                    # app that set app.basic_auth itself. It is an error, and not "no session":
                    # the app was told to accept these credentials and cannot check them.
                    LOGGER.error("basic_auth is on, but the LDAP libraries (asfquart[aioldap]) are not installed")
                    raise base.ASFQuartException("Basic authentication is not available", errorcode=500)
                try:
                    auth_user = quart.request.authorization.parameters["username"]
                    auth_pwd = quart.request.authorization.parameters["password"]
                    ldap_client = ldap.LDAPClient(auth_user, auth_pwd)
                    ldap_affiliations = await ldap_client.get_affiliations()
                    # Convert to the usual session dict. TODO: add a single standardized parser/class for sessions
                    session_dict = {
                        "uid": auth_user,
                        "pmcs": ldap_affiliations[ldap.DEFAULT_OWNER_ATTR],
                        "projects": ldap_affiliations[ldap.DEFAULT_MEMBER_ATTR],
                    }
                    return ClientSession(session_dict)
                except (binascii.Error, ValueError, KeyError) as e:
                    # binascii/ValueError == bad base64 auth string
                    # KeyError = missing username or password
                    raise base.ASFQuartException("Invalid Authorization header provided", errorcode=400) from e
            case _:  # for match, this is the default
                raise base.ASFQuartException("Not implemented yet", errorcode=501)


def write(session_data: dict, app=None, new_session: bool = False):
    """Sets a cookie-based user session for this app.

    Writing the session of the user who is already logged in keeps its creation time, so that
    changing a session does not extend its MAX_SESSION_AGE. Pass new_session=True when the user
    has just authenticated, to start a new session with the full lifetime."""

    if app is None:
        app = asfquart.APP

    if app.sessions:
        raise RuntimeError("write() cannot be used with an async session store; use awrite() instead")

    cookie_id = app.app_id
    now = time.time()
    dict_copy = session_data.copy()  # Copy dict so we don't mess with the original data
    dict_copy["cts"] = _created_at(app, session_data, now, new_session)  # Created at, for session length checks later
    dict_copy["uts"] = now  # Set last access timestamp for expiry checks later
    quart.session[cookie_id] = dict_copy


async def awrite(session_data: dict, app=None, new_session: bool = False):
    """Async version of write() for use with async session stores. With a store, every call
    creates a new session in it; new_session only matters for a session kept in the cookie."""

    if app is None:
        app = asfquart.APP

    cookie_id = app.app_id
    if app.sessions:
        entry = quart.session.get(cookie_id)
        if isinstance(entry, dict):
            old_sid = entry.get("sid")
            if isinstance(old_sid, str) and old_sid:
                await app.sessions.destroy(_hash_sid(old_sid))
        sid = _generate_sid()
        await app.sessions.create(_hash_sid(sid), session_data)
        quart.session[cookie_id] = {"sid": sid}
    else:
        now = time.time()
        dict_copy = session_data.copy()
        dict_copy["cts"] = _created_at(app, session_data, now, new_session)
        dict_copy["uts"] = now
        quart.session[cookie_id] = dict_copy


def clear(app=None):
    """Clears a session."""

    if app is None:
        app = asfquart.APP

    if app.sessions:
        raise RuntimeError("clear() cannot be used with an async session store; use aclear() instead")

    quart.session.pop(app.app_id, None)


async def aclear(app=None):
    """Async version of clear() for use with async session stores."""

    if app is None:
        app = asfquart.APP

    cookie_id = app.app_id
    if app.sessions:
        entry = quart.session.get(cookie_id)
        if isinstance(entry, dict):
            sid = entry.get("sid")
            if isinstance(sid, str) and sid:
                await app.sessions.destroy(_hash_sid(sid))
    quart.session.pop(cookie_id, None)


async def areplace(session_object: SessionProtocol, app=None):
    """Replaces the current session with a pre-constructed session object."""

    if app is None:
        app = asfquart.APP

    if not app.sessions:
        raise RuntimeError("areplace() requires an async session store")
    # Checked before the old session is touched, so a refusal leaves the user logged in
    if not hasattr(session_object, "uid"):
        raise TypeError(
            f"areplace() needs a session object with a uid attribute, got {type(session_object).__name__} "
            "- see SessionProtocol"
        )

    cookie_id = app.app_id
    new_sid = _generate_sid()
    new_hsid = _hash_sid(new_sid)
    old_hsid = None
    entry = quart.session.get(cookie_id)
    if isinstance(entry, dict):
        old_sid = entry.get("sid")
        if isinstance(old_sid, str) and old_sid:
            old_hsid = _hash_sid(old_sid)
    if hasattr(app.sessions, "replace"):
        await app.sessions.replace(old_hsid, new_hsid, session_object)
    else:
        if old_hsid is not None:
            await app.sessions.destroy(old_hsid)
        await app.sessions.register(new_hsid, session_object)
    quart.session[cookie_id] = {"sid": new_sid}
