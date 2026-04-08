#!/usr/bin/env python3
"""ASFQuart - User session methods and decorators"""

from . import base, ldap
import hashlib
import secrets
import time
import binascii

import quart
import asfquart
import asyncio


def _generate_sid() -> str:
    return secrets.token_urlsafe(20)


def _hash_sid(sid: str) -> str:
    return hashlib.sha3_256(sid.encode("utf-8")).hexdigest()


class ClientSession(dict):
    def __init__(self, raw_data: dict):
        """Initializes a client session from a raw dict. ClientSession is a subclassed dict, so that
        we can send it to quart in a format it can render."""
        super().__init__()
        self.uid = raw_data.get("uid")
        self.dn = raw_data.get("dn")
        self.fullname = raw_data.get("fullname")
        self.email = raw_data.get("email", f"{self.uid}@apache.org")
        self.isMember = raw_data.get("isMember", False)
        self.isChair = raw_data.get("isChair", False)
        self.isRoot = raw_data.get("isRoot", False)
        self.committees = raw_data.get("pmcs", [])
        self.projects = raw_data.get("projects", [])
        self.mfa = raw_data.get("mfa", False)
        self.isRole = raw_data.get("roleaccount", False)
        self.metadata = raw_data.get("metadata", {})  # This can contain whatever specific metadata the app needs
        # Update the external dict representation with internal values
        self.update(self.__dict__.items())


async def read(expiry_time=86400*7, app=None):
    """Fetches a cookie-based session if found (and valid), and updates the last access timestamp
    for the session."""

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
        max_session_age = app.cfg.get("MAX_SESSION_AGE", 0)
        cookie_expiry_deadline = now - expiry_time
        cookie_session_age_limit = now - max_session_age
        session_dict = quart.session[cookie_id]
        if isinstance(session_dict, dict):
            session_create_timestamp = session_dict.get("cts", 0)
            session_update_timestamp = session_dict.get("uts", 0)
            # If a session cookie has expired (not updated/used for seven days), we delete it instead of returning it
            if session_update_timestamp < cookie_expiry_deadline:
                del quart.session[cookie_id]
            # If max session lifetime is set and the cookie has exceeded it, we delete it
            elif max_session_age > 0 and session_create_timestamp < cookie_session_age_limit:
                del quart.session[cookie_id]
            # If it's still valid, use it
            else:
                # Update the timestamp, since the session has been requested (and thus used)
                session_dict["uts"] = now
                return ClientSession(session_dict)
    # Check for session providers in Auth header. These sessions are created ad-hoc, and do not linger in the
    # quart session DB. Since quart.request is not defined inside testing frameworks, the bool(request) test
    # asks the werkzeug LocalProxy wrapper whether a request exists or not, and bails if not.
    elif bool(quart.request) and 'Authorization' in quart.request.headers and quart.request.authorization:
        match quart.request.authorization.type:
            case "bearer":  # Role accounts, PATs - TBD
                if app.token_handler:
                    if not callable(app.token_handler):
                        raise TypeError("app.token_handler is not a callable function.")
                    session_dict = None  # Blank, in case we don't have a working callback.
                    # Async token handler?
                    if asyncio.iscoroutinefunction(app.token_handler):
                        session_dict = await app.token_handler(quart.request.authorization.token)
                    # Sync handler?
                    elif callable(app.token_handler):
                        session_dict = app.token_handler(quart.request.authorization.token)
                    # If token handler returns a dict, we have a session and should set it up
                    if session_dict:
                        return ClientSession(session_dict)
                else:
                    print(f"Debug: No PAT handler registered to handle token {quart.request.authorization.token}")
            case "basic":  # Basic LDAP auth - will need to grab info from LDAP
                if not app.basic_auth:
                    raise base.ASFQuartException("Basic authentication is not enabled", errorcode=401)
                if ldap.LDAP_SUPPORTED:
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
            case _: # for match, this is the default
                raise base.ASFQuartException("Not implemented yet", errorcode=501)


def write(session_data: dict, app=None):
    """Sets a cookie-based user session for this app."""

    if app is None:
        app = asfquart.APP

    if app.sessions:
        raise RuntimeError("write() cannot be used with an async session store; use awrite() instead")

    cookie_id = app.app_id
    dict_copy = session_data.copy()  # Copy dict so we don't mess with the original data
    dict_copy["cts"] = time.time()   # Set created at timestamp for session length checks later
    dict_copy["uts"] = time.time()   # Set last access timestamp for expiry checks later
    quart.session[cookie_id] = dict_copy


async def awrite(session_data: dict, app=None):
    """Async version of write() for use with async session stores."""

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
        dict_copy = session_data.copy()
        dict_copy["cts"] = time.time()
        dict_copy["uts"] = time.time()
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


async def areplace(session_object, app=None):
    """Replaces the current session with a pre-constructed session object."""

    if app is None:
        app = asfquart.APP

    if not app.sessions:
        raise RuntimeError("areplace() requires an async session store")

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
