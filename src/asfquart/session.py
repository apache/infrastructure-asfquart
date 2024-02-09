#!/usr/bin/env python3
"""ASFQuart - User session methods and decorators"""
from . import base
import quart.sessions
import time
import binascii
import base64


def read(expiry_time=86400*7):
    """Fetches a cookie-based session if found (and valid), and updates the last access timestamp
    for the session."""
    # We store the session cookie using the base.APP.app_id identifier, to distinguish between
    # two asfquart apps running on the same hostname.
    cookie_id = base.APP.app_id
    if cookie_id in quart.session:
        now = time.time()
        cookie_expiry_deadline = now - expiry_time
        session_dict = quart.session[cookie_id]
        if isinstance(session_dict, dict):
            session_update_timestamp = session_dict.get("uts", 0)
            # If a session cookie has expired (not updated/used for seven days), we delete it instead of returning it
            if session_update_timestamp < cookie_expiry_deadline:
                del quart.session[cookie_id]
            # If it's still valid, use it
            else:
                # Update the timestamp, since the session has been requested (and thus used)
                session_dict["uts"] = now
                return session_dict
    # Check for session provides in Auth header
    elif 'Authorization' in quart.request.headers:
        auth_header = quart.request.headers.get("Authorization")
        if " " in auth_header:
            authtype, authparams = auth_header.split(" ", maxsplit=1)
            match authtype.lower():
                case "bearer":  # Role accounts, PATs - TBD
                    print(f"Debug: Do auth check for role with token {authparams} here...")
                case "basic":  # Basic LDAP auth - will need to grab info from LDAP
                    try:
                        params_decoded = base64.standard_b64decode(authparams).decode("utf-8")
                        auth_user, auth_pwd = params_decoded.split(":", maxsplit=1)
                        print(f"Debug: Do auth check for {auth_user} here...")
                    except (binascii.Error, ValueError) as e:
                        raise base.ASFQuartException("Invalid Authorization header provided", errorcode=400)
                case default:
                    raise base.ASFQuartException("Not implemented yet", errorcode=501)


def write(session_data: dict):
    """Sets a cookie-based user session for this app"""
    cookie_id = base.APP.app_id
    dict_copy = session_data.copy()  # Copy dict so we don't mess with the original data
    dict_copy["uts"] = time.time()   # Set last access timestamp for expiry checks later
    quart.session[cookie_id] = dict_copy


def clear():
    """Clears a session"""
    quart.session.pop(base.APP.app_id, None)  # Safely pop the session if it's there.
