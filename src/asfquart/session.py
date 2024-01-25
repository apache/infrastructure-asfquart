#!/usr/bin/env python3
"""ASFQuart - User session methods and decorators"""
from . import base
import quart.sessions
import time


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


def write(session_data: dict):
    """Sets a cookie-based user session for this app"""
    cookie_id = base.APP.app_id
    dict_copy = session_data.copy()  # Copy dict so we don't mess with the original data
    dict_copy["uts"] = time.time()   # Set last access timestamp for expiry checks later
    quart.session[cookie_id] = dict_copy


def clear():
    """Clears a session"""
    quart.session.pop(base.APP.app_id, None)  # Safely pop the session if it's there.
