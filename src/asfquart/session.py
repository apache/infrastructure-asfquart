#!/usr/bin/env python3
"""ASFQuart - User session methods and decorators"""
import typing

from . import base, ldap
import quart.sessions
import time
import binascii


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
        # Update the external dict representation with internal values
        self.update(self.__dict__.items())


async def read(expiry_time=86400*7) -> typing.Optional[ClientSession]:
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
                return ClientSession(session_dict)
    # Check for session providers in Auth header. These sessions are created ad-hoc, and do not linger in the
    # quart session DB. Since quart.request is not defined inside testing frameworks, the bool(request) test
    # asks the werkzeug LocalProxy wrapper whether a request exists or not, and bails if not.
    elif bool(quart.request) and 'Authorization' in quart.request.headers:
        match quart.request.authorization.type:
                case "bearer":  # Role accounts, PATs - TBD
                    print(f"Debug: Do auth check for role with token {quart.request.authorization.token} here...")
                case "basic":  # Basic LDAP auth - will need to grab info from LDAP
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
