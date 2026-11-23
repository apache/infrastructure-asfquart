#!/usr/bin/env python3
"""ASFQuart - LDAP Authentication methods and decorators"""

import logging
import re
import time

from . import base

# The ASF LDAP server, used only for requests with an "Authorization: Basic" header and no session
# cookie: to check the password (on every such request) and to look up project memberships (cached
# for an hour per user).
# If it cannot be reached, those requests fail with a 500; OAuth logins and sessions do not depend
# on it. There is no fallback server. See docs/external-services.md.
DEFAULT_LDAP_URI = "ldaps://ldap-eu.apache.org:636"
DEFAULT_LDAP_BASE = "uid=%s,ou=people,dc=apache,dc=org"
DEFAULT_LDAP_GROUP_BASE = "ou=project,ou=groups,dc=apache,dc=org"
UID_RE = re.compile(r"^(?:uid=)?([^,]+)")
GROUP_RE = re.compile(r"^(?:cn=)?([^,]+)")
# The shape of an ASF user id. The rule is written once, as base.ASF_UID_RE, and is the same one
# that generics.py applies to the OAuth provider's response. None of the characters that it allows
# has a special meaning in a DN.
VALID_UID_RE = base.ASF_UID_RE
DEFAULT_MEMBER_ATTR = "member"
DEFAULT_OWNER_ATTR = "owner"
DEFAULT_LDAP_CACHE_TTL = 3600  # Cache LDAP lookups for one hour
DEFAULT_LDAP_CACHE_MAX_ENTRIES = 1000  # ... for at most this many users; the least recently used go first

# Test if LDAP is enabled for this quart app, and if so, enable LDAP Auth support
# This assumes the quart app was installed with asfpy[aioldap] in the Pipfile.
try:
    import asfpy.aioldap
    import bonsai.errors  # pyright: ignore[reportMissingImports] - optional, with the aioldap extra

    LDAP_SUPPORTED = True
except ModuleNotFoundError:
    LDAP_SUPPORTED = False

LDAP_CACHE: dict[str, tuple[float, dict[str, list[str]]]] = {}  # Temporary one-hour cache to speed up lookups.

LOGGER = logging.getLogger(__name__)

# A wrong password is logged, so that somebody guessing passwords can be seen. For one user it
# is logged at most this often, in seconds, with a count of the failures in between, so that a
# flood of guesses does not become a flood in the log.
FAILED_LOGIN_LOG_INTERVAL = 60
# The users whose failures are being counted. No more than this many are kept; a user who is
# dropped is logged again at their next failure.
MAX_FAILED_LOGIN_USERS = 1000
# user id -> (when a failure was last logged, failures since then that were not logged)
_FAILED_LOGINS: dict[str, tuple[float, int]] = {}


def _log_failed_login(userid: str, error: Exception) -> None:
    """Logs that LDAP refused this user's password. The user id has the form of an ASF user id,
    having been checked before LDAP was asked, so it is safe in a log. The password is not logged."""
    now = time.time()
    logged_at, unlogged = _FAILED_LOGINS.pop(userid, (0.0, 0))
    if now - logged_at < FAILED_LOGIN_LOG_INTERVAL:
        _FAILED_LOGINS[userid] = (logged_at, unlogged + 1)  # back at the end, as the latest to fail
        return
    while len(_FAILED_LOGINS) >= MAX_FAILED_LOGIN_USERS:
        del _FAILED_LOGINS[next(iter(_FAILED_LOGINS))]  # the one that failed longest ago
    _FAILED_LOGINS[userid] = (now, 0)
    if unlogged:
        LOGGER.warning(
            "HTTP Basic authentication failed for user %s: %s (and %d more times since this was last logged)",
            userid,
            error,
            unlogged,
        )
    else:
        LOGGER.warning("HTTP Basic authentication failed for user %s: %s", userid, error)


def _purge_ldap_cache(max_size: int) -> None:
    """Removes the cached lookups that have expired, and then those that were used least recently
    for as long as there are more than max_size.

    The dictionary is kept in order of use: a lookup goes to the end when it is made, and again
    each time it is used, so the ones at the front are the ones that have gone longest unused.
    That is not the order of their ages, so every entry is looked at for expiry."""
    deadline = time.time() - DEFAULT_LDAP_CACHE_TTL
    for userid in [userid for userid, entry in LDAP_CACHE.items() if entry[0] <= deadline]:
        del LDAP_CACHE[userid]
    while LDAP_CACHE and len(LDAP_CACHE) > max_size:
        del LDAP_CACHE[next(iter(LDAP_CACHE))]


class LDAPClient:
    def __init__(self, username: str, password: str) -> None:
        # The username goes into a DN, so it must be a plain user id, and nothing that could alter
        # the DN (a comma, an equals sign and so on). The error is the one given for a wrong
        # password, and no connection to LDAP is made.
        if not isinstance(username, str) or not VALID_UID_RE.fullmatch(username):
            raise base.ASFQuartException("Invalid credentials provided", errorcode=403)
        # An empty password must never reach LDAP: a bind with a DN and no password is an
        # "unauthenticated bind", which a server may accept without checking anything.
        if not isinstance(password, str) or not password:
            raise base.ASFQuartException("Invalid credentials provided", errorcode=403)
        self.userid = username
        self.dn = DEFAULT_LDAP_BASE % username
        # The ignores here and below: both modules are imported when LDAP_SUPPORTED
        self.client = asfpy.aioldap.LDAPClient(DEFAULT_LDAP_URI, self.dn, password)  # pyright: ignore[reportPossiblyUnboundVariable]

    async def get_affiliations(self) -> dict[str, list[str]]:  # noqa: C901
        """Scans for which projects this user is a part of. Returns a dict with memberships of each
        pmc/committer role (member/owner in LDAP)"""
        all_projects = DEFAULT_LDAP_GROUP_BASE
        attrs = [DEFAULT_MEMBER_ATTR, DEFAULT_OWNER_ATTR]
        # Lookups that have expired are not left in the cache until the same user comes back
        _purge_ldap_cache(DEFAULT_LDAP_CACHE_MAX_ENTRIES)
        # Check LDAP cache. If found, we only need to test LDAP auth
        try:
            # The lookup is held here, and not read from the cache again further down: while this
            # request waits for LDAP, another may remove it from the cache.
            cached = LDAP_CACHE.get(self.userid)
            if cached is not None and cached[0] > (time.time() - DEFAULT_LDAP_CACHE_TTL):
                async with self.client.connect():
                    pass
                # The password was right, so this counts as a use: move the lookup to the end, where
                # it is the last to be dropped. (Unless it has been removed or renewed meanwhile.)
                if LDAP_CACHE.get(self.userid) is cached:
                    LDAP_CACHE[self.userid] = LDAP_CACHE.pop(self.userid)
                return cached[1]
            else:
                ldap_groups: dict[str, list[str]] = {attr: [] for attr in attrs}
                async with self.client.connect() as conn:
                    rv = await conn.search(all_projects, attrs)
                    if not rv:
                        raise Exception("Empty result set returned by LDAP")  # pylint: disable=broad-exception-raised
                    for project in rv:
                        if "dn" in project and any(xattr in project for xattr in attrs):
                            dn_match = GROUP_RE.match(str(project["dn"]))
                            if dn_match:
                                project_name = dn_match.group(1)
                                for xattr in attrs:
                                    if self.dn in project.get(xattr, []):
                                        ldap_groups[xattr].append(project_name)
                    # Make room if the cache is full, and add this lookup at the end, as the newest
                    LDAP_CACHE.pop(self.userid, None)
                    _purge_ldap_cache(DEFAULT_LDAP_CACHE_MAX_ENTRIES - 1)
                    LDAP_CACHE[self.userid] = (time.time(), ldap_groups)
                return ldap_groups

        except bonsai.errors.AuthenticationError as e:  # pyright: ignore[reportPossiblyUnboundVariable]
            # What LDAP said goes to the log, and not to the client
            _log_failed_login(self.userid, e)
            raise base.ASFQuartException("Invalid credentials provided", errorcode=403) from e
        except Exception as e:
            LOGGER.error("LDAP lookup for user %s failed: %s: %s", self.userid, type(e).__name__, e)
            raise base.ASFQuartException(
                "Could not perform LDAP authorization check, please try again later.", errorcode=500
            ) from e
