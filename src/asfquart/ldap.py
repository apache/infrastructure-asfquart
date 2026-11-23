#!/usr/bin/env python3
"""ASFQuart - LDAP Authentication methods and decorators"""

import asyncio
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
# For all users together, no more than this many lines about wrong passwords are written in one
# interval, so that guessing at many user ids in turn does not flood the log either. The failures
# past that are counted, and one more line gives the count when the next interval begins.
FAILED_LOGIN_LOG_LIMIT = 60
# [when this interval began, lines written in it, failures in it that no line was written for]
_FAILED_LOGIN_LINES: list[float] = [0.0, 0, 0]
# The users whose failures are being counted. No more than this many are kept. A user who is
# dropped has the failures that were counted logged first, and is logged again at the next one.
MAX_FAILED_LOGIN_USERS = 1000
# user id -> (when a failure was last logged, failures since then that were not logged)
_FAILED_LOGINS: dict[str, tuple[float, int]] = {}

# How long a request waits for LDAP to check a password and look up the memberships, in seconds.
# After that the request is answered with an error. The work in LDAP cannot be stopped from here:
# it goes on in a thread of asfpy.aioldap until LDAP answers or the connection fails.
LDAP_TIMEOUT = 30
# How many such pieces of work there may be at one time, counting those that a request has stopped
# waiting for. Each one holds a thread and a connection, so without a limit an LDAP server that
# does not answer would collect them for as long as requests kept coming. Over the limit, a
# request is answered with an error at once, and LDAP is not asked.
MAX_LDAP_OPERATIONS = 10
_ldap_operations = 0  # how many there are now
_busy_logged_at = 0.0  # when it was last logged that the limit was reached; at most once a minute


def _unavailable() -> base.ASFQuartException:
    """The error for an LDAP check that could not be made. The log says why; the client is not told."""
    return base.ASFQuartException("Could not perform LDAP authorization check, please try again later.", errorcode=500)


def _ldap_operation_done(task: "asyncio.Future[dict[str, list[str]]]") -> None:
    """Called when the work in LDAP has ended, however it ended, and however long ago the request
    that started it stopped waiting"""
    global _ldap_operations
    _ldap_operations -= 1
    if not task.cancelled():
        task.exception()  # looked at, so that asyncio does not report it as never retrieved


def _failed_login_line(failures: int, message: str, *args: object) -> None:
    """Writes one line about wrong passwords, which stands for this many failures that have not
    been logged, unless FAILED_LOGIN_LOG_LIMIT lines were written in this interval already. Then
    the failures are counted, and the count is logged when the next interval begins."""
    now = time.time()
    began, _lines, unlogged = _FAILED_LOGIN_LINES
    if now - began >= FAILED_LOGIN_LOG_INTERVAL:
        _FAILED_LOGIN_LINES[:] = [now, 0, 0]
        if unlogged:
            LOGGER.warning(
                "HTTP Basic authentication failed %d more times, which were not logged one by one:"
                " the limit of %d lines in %d seconds had been reached",
                unlogged,
                FAILED_LOGIN_LOG_LIMIT,
                FAILED_LOGIN_LOG_INTERVAL,
            )
    if _FAILED_LOGIN_LINES[1] >= FAILED_LOGIN_LOG_LIMIT:
        _FAILED_LOGIN_LINES[2] += failures
        return
    _FAILED_LOGIN_LINES[1] += 1
    LOGGER.warning(message, *args)


def _log_failed_login(userid: str, error: Exception) -> None:
    """Logs that LDAP refused this user's password. The user id has the form of an ASF user id,
    having been checked before LDAP was asked, so it is safe in a log. The password is not logged.

    No failure goes uncounted: one that gets no line of its own is in the count of the user's
    next line, or of the line that is written when the user is dropped, or of the line for all
    users that is written after the limit on lines was reached."""
    now = time.time()
    logged_at, unlogged = _FAILED_LOGINS.pop(userid, (0.0, 0))
    if now - logged_at < FAILED_LOGIN_LOG_INTERVAL:
        _FAILED_LOGINS[userid] = (logged_at, unlogged + 1)  # back at the end, as the latest to fail
        return
    while len(_FAILED_LOGINS) >= MAX_FAILED_LOGIN_USERS:
        dropped = next(iter(_FAILED_LOGINS))  # the one that failed longest ago
        _dropped_at, dropped_unlogged = _FAILED_LOGINS.pop(dropped)
        if dropped_unlogged:
            # What LDAP said is not kept, and it was in the line that these are counted from
            _failed_login_line(
                dropped_unlogged,
                "HTTP Basic authentication failed for user %s %d more times since it was last logged",
                dropped,
                dropped_unlogged,
            )
    _FAILED_LOGINS[userid] = (now, 0)
    if unlogged:
        _failed_login_line(
            unlogged + 1,
            "HTTP Basic authentication failed for user %s: %s (and %d more times since this was last logged)",
            userid,
            error,
            unlogged,
        )
    else:
        _failed_login_line(1, "HTTP Basic authentication failed for user %s: %s", userid, error)


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

    async def get_affiliations(self) -> dict[str, list[str]]:
        """Checks the password, and scans for which projects this user is a part of. Returns a dict
        with memberships of each pmc/committer role (member/owner in LDAP).

        Waits for LDAP no longer than LDAP_TIMEOUT, and does not ask LDAP at all while
        MAX_LDAP_OPERATIONS earlier checks are still going on. In both cases the error is the
        one for an LDAP server that cannot be reached."""
        global _ldap_operations, _busy_logged_at
        if _ldap_operations >= MAX_LDAP_OPERATIONS:
            if time.time() - _busy_logged_at >= 60:
                _busy_logged_at = time.time()
                LOGGER.error(
                    "%d LDAP checks are going on, which is the most allowed; refusing more until one ends."
                    " LDAP may not be answering",
                    _ldap_operations,
                )
            raise _unavailable()
        _ldap_operations += 1
        # A task of its own, so that it runs to its end when this request stops waiting for it or
        # goes away, and is counted until then. asyncio.wait() leaves the task alone in both cases.
        task = asyncio.ensure_future(self._lookup_affiliations())
        task.add_done_callback(_ldap_operation_done)
        done, _pending = await asyncio.wait({task}, timeout=LDAP_TIMEOUT)
        if not done:
            LOGGER.error("LDAP did not answer within %s seconds for user %s", LDAP_TIMEOUT, self.userid)
            raise _unavailable()
        return task.result()

    async def _lookup_affiliations(self) -> dict[str, list[str]]:  # noqa: C901
        """The work of get_affiliations() in LDAP, without its limits"""
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
            raise _unavailable() from e
