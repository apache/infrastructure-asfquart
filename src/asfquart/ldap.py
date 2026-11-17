#!/usr/bin/env python3
"""ASFQuart - LDAP Authentication methods and decorators"""
from . import base
import re
import time

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
DEFAULT_LDAP_CACHE_MAX_ENTRIES = 1000  # ... for at most this many users; the oldest lookups go first

# Test if LDAP is enabled for this quart app, and if so, enable LDAP Auth support
# This assumes the quart app was installed with asfpy[aioldap] in the Pipfile.
try:
    import asfpy.aioldap
    import bonsai.errors
    LDAP_SUPPORTED = True
except ModuleNotFoundError:
    LDAP_SUPPORTED = False

LDAP_CACHE: dict[str, list] = {}  # Temporary one-hour cache to speed up lookups.


def _purge_ldap_cache(max_size: int) -> None:
    """Removes the cached lookups that have expired, and then the oldest of the rest for as long
    as there are more than max_size.

    The dictionary keeps its entries in the order they were added, and a lookup that is renewed is
    added again at the end, so the oldest are at the front."""
    deadline = time.time() - DEFAULT_LDAP_CACHE_TTL
    while LDAP_CACHE:
        oldest = next(iter(LDAP_CACHE))
        if LDAP_CACHE[oldest][0] > deadline and len(LDAP_CACHE) <= max_size:
            break
        del LDAP_CACHE[oldest]


class LDAPClient:
    def __init__(self, username: str, password: str):
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
        self.client = asfpy.aioldap.LDAPClient(DEFAULT_LDAP_URI, self.dn, password)

    async def get_affiliations(self):
        """Scans for which projects this user is a part of. Returns a dict with memberships of each
        pmc/committer role (member/owner in LDAP)"""
        all_projects = DEFAULT_LDAP_GROUP_BASE
        attrs = [DEFAULT_MEMBER_ATTR, DEFAULT_OWNER_ATTR]
        # Lookups that have expired are not left in the cache until the same user comes back
        _purge_ldap_cache(DEFAULT_LDAP_CACHE_MAX_ENTRIES)
        # Check LDAP cache. If found, we only need to test LDAP auth
        try:
            if self.userid in LDAP_CACHE and LDAP_CACHE[self.userid][0] > (time.time() - DEFAULT_LDAP_CACHE_TTL):
                async with self.client.connect():
                    pass
            else:
                ldap_groups = {attr: [] for attr in attrs}
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
            return LDAP_CACHE[self.userid][1]

        except bonsai.errors.AuthenticationError as e:
            raise base.ASFQuartException(f"Invalid credentials provided: {e}", errorcode=403)
        except Exception as e:
            print(f"Base exception during LDAP lookup: {e}")
            raise base.ASFQuartException(
                "Could not perform LDAP authorization check, please try again later.", errorcode=500
            )
