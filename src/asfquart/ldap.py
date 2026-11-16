#!/usr/bin/env python3
"""ASFQuart - LDAP Authentication methods and decorators"""
from . import base
import re
import time

DEFAULT_LDAP_URI = "ldaps://ldap-eu.apache.org:636"
DEFAULT_LDAP_BASE = "uid=%s,ou=people,dc=apache,dc=org"
DEFAULT_LDAP_GROUP_BASE = "ou=project,ou=groups,dc=apache,dc=org"
UID_RE = re.compile(r"^(?:uid=)?([^,]+)")
GROUP_RE = re.compile(r"^(?:cn=)?([^,]+)")
# The shape of an ASF user id: lower case letters, digits, hyphens and underscores, starting with a
# letter, and at least two characters. This is the rule of AsfUid in atr/models/safe.py of
# apache/tooling-trusted-releases, except that AsfUid asks for three characters, and there are ASF
# users whose id has two. None of these characters has a special meaning in a DN.
VALID_UID_RE = re.compile(r"[a-z][a-z0-9_-]{1,}")
DEFAULT_MEMBER_ATTR = "member"
DEFAULT_OWNER_ATTR = "owner"
DEFAULT_LDAP_CACHE_TTL = 3600  # Cache LDAP lookups for one hour

# Test if LDAP is enabled for this quart app, and if so, enable LDAP Auth support
# This assumes the quart app was installed with asfpy[aioldap] in the Pipfile.
try:
    import asfpy.aioldap
    import bonsai.errors
    LDAP_SUPPORTED = True
except ModuleNotFoundError:
    LDAP_SUPPORTED = False

LDAP_CACHE: dict[str, list] = {}  # Temporary one-hour cache to speed up lookups.


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
                    LDAP_CACHE[self.userid] = (time.time(), ldap_groups)
            return LDAP_CACHE[self.userid][1]

        except bonsai.errors.AuthenticationError as e:
            raise base.ASFQuartException(f"Invalid credentials provided: {e}", errorcode=403)
        except Exception as e:
            print(f"Base exception during LDAP lookup: {e}")
            raise base.ASFQuartException(
                "Could not perform LDAP authorization check, please try again later.", errorcode=500
            )
