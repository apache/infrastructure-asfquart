#!/usr/bin/env python3
"""Generic endpoints for ASFQuart"""

import asyncio
import functools
import hashlib
import hmac
import logging
import posixpath
import re
import secrets
import ssl
import time
import typing
import unicodedata
import urllib
import urllib.parse

import aiohttp
import quart
import quart.typing

import asfquart  # implies .session

# These are the ASF OAuth URLs for init and verification. Used for setup_oauth()
# - OAUTH_URL_INIT: where the browser is sent to log in. asfquart does not connect to it itself.
# - OAUTH_URL_CALLBACK: where asfquart exchanges the code from the callback for the user's details,
#   once per login. If it cannot be reached or refuses the code, that login fails and no session is made.
#   The code is POSTed in a form body, to keep it out of URLs that get logged (#96). A value with a
#   %s for the code, as it used to need, is still sent as a GET - see docs/external-services.md.
# Sessions that already exist do not depend on either. See docs/external-services.md.
OAUTH_URL_INIT = "https://oauth.apache.org/auth-oidc?state=%s&redirect_uri=%s"
OAUTH_URL_CALLBACK = "https://oauth.apache.org/token-oidc"
_OLD_DEFAULT_CALLBACK = OAUTH_URL_CALLBACK + "?code=%s"  # the default before #96
DEFAULT_OAUTH_URI = "/auth"

# The default for setup_oauth()'s callback_host, e.g. "https://myapp.apache.org" (#93)
OAUTH_CALLBACK_HOST: str | None = None

# The default for setup_oauth()'s logout_by_get. A logout changes state, so it ought to be a POST
# (#69). GET is still accepted because many apps have a logout link; an app whose logout is a form
# can set this to False, and a GET logout is then a 405. See docs/oauth.md.
OAUTH_LOGOUT_BY_GET = True

# The default for setup_oauth()'s logout_same_site. A logout is accepted from the app's own pages
# (the same origin). With True it is also accepted from the same site, which is every host that
# shares the app's registered domain: for an app at apache.org, every other apache.org host. Set it
# only if users have to be able to log out from a link or a form on another such host.
OAUTH_LOGOUT_SAME_SITE = False

# The pending login is tied to the browser that started it, via this cookie.
# SameSite=Lax is required: the callback is a top level navigation from the
# OAuth provider, and a Strict cookie is not sent when the provider is on a
# different site. Deployments where the provider and the app share a site may
# set STATE_COOKIE_SAMESITE = "Strict".
#
# The __Host- prefix makes a browser refuse the cookie unless it is Secure, has Path=/, and has no
# Domain. Without it, a page on another host of the same site could give the browser a cookie of
# this name with a Domain, and so its own identifier, and complete a login in somebody else's
# browser. A browser also refuses a __Host- cookie that is not Secure, so to develop over plain
# HTTP set the name back to "asfquart-oauth-state" along with STATE_COOKIE_SECURE = False. See
# "Cookie names" in docs/sessions.md.
STATE_COOKIE_NAME = "__Host-asfquart-oauth-state"
STATE_COOKIE_SAMESITE = "Lax"
STATE_COOKIE_SECURE = True

# Time limits for the code exchange with the OAuth provider. The exchange holds a
# request open, so every phase is bounded: 10 seconds to connect, 15 seconds
# between reads, and 30 seconds for the exchange as a whole.
OAUTH_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10, sock_connect=10, sock_read=15)

# The shape of an ASF user id, as returned in the "uid" field by the OAuth provider. The rule is
# written once, as base.ASF_UID_RE, and is the same one that ldap.py applies to a username.
OAUTH_UID_RE = asfquart.base.ASF_UID_RE

# How many logins may be pending (started, and not yet completed or expired) at one time. Each
# takes a few hundred bytes, plus its redirect target. When there are more, the oldest are dropped,
# and fail if completed.
DEFAULT_MAX_PENDING_LOGINS = 10000

# The longest redirect target (the value of ?login= or ?logout=) that is accepted, in characters
MAX_REDIRECT_URI_LENGTH = 2048

LOGGER = logging.getLogger(__name__)


# An exact match rather than parsing, as urlsplit lets through userinfo, spaces and the like
_CALLBACK_HOST_RE = re.compile(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?")


def _check_callback_host(host: object) -> None:
    """Raises a ValueError unless host is usable as the OAuth callback host"""
    if not isinstance(host, str) or not _CALLBACK_HOST_RE.fullmatch(host):
        raise ValueError("The OAuth callback host must be https://, a host name, and optionally a port")


# The longest scheme and host that a callback address is built from when none is pinned and they
# come from the request: "https://", a host name of 253 characters, a port and a "/". The address
# is kept for every pending login, so what a client can put into it has a limit.
MAX_CALLBACK_HOST_LENGTH = 268

_warned_host_not_pinned = False  # so the warning below is logged once per process, not per login


def _callback_host(pinned: str | None) -> str | None:
    """Returns the scheme and host for the OAuth callback URL. pinned is setup_oauth()'s callback_host.
    None if they have to come from the request and what the request has is too long."""
    global _warned_host_not_pinned
    host = pinned if pinned is not None else OAUTH_CALLBACK_HOST
    if host is None:
        if not _warned_host_not_pinned:
            _warned_host_not_pinned = True
            LOGGER.warning(
                "No callback_host is set, so the OAuth callback address is built from the Host header"
                " of each request. A client can send any Host header, unless the reverse proxy in"
                " front of the application refuses the ones that are not its own. The check that the"
                " provider's response is for a login that this application started depends on that"
                " address. Set callback_host in setup_oauth(), or generics.OAUTH_CALLBACK_HOST."
            )
        from_request = quart.request.host_url.replace("http://", "https://")  # Enforce HTTPS
        return from_request if len(from_request) <= MAX_CALLBACK_HOST_LENGTH else None
    # OAUTH_CALLBACK_HOST is read here, not at setup, so one set late still applies. A bad value
    # is an error - falling back to the Host header would quietly undo the pin.
    _check_callback_host(host)
    return host


_warned_legacy_callback = False  # so the warning below is logged once per process, not per login


async def _exchange_code(session: aiohttp.ClientSession, code: str) -> aiohttp.ClientResponse:
    """Sends the code from the callback to the OAuth provider, and returns its response"""
    global _warned_legacy_callback
    url = OAUTH_URL_CALLBACK
    if url == _OLD_DEFAULT_CALLBACK:
        url = url.removesuffix("?code=%s")  # apps that copied the old default get the POST too
    if "%s" not in url:
        # Don't follow redirects - aiohttp would resend as a GET with no body, losing the code
        return await session.post(url, data={"code": code}, allow_redirects=False)
    if not _warned_legacy_callback:
        _warned_legacy_callback = True
        LOGGER.warning(
            "OAUTH_URL_CALLBACK has a %s for the code, so the code is sent in the URL of a GET. "
            "Remove the query string to send it in a POST body instead."
        )
    # The code comes from the query string, so it is quoted before it goes into ours
    return await session.get(url % urllib.parse.quote(code, safe=""))


_warned_get_logout = False  # so the warning below is logged once per process, not per logout


def _refuse_logout(logout_by_get: bool | None, logout_same_site: bool | None) -> quart.Response | None:
    """Says whether a logout request is to be refused: returns the response to send, or None if the
    logout may go ahead. A refused logout leaves the session alone and clears nothing in the
    browser. The arguments are setup_oauth()'s arguments of those names."""
    global _warned_get_logout
    # The module settings are read here, not at setup, so that one set late still applies
    if logout_by_get is None:
        logout_by_get = OAUTH_LOGOUT_BY_GET
    if logout_same_site is None:
        logout_same_site = OAUTH_LOGOUT_SAME_SITE
    headers = quart.request.headers
    by_get = quart.request.method != "POST"
    if by_get and not logout_by_get:
        return quart.Response(
            status=405,
            response="Log out with a POST request.\n",
            headers={"Allow": "POST"},
            content_type="text/plain; charset=utf-8",
        )
    # A browser that is fetching the page ahead of time, in case the user goes there, has not been
    # asked to log anyone out. Sec-Purpose is the standard header; the other two are older.
    if by_get and (
        headers.get("Sec-Purpose", "").startswith("prefetch")
        or headers.get("Purpose") == "prefetch"
        or headers.get("X-Moz") == "prefetch"
    ):
        return quart.Response(status=403, response="Not prefetched\n", content_type="text/plain; charset=utf-8")
    # What the browser says about where the request came from. A browser that does not send these
    # headers is let through, as is a client that is not a browser.
    site = headers.get("Sec-Fetch-Site")
    if site is not None:
        # From the app's own pages, or from the same site if the app allows that
        allowed = site == "same-origin" or (site == "same-site" and logout_same_site)
        if by_get:
            # "none" is the user's own doing: a typed address or a bookmark. A form cannot be that.
            allowed = allowed or site == "none"
            # And it is the user going to the address in a window or tab, not a page fetching it
            # for an image, a script or a frame
            allowed = (
                allowed and headers.get("Sec-Fetch-Mode") == "navigate" and headers.get("Sec-Fetch-Dest") == "document"
            )
        if not allowed:
            return quart.Response(status=403, response="CSRF Protection\n", content_type="text/plain; charset=utf-8")
    if by_get and not _warned_get_logout:
        _warned_get_logout = True
        LOGGER.warning(
            "A logout was requested with GET. A logout changes state, so it should be a POST: use a form"
            " rather than a link, and then set asfquart.generics.OAUTH_LOGOUT_BY_GET = False. See docs/oauth.md"
        )
    return None


def _browser_digest(browser: str) -> str:
    return hashlib.sha256(browser.encode("utf-8")).hexdigest()


def _is_local_redirect(uri: str) -> bool:
    """Tests whether a login/logout redirect target is a path on this site, and safe to place
    in a Location or Refresh header."""
    # Not longer than a path has reason to be. The target of a login is kept in memory until the
    # login completes or expires, so without a limit a client could have a lot kept for it.
    if len(uri) > MAX_REDIRECT_URI_LENGTH:
        return False
    # Must be a path, and not a protocol-relative URL (//example.org)
    if (not uri.startswith("/")) or uri.startswith("//"):
        return False
    # Browsers treat a backslash as a forward slash, so /\example.org is //example.org
    if "\\" in uri:
        return False
    # No control characters: CR and LF would split a header, and browsers drop tabs and
    # newlines from a URL before parsing it, so /<tab>/example.org is //example.org too.
    # This is every character in a Unicode "C" category (control, format, surrogate, private
    # use, unassigned), as in ATR's _assert_standard_safe_syntax, and the line and paragraph
    # separators, which are not in a "C" category but do end a line.
    if any(unicodedata.category(char)[0] == "C" or char in "\u2028\u2029" for char in uri):
        return False
    return True


def _is_oauth_endpoint(target: str, uri: str) -> bool:
    """Tests whether a redirect target is the OAuth endpoint itself, once the browser has resolved
    it: /x/../auth and /%61uth are both /auth."""
    path = urllib.parse.unquote(urllib.parse.urlsplit(target).path)
    return posixpath.normpath(path) == uri


@functools.cache
def _oauth_ssl_context() -> ssl.SSLContext:
    """The TLS settings for the code exchange with the OAuth provider: the provider's certificate
    must be valid, it must be for the provider's host name, and the connection must use TLS 1.2
    or later."""
    # These are the values that ssl.create_default_context() gives in current versions of Python.
    # They are set here as well, so that they are stated, and do not depend on those defaults.
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _oauth_data_problem(oauth_data: object) -> str | None:
    """Tests whether the OAuth provider's response identifies a user. Returns None if it does,
    and otherwise what is wrong with it, for the log. The response itself is not in the result."""
    if not isinstance(oauth_data, dict):
        return "response is not a JSON object"
    if "uid" not in oauth_data:
        return "response has no uid"
    uid = oauth_data["uid"]
    if not isinstance(uid, str):
        return "uid is not a string"
    if not OAUTH_UID_RE.fullmatch(uid):
        return "uid is not in the form of an ASF user id"
    return None


_DEFAULT_PORTS = {"https": 443, "http": 80}


def _address_parts(url: str) -> tuple[str, str, int | None, str, list[str] | None]:
    """The parts of a callback address that say which login it is for: the scheme, the host, the
    port (the one of the scheme, if the address names none), the path, and the state.
    A ValueError for an address that cannot be taken apart, or that has a user name in it."""
    parts = urllib.parse.urlsplit(url)
    if parts.username is not None or parts.password is not None:
        raise ValueError("a callback address has no user name")
    scheme = parts.scheme.lower()
    port = parts.port if parts.port is not None else _DEFAULT_PORTS.get(scheme)
    return scheme, (parts.hostname or "").lower(), port, parts.path, urllib.parse.parse_qs(parts.query).get("state")


_warned_no_origin_uri = False  # so the warning below is logged once per process, not per login


def _oauth_origin_problem(oauth_data: dict[str, typing.Any], callback_url: str) -> str | None:
    """Tests whether the OAuth provider's response is for the login that this app started. Returns
    None if it is, or if the response does not say, and otherwise what is wrong, for the log.

    The provider gives its user's details to whoever presents a code, and a code is not tied to
    the app that presents it. A code that the provider issued for a login at another app would
    otherwise do here, and whoever had it would be logged in as its user. The provider's response
    has origin_uri, the address that it was asked to send the browser back to. For a login that
    this app started, that is callback_url: this app's own address, with the state of this login.

    A response without origin_uri is accepted, as not every provider sends it, and that is
    logged, once."""
    global _warned_no_origin_uri
    if "origin_uri" not in oauth_data:
        if not _warned_no_origin_uri:
            _warned_no_origin_uri = True
            LOGGER.warning(
                "The OAuth provider's response has no origin_uri, so it cannot be checked that the"
                " response is for a login that this application started"
            )
        return None
    origin_uri = oauth_data["origin_uri"]
    if not isinstance(origin_uri, str):
        return "origin_uri is not a string"
    try:
        # Compared in parts, and not as two strings, so that a provider which writes the same
        # address another way (":443" left out or put in, the query string encoded differently)
        # is not turned away
        same = _address_parts(origin_uri) == _address_parts(callback_url)
    except ValueError:
        same = False
    if not same:
        return "response is for another login: origin_uri is not the callback address of this one"
    return None


def _purge_pending_states(pending_states: dict[str, list[typing.Any]], workflow_timeout: int, max_size: int) -> int:
    """Removes the pending logins that have expired, and then the oldest of the rest for as long as
    there are more than max_size. Returns how many were removed that had not expired.

    The dictionary keeps its entries in the order they were added, which is the order of their
    timestamps, so the oldest are at the front and nothing past the first one to keep is looked at."""
    deadline = time.time() - workflow_timeout
    evicted = 0
    while pending_states:
        oldest = next(iter(pending_states))
        expired = pending_states[oldest][0] < deadline
        if not expired and len(pending_states) <= max_size:
            break
        del pending_states[oldest]
        if not expired:
            evicted += 1
    return evicted


def setup_oauth(  # noqa: C901
    app: asfquart.base.QuartApp,
    uri: str = DEFAULT_OAUTH_URI,
    workflow_timeout: int = 900,
    max_pending_logins: int | None = None,
    callback_host: str | None = None,
    logout_by_get: bool | None = None,
    logout_same_site: bool | None = None,
) -> None:
    """Sets up a generic ASF OAuth endpoint for the given app. The default URI is /auth, and the
    default workflow timeout is 900 seconds (15 min), within which the OAuth login must
    be completed. At most max_pending_logins logins that have been started and not yet completed
    are kept (DEFAULT_MAX_PENDING_LOGINS if not given); see docs/oauth.md. The OAuth endpoint
    handles everything related to logging in and out via OAuth, and has the following actions:

    - /auth?login  - Initializes an OAuth login
    - /auth?login=/foo - Same as above, but redirects to /foo on successful login
    - /auth?logout - Clears a user session, logging them out
    - /auth  - Shows the user's credentials if logged in, 404 otherwise.

    callback_host pins the host the OAuth provider sends the browser back to, e.g.
    "https://myapp.apache.org" (OAUTH_CALLBACK_HOST if not given). Without one, this generic route
    expects the Host: header of the request to be accurate, which means setting
    "ProxyPreserveHost On" in your httpd config if proxying.

    logout_by_get says whether a logout may be requested with GET as well as with POST
    (OAUTH_LOGOUT_BY_GET if not given, which is True). With False a GET logout is a 405.
    logout_same_site says whether a logout is accepted from other hosts of the same site, and not
    only from the app's own pages (OAUTH_LOGOUT_SAME_SITE if not given, which is False). A logout
    that another site asked for is always refused; see docs/oauth.md.
    """

    host = callback_host if callback_host is not None else OAUTH_CALLBACK_HOST
    if host is not None:
        _check_callback_host(host)  # fail at startup rather than at the first login

    pending_states: dict[str, list[typing.Any]] = {}  # keeps track of pending states and their expiry
    if max_pending_logins is None:
        max_pending_logins = DEFAULT_MAX_PENDING_LOGINS
    if max_pending_logins < 1:
        raise ValueError("max_pending_logins must be at least 1")
    last_eviction_warning = 0.0
    evicted_since_warning = 0

    def purge_pending_states(max_size: int) -> None:
        """Keeps pending_states within bounds, and says so in the log when that costs somebody their login"""
        nonlocal last_eviction_warning, evicted_since_warning
        evicted_since_warning += _purge_pending_states(pending_states, workflow_timeout, max_size)
        # At most one warning a minute: when this happens at all, it is likely to happen a lot. Each
        # warning says how many were dropped since the one before, which tells a single burst (one
        # warning, a small number) from pressure that lasts (a warning every minute, large numbers).
        if evicted_since_warning and time.time() - last_eviction_warning >= 60:
            LOGGER.warning(
                "More than %d OAuth logins are pending; %d dropped since the last warning, oldest first."
                " A dropped login fails if its user completes it",
                max_pending_logins,
                evicted_since_warning,
            )
            last_eviction_warning = time.time()
            evicted_since_warning = 0

    @app.after_request
    async def no_referrer_for_code(response: quart.typing.ResponseTypes) -> quart.typing.ResponseTypes:
        # A URL with a code in it shouldn't be passed on as a Referer. Set here rather than in
        # the endpoint so it covers every response, errors included.
        if quart.request.path == uri and "code" in quart.request.args:
            response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.route(uri, methods=["GET", "POST"])
    async def oauth_endpoint() -> quart.typing.ResponseReturnValue:  # noqa: C901
        # lightweight CSRF protection.
        if quart.request.method == "POST":
            if quart.request.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "same-site"):
                return quart.Response(
                    status=403, response="CSRF Protection\n", content_type="text/plain; charset=utf-8"
                )
        # Of the requests below, three change state. Starting a login and completing one have to
        # work with GET, because the browser arrives at both by a redirect. Logging out does not.
        # Init oauth login
        login_uri = quart.request.args.get("login")
        logout_uri = quart.request.args.get("logout")
        if login_uri or quart.request.query_string == b"login":
            # The target is gone to from our own page once the login completes, so one that is this
            # endpoint would let another site ask for a logout, by way of a login
            if login_uri and (not _is_local_redirect(login_uri) or _is_oauth_endpoint(login_uri, uri)):
                return quart.Response(
                    status=400, response="Invalid redirect URI.\n", content_type="text/plain; charset=utf-8"
                )
            callback_base = _callback_host(callback_host)
            if callback_base is None:
                return quart.Response(
                    status=400, response="Invalid Host header.\n", content_type="text/plain; charset=utf-8"
                )
            state = secrets.token_hex(16)
            browser = quart.request.cookies.get(STATE_COOKIE_NAME) or secrets.token_hex(16)
            # Logins that were started and never completed are not left to pile up: drop those
            # that have expired, and make room for this one if there are too many all the same
            purge_pending_states(max_pending_logins - 1)
            callback_url = urllib.parse.urljoin(  # NOTE: the uri MUST start with a single forward slash!
                callback_base,
                f"{uri}?state={state}",
            )
            # Save the time we initialized this state, the optional login redirect URI,
            # a digest of the browser cookie that is allowed to complete this login, and the
            # address that the provider is asked to send the browser back to
            pending_states[state] = [time.time(), login_uri, _browser_digest(browser), callback_url]
            redirect_url = OAUTH_URL_INIT % (state, urllib.parse.quote(callback_url))
            response = quart.redirect(redirect_url)
            response.set_cookie(
                STATE_COOKIE_NAME,
                browser,
                max_age=workflow_timeout,
                secure=STATE_COOKIE_SECURE,
                httponly=True,
                samesite=STATE_COOKIE_SAMESITE,
                path="/",  # and no domain: both are what the __Host- prefix requires
            )
            return response

        # Log out
        elif logout_uri or quart.request.query_string == b"logout":
            refusal = _refuse_logout(logout_by_get, logout_same_site)
            if refusal is not None:
                return refusal
            await asfquart.session.aclear()
            if logout_uri and not _is_local_redirect(logout_uri):
                response = quart.Response(
                    status=400, response="Invalid redirect URI.\n", content_type="text/plain; charset=utf-8"
                )
            elif logout_uri:  # if called with /auth=logout=/foo, redirect to /foo
                response = quart.redirect(logout_uri)
            elif quart.request.method == "POST":
                response = quart.Response(status=204)
            else:
                response = quart.Response(
                    status=200, response="Client session removed, goodbye!\n", content_type="text/plain; charset=utf-8"
                )
            response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
            return response
        else:
            code = quart.request.args.get("code")
            state = quart.request.args.get("state")
            if code and state:  # Callback from oauth, complete flow.
                # grab the state data before using it
                # This ensures it can only be used once
                state_data = pending_states.pop(state, None)  # safe pop
                purge_pending_states(max_pending_logins)  # and tidy up the ones that have expired
                # The login may only be completed by the browser that started it
                browser = quart.request.cookies.get(STATE_COOKIE_NAME) or ""
                if (state_data is not None) and (not hmac.compare_digest(state_data[2], _browser_digest(browser))):
                    state_data = None
                if (state_data is None) or (state_data[0] < (time.time() - workflow_timeout)):
                    return quart.Response(
                        status=403,
                        response=(
                            "Invalid or expired OAuth state provided. "
                            f"OAuth workflows must be completed within {workflow_timeout} seconds.\n"
                        ),
                        content_type="text/plain; charset=utf-8",
                    )
                redirect_uri = state_data[1]
                oauth_data: typing.Any = None  # what the provider sent; checked by _oauth_data_problem()
                try:
                    connector = aiohttp.TCPConnector(ssl=_oauth_ssl_context())
                    async with aiohttp.client.ClientSession(timeout=OAUTH_TIMEOUT, connector=connector) as session:
                        rv = await _exchange_code(session, code)
                        if rv.status == 200:
                            oauth_data = await rv.json()
                            problem = _oauth_data_problem(oauth_data) or _oauth_origin_problem(
                                oauth_data, state_data[3]
                            )
                        else:
                            problem = f"provider answered with status {rv.status}"
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as e:
                    # OSError covers what aiohttp does not wrap, such as a CA store that cannot be loaded.
                    # Only the kind of error is logged: the message may carry the URL, and with it the code
                    problem = type(e).__name__
                # Nothing is stored unless the response identifies a user. The log says what went wrong,
                # so that a provider that is down, one that has changed its response, and a uid that was
                # turned away can be told apart. It does not have the code, the state or the response.
                if problem is not None:
                    LOGGER.warning("OAuth code exchange failed: %s", problem)
                    return quart.Response(
                        status=403, response="OAuth authentication failed.\n", content_type="text/plain; charset=utf-8"
                    )
                # The user has just authenticated: this is a new session, with the full lifetime
                await asfquart.session.awrite(oauth_data, new_session=True)
                if redirect_uri:  # if called with /auth=login=/foo, redirect to /foo
                    # If SameSite is set, we cannot redirect with a 30x response, as that may invalidate the set-cookie
                    # instead, we issue a 200 Okay with a Refresh header, instructing the browser to immediately go
                    # someplace else. This counts as a samesite request.
                    return quart.Response(
                        status=200,
                        response=f"Successfully logged in! Welcome, {oauth_data['uid']}\n",
                        headers={"Refresh": f"0; url={redirect_uri}"},
                        content_type="text/plain; charset=utf-8",
                    )
                # Otherwise, just say hi
                return quart.Response(
                    status=200,
                    response=f"Successfully logged in! Welcome, {oauth_data['uid']}\n",
                    content_type="text/plain; charset=utf-8",
                )
            else:  # Just spit out existing session if it's there
                client_session = await asfquart.session.read()
                if client_session is not None:
                    if isinstance(client_session, dict):
                        return client_session
                    model_dump: typing.Callable[[], dict[str, typing.Any]] | None
                    model_dump = getattr(client_session, "model_dump", None)
                    if callable(model_dump):
                        return model_dump()
                    raise TypeError(
                        f"Session type {type(client_session).__name__} cannot be shown: it must be a dictionary"
                        " or have a model_dump() method - see docs/session-stores.md"
                    )
                return quart.Response(
                    status=404, response="No active session found.\n", content_type="text/plain; charset=utf-8"
                )


def enforce_login(app: asfquart.base.QuartApp, redirect_uri: str = DEFAULT_OAUTH_URI) -> None:
    """Enforces redirect to the auth provider (if enabled) when a client tries to access a restricted page
    without being logged in. Only redirects if there is no active user session. On success, the client
    is redirected back to the origin page that was restricted. If it is still restricted, the client
    will instead see an error message."""

    @app.errorhandler(asfquart.auth.AuthenticationFailed)
    async def auth_redirect(error: asfquart.auth.AuthenticationFailed) -> quart.typing.ResponseTypes:
        # If we have no client session (and X-No-Redirect is not set), redirect to auth flow
        if (
            "x-no-redirect" not in quart.request.headers
            and not quart.request.authorization
            and not await asfquart.session.read()
        ):
            # The werkzeug.sansio.request.full_path property returns:
            # f"{self.path}?{self.query_string.decode()}"
            # Therefore it contains a "?" even if there is no query string
            full_path = quart.request.full_path
            # Strip the trailing "?" when the query string is empty
            if full_path.endswith("?"):
                parsed = urllib.parse.urlsplit(full_path)
                if not parsed.query:
                    # The query string is empty
                    full_path = full_path[:-1]
            quoted_path = urllib.parse.quote(full_path)
            return quart.redirect(f"{redirect_uri}?login={quoted_path}")
        # If we have a session, but still no access, just say so in plain text.
        return quart.Response(status=error.errorcode, response=error.message, content_type="text/plain; charset=utf-8")
