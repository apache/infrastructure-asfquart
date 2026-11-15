#!/usr/bin/env python3
"""Generic endpoints for ASFQuart"""

import asyncio
import hashlib
import hmac
import logging
import re
import secrets
import urllib
import urllib.parse
import time

import quart
import aiohttp

import asfquart  # implies .session


# These are the ASF OAuth URLs for init and verification. Used for setup_oauth()
OAUTH_URL_INIT = "https://oauth.apache.org/auth-oidc?state=%s&redirect_uri=%s"
OAUTH_URL_CALLBACK = "https://oauth.apache.org/token-oidc?code=%s"
DEFAULT_OAUTH_URI = "/auth"

# The pending login is tied to the browser that started it, via this cookie.
# SameSite=Lax is required: the callback is a top level navigation from the
# OAuth provider, and a Strict cookie is not sent when the provider is on a
# different site. Deployments where the provider and the app share a site may
# set STATE_COOKIE_SAMESITE = "Strict".
STATE_COOKIE_NAME = "asfquart-oauth-state"
STATE_COOKIE_SAMESITE = "Lax"
STATE_COOKIE_SECURE = True

# Time limits for the code exchange with the OAuth provider. The exchange holds a
# request open, so every phase is bounded: 10 seconds to connect, 15 seconds
# between reads, and 30 seconds for the exchange as a whole.
OAUTH_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10, sock_connect=10, sock_read=15)

# The shape of an ASF user id, as returned in the "uid" field by the OAuth provider.
OAUTH_UID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")

LOGGER = logging.getLogger(__name__)


def _browser_digest(browser):
    return hashlib.sha256(browser.encode("utf-8")).hexdigest()


def _is_local_redirect(uri: str) -> bool:
    """Tests whether a login/logout redirect target is a path on this site, and safe to place
    in a Location or Refresh header."""
    # Must be a path, and not a protocol-relative URL (//example.org)
    if (not uri.startswith("/")) or uri.startswith("//"):
        return False
    # Browsers treat a backslash as a forward slash, so /\example.org is //example.org
    if "\\" in uri:
        return False
    # No control characters: CR and LF would split a header, and browsers drop tabs and
    # newlines from a URL before parsing it, so /<tab>/example.org is //example.org too
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in uri):
        return False
    return True


def _is_valid_oauth_data(oauth_data) -> bool:
    """Tests whether the OAuth provider's response identifies a user."""
    if not isinstance(oauth_data, dict):
        return False
    uid = oauth_data.get("uid")
    return isinstance(uid, str) and OAUTH_UID_RE.fullmatch(uid) is not None


def setup_oauth(app, uri=DEFAULT_OAUTH_URI, workflow_timeout: int = 900):
    """Sets up a generic ASF OAuth endpoint for the given app. The default URI is /auth, and the
    default workflow timeout is 900 seconds (15 min), within which the OAuth login must
    be completed. The OAuth endpoint handles everything related to logging in and out via OAuth,
    and has the following actions:

    - /auth?login  - Initializes an OAuth login
    - /auth?login=/foo - Same as above, but redirects to /foo on successful login
    - /auth?logout - Clears a user session, logging them out
    - /auth  - Shows the user's credentials if logged in, 404 otherwise.

    This generic route expects the Host: header of the request to be accurate, which means setting
    "ProxyPreserveHost On" in your httpd config if proxying.
    """

    pending_states = {}  # keeps track of pending states and their expiry

    @app.route(uri, methods=["GET", "POST"])
    async def oauth_endpoint():
        # lightweight CSRF protection.
        if quart.request.method == "POST":
            if quart.request.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "same-site"):
                return quart.Response(
                    status=403,
                    response="CSRF Protection\n",
                    content_type="text/plain; charset=utf-8"
                )
        # Init oauth login
        login_uri = quart.request.args.get("login")
        logout_uri = quart.request.args.get("logout")
        if login_uri or quart.request.query_string == b"login":
            if login_uri and not _is_local_redirect(login_uri):
                return quart.Response(
                    status=400,
                    response="Invalid redirect URI.\n",
                    content_type="text/plain; charset=utf-8"
                )
            state = secrets.token_hex(16)
            browser = quart.request.cookies.get(STATE_COOKIE_NAME) or secrets.token_hex(16)
            # Save the time we initialized this state, the optional login redirect URI,
            # and a digest of the browser cookie that is allowed to complete this login
            pending_states[state] = [time.time(), login_uri, _browser_digest(browser)]
            callback_host = quart.request.host_url.replace("http://", "https://")  # Enforce HTTPS
            callback_url = urllib.parse.urljoin(  # NOTE: the uri MUST start with a single forward slash!
                callback_host,
                f"{uri}?state={state}",
            )
            redirect_url = OAUTH_URL_INIT % (state, urllib.parse.quote(callback_url))
            response = quart.redirect(redirect_url)
            response.set_cookie(
                STATE_COOKIE_NAME,
                browser,
                max_age=workflow_timeout,
                secure=STATE_COOKIE_SECURE,
                httponly=True,
                samesite=STATE_COOKIE_SAMESITE,
                path=uri,
            )
            return response

        # Log out
        elif logout_uri or quart.request.query_string == b"logout":
            await asfquart.session.aclear()
            if logout_uri and not _is_local_redirect(logout_uri):
                response = quart.Response(
                    status=400,
                    response="Invalid redirect URI.\n",
                    content_type="text/plain; charset=utf-8"
                )
            elif logout_uri:  # if called with /auth=logout=/foo, redirect to /foo
                response = quart.redirect(logout_uri)
            elif quart.request.method == "POST":
                response = quart.Response(status=204)
            else:
                response = quart.Response(
                    status=200,
                    response="Client session removed, goodbye!\n",
                    content_type="text/plain; charset=utf-8"
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
                # The login may only be completed by the browser that started it
                browser = quart.request.cookies.get(STATE_COOKIE_NAME) or ""
                if (state_data is not None) and (not hmac.compare_digest(state_data[2], _browser_digest(browser))):
                    state_data = None
                if (state_data is None) or (state_data[0] < (time.time() - workflow_timeout)):
                    return quart.Response(
                        status=403,
                        response=f"Invalid or expired OAuth state provided. OAuth workflows must be completed within {workflow_timeout} seconds.\n",
                        content_type="text/plain; charset=utf-8"
                    )
                redirect_uri = state_data[1]
                oauth_data = None
                try:
                    async with aiohttp.client.ClientSession(timeout=OAUTH_TIMEOUT) as session:
                        # The code comes from the query string, so it is quoted before it goes into ours
                        rv = await session.get(OAUTH_URL_CALLBACK % urllib.parse.quote(code, safe=""))
                        if rv.status == 200:
                            oauth_data = await rv.json()
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                    # Only the kind of error is logged: the message may carry the URL, and with it the code
                    LOGGER.warning("OAuth code exchange failed: %s", type(e).__name__)
                # Nothing is stored unless the response identifies a user
                if not _is_valid_oauth_data(oauth_data):
                    return quart.Response(
                        status=403,
                        response="OAuth authentication failed.\n",
                        content_type="text/plain; charset=utf-8"
                    )
                await asfquart.session.awrite(oauth_data)
                if redirect_uri:  # if called with /auth=login=/foo, redirect to /foo
                    # If SameSite is set, we cannot redirect with a 30x response, as that may invalidate the set-cookie
                    # instead, we issue a 200 Okay with a Refresh header, instructing the browser to immediately go
                    # someplace else. This counts as a samesite request.
                    return quart.Response(
                        status=200,
                        response=f"Successfully logged in! Welcome, {oauth_data['uid']}\n",
                        headers={"Refresh": f"0; url={redirect_uri}"},
                        content_type="text/plain; charset=utf-8"
                    )
                # Otherwise, just say hi
                return quart.Response(
                    status=200,
                    response=f"Successfully logged in! Welcome, {oauth_data['uid']}\n",
                    content_type="text/plain; charset=utf-8"
                )
            else:  # Just spit out existing session if it's there
                client_session = await asfquart.session.read()
                if client_session is not None:
                    if hasattr(client_session, "model_dump"):
                        return client_session.model_dump()
                    return client_session
                return quart.Response(
                    status=404,
                    response="No active session found.\n",
                    content_type="text/plain; charset=utf-8"
                )


def enforce_login(app, redirect_uri=DEFAULT_OAUTH_URI):
    """Enforces redirect to the auth provider (if enabled) when a client tries to access a restricted page
    without being logged in. Only redirects if there is no active user session. On success, the client
    is redirected back to the origin page that was restricted. If it is still restricted, the client
    will instead see an error message."""

    @app.errorhandler(asfquart.auth.AuthenticationFailed)
    async def auth_redirect(error):
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
        return quart.Response(
            status=error.errorcode,
            response=error.message,
            content_type="text/plain; charset=utf-8"
        )
